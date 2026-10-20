//! Running the chunk program: each [`Chunk`] descriptor executed over the
//! loaded stages, as a circuit that holds its results to the stages or as
//! the prover's native run that fills them.
//!
//! [`execute`] runs one chunk of a side and returns what it writes; a
//! chunk circuit enforces those writes equal to the work and transcript
//! stages' wires, and [`Prepared::run`] stores them. The chunk kinds are
//! the same on both sides; what differs, the targets and their order, goes
//! through the [`Side`].

use alloc::vec::Vec;

use ragu_circuits::{polynomials::Rank, registry::CircuitIndex};
use ragu_core::{
    Cycle, Error, Result,
    drivers::{
        Driver, DriverValue,
        emulator::{Emulator, Wireless},
    },
    maybe::{Always, Maybe},
};
use ragu_primitives::{
    Element, Endoscalar, EndoscalarChallenge, GadgetExt, NonzeroBank, Point, extract_endoscalar,
    poseidon::{Sponge, SpongeState},
    vec::{FixedVec, Len},
};
use udon::{curve::EndomorphismAffine as Affine, field::Field};

use super::{
    batch,
    circuit::{SideWitness, Witness},
    derive::{self, Digits},
    ipa,
    program::{
        APPLICATION, ChainChunk, ChallengeRef, Chunk, ElementSrc, Op, PointSrc, ScalarRef,
        Schedule, Step, squeezed,
    },
    revdot,
    side::{Native, Nested, Side},
    stages::{self, MessageScalars, Values},
};
use crate::{
    Application, CompressedPcd, SelectableBackend,
    compress::{
        instance::OPENED,
        revdot::{
            OpeningClaim,
            claims::Kind,
            fold::{Derived, Weights},
        },
    },
    header::{Header, Suffix},
    ipa::IpaCycle,
    profile::{ProfiledCycle, Standard},
};

/// A chunk's result: the value a slot of the work stage, or of the
/// transcript stage for a sponge state, must hold.
pub(crate) enum Write<'dr, D: Driver<'dr>, P: Affine<Base = D::F>> {
    Element(usize, Element<'dr, D>),
    Point(usize, Point<'dr, D, P>),
    State(usize, Element<'dr, D>),
}

/// One stage's wires as a chunk sees them.
pub(crate) struct View<'a, 'dr, D: Driver<'dr>, P: Affine<Base = D::F>> {
    pub points: &'a [Point<'dr, D, P>],
    pub elements: &'a [Element<'dr, D>],
}

impl<'a, 'dr, D: Driver<'dr>, P: Affine<Base = D::F>> View<'a, 'dr, D, P> {
    pub(crate) fn new<LP: Len, LE: Len>(output: &'a stages::Output<'dr, D, P, LP, LE>) -> Self {
        View {
            points: &output.points,
            elements: &output.elements,
        }
    }

    /// The view of a stage the chunk did not load.
    pub(crate) fn empty() -> Self {
        View {
            points: &[],
            elements: &[],
        }
    }
}

impl<'dr, D: Driver<'dr>, P: Affine<Base = D::F>> Clone for View<'_, 'dr, D, P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'dr, D: Driver<'dr>, P: Affine<Base = D::F>> Copy for View<'_, 'dr, D, P> {}

/// The stages as a chunk sees them.
pub(crate) struct Loaded<'a, 'dr, D: Driver<'dr>, P: Affine<Base = D::F>> {
    pub instance: View<'a, 'dr, D, P>,
    pub messages: View<'a, 'dr, D, P>,
    pub work: View<'a, 'dr, D, P>,
    pub transcript: View<'a, 'dr, D, P>,
}

impl<'dr, D: Driver<'dr>, P: Affine<Base = D::F>> Clone for Loaded<'_, 'dr, D, P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'dr, D: Driver<'dr>, P: Affine<Base = D::F>> Copy for Loaded<'_, 'dr, D, P> {}

/// What a side allocates beyond the stages: the challenges squeezed on
/// the other side as their endoscalars' bits, and the other field's
/// full-width scalars.
pub(crate) struct Aux<G> {
    /// Every compression challenge the side did not squeeze, in the order
    /// the schedule's [`ChallengeRef::Bits`] indexes them: the reduction
    /// it checks in its field, the fuse's $x$, $y$ and $u$, then the
    /// reduction whose points it checks.
    pub challenge_bits: Vec<u128>,
    /// The other field's values, in [`ScalarRef::Bits`] order: $v$, $c$
    /// and $c b z$ of the reduction whose points the side checks, then
    /// what the side's [`Side::foreign`] adds.
    pub foreign: Vec<G>,
}

/// Everything a side's chunks need: the stages' values, the work and
/// transcript stages filled, the auxiliary witnesses and the schedule.
pub(crate) struct Prepared<C: Cycle, S: Side<C>> {
    pub schedule: Schedule,
    pub instance: Values<S::F, S::P>,
    pub messages: Values<S::F, S::P>,
    pub work: Values<S::F, S::P>,
    pub transcript: Values<S::F, S::P>,
    pub aux: Aux<S::Other>,
    pub extra: S::Extra,
}

/// What every chunk of a side can reach.
pub(crate) struct Ctx<'a, 'w, 'dr, D, C, S>
where
    D: Driver<'dr>,
    C: Cycle,
    S: Side<C, F = D::F>,
{
    pub loaded: Loaded<'a, 'dr, D, S::P>,
    pub schedule: &'a Schedule,
    pub generators: &'a [S::P],
    pub u: S::P,
    pub poseidon: &'dr S::Poseidon,
    /// The side's prepared witness, when the driver has one.
    pub witness: DriverValue<D, &'w Prepared<C, S>>,
}

impl<'a, 'w, 'dr, D, C, S> Ctx<'a, 'w, 'dr, D, C, S>
where
    D: Driver<'dr>,
    C: Cycle,
    S: Side<C, F = D::F>,
{
    fn point(&self, dr: &mut D, src: PointSrc) -> Result<Point<'dr, D, S::P>> {
        let l = &self.loaded;
        Ok(match src {
            PointSrc::Instance(i) => l.instance.points[i].clone(),
            PointSrc::Message(i) => l.messages.points[i].clone(),
            PointSrc::Bridge(i) => l.transcript.points[i].clone(),
            PointSrc::Work(slot) => l.work.points[slot].clone(),
            PointSrc::Generator(i) => Point::constant(dr, self.generators[i])?,
            PointSrc::U => Point::constant(dr, self.u)?,
        })
    }

    fn element(&self, dr: &mut D, src: ElementSrc) -> Result<Element<'dr, D>> {
        let l = &self.loaded;
        Ok(match src {
            ElementSrc::Instance(i) => l.instance.elements[i].clone(),
            ElementSrc::Message(i) => l.messages.elements[i].clone(),
            ElementSrc::Work(slot) => l.work.elements[slot].clone(),
            ElementSrc::Coordinate(point, which) => {
                let point = self.point(dr, point)?;
                let mut coordinates = Vec::with_capacity(2);
                GadgetExt::write(&point, dr, &mut coordinates)?;
                coordinates[which as usize].clone()
            }
            ElementSrc::InstanceSquared(i) => l.instance.elements[i].square(dr)?,
        })
    }

    /// The work stage element at `slot`.
    pub(crate) fn work(&self, slot: usize) -> Element<'dr, D> {
        self.loaded.work.elements[slot].clone()
    }

    /// The transcript stage element at `slot`: part of a saved sponge
    /// state.
    fn state(&self, slot: usize) -> Element<'dr, D> {
        self.loaded.transcript.elements[slot].clone()
    }

    /// The other field's value at `id` of the side's foreign scalars.
    fn foreign(&self, id: usize) -> DriverValue<D, S::Other> {
        self.witness.as_ref().map(|w| w.aux.foreign[id])
    }

    /// A challenge's endoscalar: read off the squeezed element,
    /// constrained into range, or allocated from its bits.
    fn endoscalar(&self, dr: &mut D, challenge: ChallengeRef) -> Result<Endoscalar<'dr, D>> {
        Ok(match challenge {
            ChallengeRef::Raw(slot) => Endoscalar::extract(EndoscalarChallenge::from_element(
                dr,
                &mut (),
                self.work(slot),
            )?),
            ChallengeRef::Bits(id) => {
                let bits = self.witness.as_ref().map(|w| w.aux.challenge_bits[id]);
                Endoscalar::alloc(dr, bits)?
            }
        })
    }

    /// A fixed point's value, for a scaling's offset.
    fn fixed(&self, src: PointSrc) -> S::P {
        match src {
            PointSrc::Generator(i) => self.generators[i],
            PointSrc::U => self.u,
            _ => panic!("an offset is a fixed point"),
        }
    }

    /// The reduction's challenges from this side's lifts.
    fn revdot_challenges(&self) -> revdot::Challenges<'dr, D> {
        let lifts = &self.schedule.regions.lifts;
        revdot::Challenges {
            z: self.work(lifts[squeezed::Z]),
            weights: Weights {
                mu: self.work(lifts[squeezed::MU]),
                nu: self.work(lifts[squeezed::NU]),
                mu_prime: self.work(lifts[squeezed::MU_PRIME]),
                nu_prime: self.work(lifts[squeezed::NU_PRIME]),
            },
            rho: self.work(lifts[squeezed::RHO]),
            r: self.work(lifts[squeezed::R]),
        }
    }

    /// The scalar messages of the reduction this side checks.
    fn message_scalars(&self) -> MessageScalars<'_, Element<'dr, D>> {
        let span = self.schedule.layout.messages.scalars;
        MessageScalars(&self.loaded.messages.elements[span.start..span.start + span.len])
    }

    fn revdot_messages(&self) -> revdot::Messages<'dr, D> {
        let m = self.message_scalars();
        revdot::Messages {
            inner_epsilon: m.inner_epsilon().clone(),
            outer_epsilon: m.outer_epsilon().clone(),
            openings: m.openings().to_vec(),
            p_at_inverse_r: m.p_at_inverse_r().clone(),
            q_at_r: m.q_at_r().clone(),
        }
    }

    /// The wire bindings from the plans.
    fn bindings(&self, dr: &mut D) -> Result<Vec<revdot::Binding<'dr, D>>> {
        let mut bindings = Vec::with_capacity(self.schedule.bindings.len());
        for plan in &self.schedule.bindings {
            let mut expected = Vec::with_capacity(plan.expected.len());
            for &src in &plan.expected {
                expected.push(self.element(dr, src)?);
            }
            bindings.push(revdot::Binding {
                degrees: plan.degrees.clone(),
                expected,
            });
        }
        Ok(bindings)
    }

    /// The reduction's public parts from the plans, with `targets` the
    /// claims' targets in order.
    fn public(&self, dr: &mut D, targets: Vec<Element<'dr, D>>) -> Result<revdot::Public<'dr, D>> {
        let schedule = self.schedule;
        let regions = &schedule.regions;
        let kinds: Vec<Kind> = schedule.claims.iter().map(|claim| claim.kind).collect();
        let mut restrictions = Vec::new();
        for (claim, slot) in schedule.claims.iter().zip(&regions.restrictions) {
            if let (Kind::Circuit(circuit) | Kind::Bonding(circuit), Some(slot)) =
                (claim.kind, slot)
                && !restrictions.iter().any(|(listed, _)| *listed == circuit)
            {
                restrictions.push((circuit, self.work(*slot)));
            }
        }
        Ok(revdot::Public {
            kinds,
            targets,
            restrictions,
            bindings: self.bindings(dr)?,
            sigma: self.work(regions.lifts[squeezed::SIGMA]),
        })
    }

    /// The batch and the IPA's scalars over the reduction's openings and
    /// the instance's, leaving $v$ and $c b z$.
    fn batch_ipa(&self, dr: &mut D) -> Result<[Element<'dr, D>; 2]> {
        let regions = &self.schedule.regions;
        let lifts = &regions.lifts;
        let challenges = self.revdot_challenges();
        let messages = self.revdot_messages();
        let inverse_r = self.work(regions.revdot[3]);
        let target = self.work(regions.target_p0);
        let mut claims = revdot::openings(dr, &challenges, &messages, &inverse_r, target)?;
        let base = Derived::ALL.len() + 2;
        let mut opening = Vec::with_capacity(4);
        for &src in &regions.opening {
            opening.push(self.element(dr, src)?);
        }
        let [u, v, a_at_u, b_at_u]: [Element<'dr, D>; 4] = opening
            .try_into()
            .map_err(|_| Error::InvalidWitness("four opening values".into()))?;
        let claim = |poly, point: &Element<'dr, D>, value: Element<'dr, D>| OpeningClaim {
            poly,
            point: point.clone(),
            value,
        };
        claims.extend([
            claim(
                base,
                &self.work(lifts[squeezed::W]),
                self.work(regions.restriction_at_w),
            ),
            claim(base + 1, &u, v),
            claim(base + 2, &u, a_at_u),
            claim(base + 3, &u, b_at_u),
        ]);
        let m = self.message_scalars();
        let batched = batch::verify(
            dr,
            &claims,
            base + OPENED,
            &batch::Challenges {
                alpha: self.work(lifts[squeezed::ALPHA]),
                u: self.work(lifts[squeezed::U]),
                beta: self.work(lifts[squeezed::BETA]),
            },
            &batch::Messages {
                evaluations: m.evaluations().to_vec(),
            },
        )?;
        let rounds: Vec<Element<'dr, D>> = lifts[squeezed::ROUNDS..]
            .iter()
            .map(|&slot| self.work(slot))
            .collect();
        let scalars = ipa::verify(
            dr,
            &batched.point,
            &batched.value,
            &ipa::Challenges {
                xi: self.work(lifts[squeezed::XI]),
                z: self.work(lifts[squeezed::IPA_Z]),
                rounds,
            },
            &ipa::Messages { c: m.c().clone() },
        )?;
        Ok([batched.value, scalars.u.negate(dr)])
    }

    /// A chain chunk's accumulator after its steps, each challenge's
    /// endoscalar read once.
    fn chain(&self, dr: &mut D, chain: &ChainChunk) -> Result<Point<'dr, D, S::P>> {
        let mut endoscalars: Vec<(ChallengeRef, Endoscalar<'dr, D>)> = Vec::new();
        let mut endoscalar = |dr: &mut D, challenge: ChallengeRef| -> Result<Endoscalar<'dr, D>> {
            if let Some((_, endoscalar)) = endoscalars.iter().find(|(c, _)| *c == challenge) {
                return Ok(endoscalar.clone());
            }
            let endoscalar = self.endoscalar(dr, challenge)?;
            endoscalars.push((challenge, endoscalar.clone()));
            Ok(endoscalar)
        };
        NonzeroBank::scope(dr, |dr, bank| {
            let mut acc = match chain.init {
                Some(init) => Some(self.point(dr, init)?),
                None => None,
            };
            for step in &chain.steps {
                acc = Some(match *step {
                    Step::Horner { scale_by, add } => {
                        let acc = acc.expect("a Horner step scales an accumulator");
                        let scaled = endoscalar(dr, scale_by)?.group_scale(dr, &acc)?;
                        match add {
                            Some(add) => {
                                let add = self.point(dr, add)?;
                                scaled.add_incomplete(dr, &add, bank)?
                            }
                            None => scaled,
                        }
                    }
                    Step::AddScaled { point, scale_by } => {
                        let point = self.point(dr, point)?;
                        let term = match scale_by {
                            Some(challenge) => {
                                endoscalar(dr, challenge)?.group_scale(dr, &point)?
                            }
                            None => point,
                        };
                        match acc {
                            Some(acc) => acc.add_incomplete(dr, &term, bank)?,
                            None => term,
                        }
                    }
                });
            }
            acc.ok_or_else(|| Error::InvalidWitness("a chain has a step".into()))
        })
    }
}

/// Runs one chunk of side `S`, returning what it writes.
pub(crate) fn execute<'dr, D, C, S, K, const HEADER_SIZE: usize>(
    dr: &mut D,
    chunk: &Chunk,
    ctx: &Ctx<'_, '_, 'dr, D, C, S>,
) -> Result<Vec<Write<'dr, D, S::P>>>
where
    D: Driver<'dr>,
    C: Cycle,
    S: Side<C, F = D::F>,
    K: Rank,
{
    let regions = &ctx.schedule.regions;
    let layout = &ctx.schedule.layout;
    let mut writes = Vec::new();
    match chunk {
        Chunk::Transcript {
            state_in,
            ops,
            state_out,
            ..
        } => {
            let mut sponge = match state_in {
                Some(first) => {
                    let state = FixedVec::try_from_fn(|i| Ok(ctx.state(first + i)))?;
                    Sponge::resume(SpongeState::from_elements(state), ctx.poseidon)
                }
                None => Sponge::new(dr, ctx.poseidon),
            };
            for &op in ops {
                match op {
                    Op::Absorb(src) => {
                        let element = ctx.element(dr, src)?;
                        sponge.absorb(dr, &element)?;
                    }
                    Op::AbsorbConst(value) => {
                        let element = Element::constant(dr, D::F::from_u128(value));
                        sponge.absorb(dr, &element)?;
                    }
                    Op::Squeeze(slot) => writes.push(Write::Element(slot, sponge.squeeze(dr)?)),
                }
            }
            if let Some(first) = state_out {
                let state = sponge
                    .save_state(dr)
                    .map_err(|_| Error::InvalidWitness("a transcript cut is legal".into()))?;
                for (i, element) in state.into_elements().into_inner().into_iter().enumerate() {
                    writes.push(Write::State(first + i, element));
                }
            }
        }
        Chunk::Lift { pairs } => {
            for &(challenge, out) in pairs {
                let endoscalar = ctx.endoscalar(dr, challenge)?;
                writes.push(Write::Element(out, endoscalar.lift(dr)?));
            }
        }
        Chunk::Targets { out } => {
            let targets = S::targets::<D, K, HEADER_SIZE>(dr, ctx)?;
            assert_eq!(targets.len(), out.len(), "one target per slot");
            for (&slot, target) in out.iter().zip(targets) {
                writes.push(Write::Element(slot, target));
            }
        }
        Chunk::RevdotWeights { out } => {
            let challenges = ctx.revdot_challenges();
            let at_r = revdot::weights::<_, K>(dr, ctx.schedule.claims.len(), &challenges)?;
            for (slot, value) in out.iter().zip([
                at_r.inner_at_r,
                at_r.outer_at_r,
                at_r.tz_at_r,
                at_r.inverse_r,
            ]) {
                writes.push(Write::Element(*slot, value));
            }
        }
        Chunk::Bindings { out } => {
            let bindings = ctx.bindings(dr)?;
            let sigma = ctx.work(regions.lifts[squeezed::SIGMA]);
            let r = ctx.work(regions.lifts[squeezed::R]);
            let at_r = revdot::bindings_at::<_, K>(dr, &bindings, &sigma, &r)?;
            assert_eq!(at_r.len(), out.len(), "one evaluation per binding");
            for (slots, at) in out.iter().zip(at_r) {
                writes.push(Write::Element(slots[0], at.expected));
                writes.push(Write::Element(slots[1], at.mask));
            }
        }
        Chunk::RevdotPublic { out } => {
            let targets = S::ky_targets(dr, ctx);
            let public = ctx.public(dr, targets)?;
            let at_r = revdot::AtR {
                inner_at_r: ctx.work(regions.revdot[0]),
                outer_at_r: ctx.work(regions.revdot[1]),
                tz_at_r: ctx.work(regions.revdot[2]),
                inverse_r: ctx.work(regions.revdot[3]),
            };
            let bound: Vec<revdot::BindingAt<'dr, D>> = regions
                .bindings_at
                .iter()
                .map(|slots| revdot::BindingAt {
                    expected: ctx.work(slots[0]),
                    mask: ctx.work(slots[1]),
                })
                .collect();
            let target = revdot::public::<_, K>(
                dr,
                &public,
                &ctx.revdot_challenges(),
                &ctx.revdot_messages(),
                &at_r,
                &bound,
            )?;
            writes.push(Write::Element(*out, target));
        }
        Chunk::BatchIpa { out } => {
            let [v, cbz] = ctx.batch_ipa(dr)?;
            writes.push(Write::Element(out[0], v));
            writes.push(Write::Element(out[1], cbz));
        }
        Chunk::Digits { scalars } => {
            for &src in scalars {
                let element = ctx.element(dr, src)?;
                Digits::bind(dr, &element)?;
            }
        }
        Chunk::Sums { sums } => {
            for (out, terms) in sums {
                let sum = NonzeroBank::scope(dr, |dr, bank| {
                    let mut points = terms.iter();
                    let first = points
                        .next()
                        .ok_or_else(|| Error::InvalidWitness("a sum has a term".into()))?;
                    let mut acc = ctx.point(dr, *first)?;
                    for &term in points {
                        let term = ctx.point(dr, term)?;
                        acc = acc.add_incomplete(dr, &term, bank)?;
                    }
                    Ok(acc)
                })?;
                writes.push(Write::Point(*out, sum));
            }
        }
        Chunk::Chain(chain) => {
            writes.push(Write::Point(chain.out, ctx.chain(dr, chain)?));
        }
        Chunk::Checks { checks } => {
            for &(point, by, expected) in checks {
                let endoscalar = ctx.endoscalar(dr, by)?;
                let point = ctx.point(dr, point)?;
                let expected = ctx.point(dr, expected)?;
                endoscalar
                    .group_scale(dr, &point)?
                    .enforce_equal(dr, &expected)?;
            }
        }
        Chunk::Scale {
            point,
            scalar,
            offset,
            digits: (lo, hi),
            init,
            finish,
            out,
        } => {
            let width = Digits::<'dr, D>::width::<S::Other>();
            let point = ctx.point(dr, *point)?;
            let digits = match *scalar {
                ScalarRef::Bits(id) => Digits::alloc_range(dr, ctx.foreign(id), *lo..*hi)?,
                ScalarRef::Element(src) => {
                    assert_eq!((*lo, *hi), (0, width), "an element's digits are not cut");
                    let element = ctx.element(dr, src)?;
                    Digits::alloc_bound(dr, &element)?
                }
            };
            let init = init.map(|slot| ctx.loaded.work.points[slot].clone());
            let offset = ctx.fixed(*offset);
            let scaled = NonzeroBank::scope(dr, |dr, bank| {
                let acc = derive::scale_chain(dr, &point, &digits, init, offset, bank)?;
                if *finish {
                    derive::scale_shift(dr, acc, offset, width, bank)
                } else {
                    Ok(acc)
                }
            })?;
            writes.push(Write::Point(*out, scaled));
        }
        Chunk::Sign { generator, out } => {
            let dummy = Element::constant(dr, D::F::from(Suffix::internal(2).get()));
            let elements = ctx.loaded.instance.elements;
            let left = &elements[layout.instance.left_header.at(HEADER_SIZE - 1)];
            let right = &elements[layout.instance.right_header.at(HEADER_SIZE - 1)];
            let left = left.is_equal(dr, &mut (), &dummy)?;
            let right = right.is_equal(dr, &mut (), &dummy)?;
            let base_case = left.and(dr, &right)?;
            let negate = base_case.not(dr);
            let point = Point::constant(dr, ctx.generators[*generator])?;
            writes.push(Write::Point(*out, point.conditional_negate(dr, &negate)?));
        }
        Chunk::Equal { left, right } => {
            let left = ctx.point(dr, *left)?;
            let right = ctx.point(dr, *right)?;
            left.enforce_equal(dr, &right)?;
        }
    }
    Ok(writes)
}

/// Holds a chunk's writes to the work and transcript stages' wires.
pub(crate) fn enforce<'dr, D: Driver<'dr>, P: Affine<Base = D::F>>(
    dr: &mut D,
    loaded: Loaded<'_, 'dr, D, P>,
    writes: Vec<Write<'dr, D, P>>,
) -> Result<()> {
    for write in writes {
        match write {
            Write::Element(slot, element) => {
                element.enforce_equal(dr, &loaded.work.elements[slot])?
            }
            Write::Point(slot, point) => point.enforce_equal(dr, &loaded.work.points[slot])?,
            Write::State(slot, element) => {
                element.enforce_equal(dr, &loaded.transcript.elements[slot])?
            }
        }
    }
    Ok(())
}

/// The stages allocated as witnesses under a driver, for the prover's
/// native run.
struct Allocated<'dr, D: Driver<'dr>, P: Affine<Base = D::F>> {
    stages: [(Vec<Point<'dr, D, P>>, Vec<Element<'dr, D>>); 4],
}

impl<'dr, D: Driver<'dr>, P: Affine<Base = D::F>> Allocated<'dr, D, P> {
    fn alloc(dr: &mut D, values: [&Values<D::F, P>; 4]) -> Result<Self> {
        let mut stages = Vec::with_capacity(4);
        for values in values {
            let points = values
                .points
                .iter()
                .map(|&point| Point::alloc(dr, D::just(|| point)))
                .collect::<Result<Vec<_>>>()?;
            let elements = values
                .elements
                .iter()
                .map(|&value| Element::alloc(dr, &mut (), D::just(|| value)))
                .collect::<Result<Vec<_>>>()?;
            stages.push((points, elements));
        }
        Ok(Allocated {
            stages: stages
                .try_into()
                .map_err(|_| Error::InvalidWitness("four stages".into()))?,
        })
    }

    fn view(&self) -> Loaded<'_, 'dr, D, P> {
        let view = |i: usize| View {
            points: &self.stages[i].0[..],
            elements: &self.stages[i].1[..],
        };
        Loaded {
            instance: view(0),
            messages: view(1),
            work: view(2),
            transcript: view(3),
        }
    }
}

/// Stores the prover-supplied slots of a side's work stage: the registry
/// values, the restrictions and the IPA's witness points.
fn supply<F: Field, P, Q>(
    schedule: &Schedule,
    circuit_id: CircuitIndex,
    own: &SideWitness<Q>,
    other: &SideWitness<P>,
    work: &mut Values<F, P>,
) where
    P: Affine,
    Q: Affine<Scalar = F>,
{
    let regions = &schedule.regions;
    for (claim, slot) in schedule.claims.iter().zip(&regions.restrictions) {
        if let (Kind::Circuit(circuit) | Kind::Bonding(circuit), Some(slot)) = (claim.kind, slot) {
            let circuit = if circuit == APPLICATION {
                circuit_id
            } else {
                circuit
            };
            let value = own
                .restrictions
                .iter()
                .find(|(listed, _)| *listed == circuit)
                .expect("every named circuit's restriction")
                .1;
            work.elements[*slot] = value;
        }
    }
    work.elements[regions.restriction_at_w] = own.restriction_at_w;
    for (plan, (_, _, values)) in schedule.bindings.iter().zip(&own.masked) {
        for (src, value) in plan.expected.iter().zip(values) {
            if let ElementSrc::Work(slot) = src {
                work.elements[*slot] = *value;
            }
        }
    }
    for (slot, point) in regions.inverse_scaled.iter().zip(&other.inverse_scaled) {
        work.points[*slot] = *point;
    }
    work.points[regions.g_prime] = other.g_prime;
}

type Executor<F> = Emulator<Wireless<Always<()>, F>>;

/// The endoscalars of raw challenges, as their bits.
fn bits<F: Field>(raw: &[F]) -> Result<Vec<u128>> {
    raw.iter().map(|&raw| extract_endoscalar(raw)).collect()
}

impl<C: Cycle, S: Side<C>> Prepared<C, S> {
    /// Prepares side `S` from the prepared `witness` for chunk circuits at
    /// rank `R` and runs its chunks natively to fill the work and
    /// transcript stages.
    pub(crate) fn new<K: Rank, R: Rank, const HEADER_SIZE: usize>(
        params: &C::Params,
        witness: &Witness<C>,
    ) -> Result<Self> {
        let instance = &witness.proof.instance;
        let schedule = S::schedule::<K, R, HEADER_SIZE>()?;
        // The schedule reads the ab bridge's layout off the stage's wires and
        // the witness off the stage polynomial; they name the same generators.
        let mut layout = schedule.ab_terms.clone();
        layout.sort_by_key(|term| term.0);
        let mut actual = witness.ab_terms.clone();
        actual.sort_by_key(|term| term.0);
        assert_eq!(
            layout, actual,
            "the ab bridge layout is the stage polynomial's"
        );
        let mut work = Values::blank(schedule.points, schedule.elements, S::generators(params)[0]);
        supply(
            &schedule,
            instance.circuit_id,
            S::own(witness),
            S::other(witness),
            &mut work,
        );
        let mut transcript = S::transcript(params, instance, &witness.proof);
        transcript.elements = alloc::vec![S::F::ZERO; schedule.states];
        let mut challenge_bits = bits(&S::own(witness).raw.in_order())?;
        challenge_bits.extend(bits(&[witness.fuse.x, witness.fuse.y, witness.fuse.u])?);
        challenge_bits.extend(bits(&S::other(witness).raw.in_order())?);
        let aux = Aux {
            challenge_bits,
            foreign: S::foreign(witness, &schedule)?,
        };
        let mut prepared = Prepared {
            instance: S::instance(params, instance, &witness.header),
            messages: S::messages(params, &witness.proof),
            extra: S::extra(witness)?,
            schedule,
            work,
            transcript,
            aux,
        };
        prepared.run::<K, HEADER_SIZE>(params)?;
        Ok(prepared)
    }

    /// Runs every chunk natively, storing what each writes.
    fn run<K: Rank, const HEADER_SIZE: usize>(&mut self, params: &C::Params) -> Result<()> {
        for k in 0..self.schedule.chunks.len() {
            let mut dr = Executor::<S::F>::execute();
            let allocated = Allocated::alloc(
                &mut dr,
                [&self.instance, &self.messages, &self.work, &self.transcript],
            )?;
            let writes = {
                let ctx = Ctx {
                    loaded: allocated.view(),
                    schedule: &self.schedule,
                    generators: S::generators(params),
                    u: S::u(params),
                    poseidon: S::poseidon(params),
                    witness: Executor::<S::F>::just(|| &*self),
                };
                execute::<_, C, S, K, HEADER_SIZE>(&mut dr, &self.schedule.chunks[k], &ctx)?
            };
            for write in writes {
                match write {
                    Write::Element(slot, element) => {
                        self.work.elements[slot] = *element.value().take();
                    }
                    Write::Point(slot, point) => {
                        self.work.points[slot] = point.value().take();
                    }
                    Write::State(slot, element) => {
                        self.transcript.elements[slot] = *element.value().take();
                    }
                }
            }
        }
        Ok(())
    }
}

/// Both sides prepared for one compressed proof.
pub(crate) struct Sides<C: IpaCycle + ProfiledCycle<Profile = Standard>> {
    pub native: Prepared<C, Native>,
    pub nested: Prepared<C, Nested>,
}

impl<C: IpaCycle + ProfiledCycle<Profile = Standard>> Sides<C> {
    /// Prepares both sides for `pcd` under `app`, for chunk circuits at
    /// rank `R`.
    ///
    /// # Errors
    ///
    /// Fails if the native verifier would reject the proof, or on an
    /// internal error.
    pub(crate) fn prepare<K: Rank, R: Rank, const HEADER_SIZE: usize, B: SelectableBackend, H>(
        app: &Application<'_, C, K, HEADER_SIZE, B>,
        pcd: &CompressedPcd<C, H>,
    ) -> Result<Self>
    where
        H: Header<C::CircuitField>,
    {
        let witness = Witness::prepare(app, pcd)?;
        Ok(Sides {
            native: Prepared::new::<K, R, HEADER_SIZE>(app.params, &witness)?,
            nested: Prepared::new::<K, R, HEADER_SIZE>(app.params, &witness)?,
        })
    }
}

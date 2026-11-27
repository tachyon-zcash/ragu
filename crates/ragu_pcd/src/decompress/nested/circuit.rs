//! The scalar-field side's whole circuit ([`Circuit`]): the side's verifier
//! over its stages, in its [`witness`](MultiStageCircuit::witness), as the
//! internal recursion circuits each verify their part in theirs. It loads the
//! stages unenforced and gives what it writes to the lifts and digits
//! stages beside its output ([`Written`]).

use alloc::{sync::Arc, vec, vec::Vec};
use core::{iter::once, marker::PhantomData};

use ragu_circuits::{
    WithAux,
    paging::Pageable,
    polynomials::Rank,
    staging::{MultiStage, MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Cycle, Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Boolean, Element, Endoscalar, GadgetExt, NonzeroBank, Point, WithSuffix, vec::FixedVec,
};

use super::{
    super::{
        common::{
            AbValue, Carried, Challenge, Exposed, Prepared, Run, Side, Tables, Written,
            challenges_per_curve, coordinates, fuse, squeezed,
        },
        gadgets::derive::{self, Digits},
        online::input,
        stages::{
            AB_TERMS, DigitsStage, LiftsStage, OnlineInputStage, OnlineQueryStage, nested_scalars,
        },
    },
    Nested, NestedTargets,
    stages::{RunIndex, Runs, TrailingStage, load_nested_front},
};
use crate::{
    compress::revdot::{native_components, native_position},
    internal::{
        native,
        nested::{claims::ky_values as nested_ky_values, unified as nested_unified},
    },
    ipa::IpaCycle,
    profile::{ProfiledCycle, Standard},
};

/// The scalar-field side's whole circuit: the side's verifier over its
/// stages, for a proof at rank `K` in polynomials of rank `R`, over the
/// host curve. It exposes its recomputation of the circuit-field side's
/// digits stage, then the two application output commitments and the
/// commitment of the host IPA's $s(X)$ in the native batch of the step
/// that proves the side.
pub(crate) struct Circuit<'p, C: Cycle, K, R, const HEADER_SIZE: usize> {
    tables: Arc<Tables>,
    params: &'p C::Params,
    _marker: PhantomData<fn() -> (K, R)>,
}

impl<C: Cycle, K, R, const HEADER_SIZE: usize> Clone for Circuit<'_, C, K, R, HEADER_SIZE> {
    fn clone(&self) -> Self {
        Circuit {
            tables: self.tables.clone(),
            params: self.params,
            _marker: PhantomData,
        }
    }
}

impl<'p, C, K, R, const HEADER_SIZE: usize> Circuit<'p, C, K, R, HEADER_SIZE>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Runs,
    R: Rank,
{
    /// The side's whole circuit, laid out by `tables`, the side's
    /// ([`tables`](crate::decompress::common::tables)).
    pub(crate) fn new(
        tables: Arc<Tables>,
        params: &'p C::Params,
    ) -> MultiStage<C::ScalarField, R, Self> {
        MultiStage::new(Circuit {
            tables,
            params,
            _marker: PhantomData,
        })
    }
}

impl<C, K, R, const HEADER_SIZE: usize> MultiStageCircuit<C::ScalarField, R>
    for Circuit<'_, C, K, R, HEADER_SIZE>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Runs,
    R: Rank,
{
    type Last = DigitsStage<C, Nested, K, R, HEADER_SIZE>;
    type Instance<'source> = FixedVec<C::HostCurve, Exposed<C, Nested, K>>;
    type Witness<'source> = &'source Prepared<C, Nested>;
    type Output = Kind![
        C::ScalarField;
        @WithSuffix<
            '_,
            _,
            Kind![C::ScalarField; FixedVec<Point<'_, _, C::HostCurve>, Exposed<C, Nested, K>>]
        >
    ];
    type Aux<'source> = Written<C::ScalarField, C::HostCurve>;

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::ScalarField>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let exposed =
            FixedVec::try_from_fn(|i| Point::alloc(dr, instance.as_ref().map(|points| points[i])))?;
        Ok(WithSuffix::new(exposed, Element::zero(dr)))
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::ScalarField>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        let (online_input, dr) = dr.add_stage::<OnlineInputStage<C, Nested, R>>()?;
        let (online_query, dr) = dr.add_stage::<OnlineQueryStage<C, Nested, R>>()?;
        // One stage per run of the compression's transcript, then the
        // trailing stage.
        let (runs, dr) = K::Last::add::<C, K, R, D, _>(dr)?;
        let (trailing, dr) = dr.add_stage::<TrailingStage<C, K, R>>()?;
        let (lifts, dr) = dr.add_stage::<LiftsStage<C, Nested, K, R, HEADER_SIZE>>()?;
        let (digits, dr) = dr.add_stage::<DigitsStage<C, Nested, K, R, HEADER_SIZE>>()?;
        let dr = dr.finish();
        let online_input =
            online_input.unenforced(dr, witness.as_ref().map(|w| &w.online_input))?;
        let online_query =
            online_query.unenforced(dr, witness.as_ref().map(|w| &w.online_query))?;
        let front = load_nested_front::<C, K, R, D>(runs, trailing, dr, &witness)?;
        let lifts = lifts.unenforced(dr, witness.as_ref().map(|w| &w.lifts))?;
        let digits = digits.unenforced(dr, witness.as_ref().map(|w| &w.digits))?;

        let mut run = Run::new(
            &self.tables,
            front.instance(),
            front.messages(),
            [&online_input.elements[..], &online_query.elements[..]],
            &lifts.elements[..],
            &digits.elements[..],
            (
                <Nested as Side<C>>::generators(self.params),
                <Nested as Side<C>>::u(self.params),
                <Nested as Side<C>>::poseidon(self.params),
            ),
            witness,
        );
        let run = &mut run;

        let tables = run.tables;
        let instance = tables.layout.instance;
        let per_curve = challenges_per_curve::<K>();
        let lifted = fuse::LIFTED.len();

        // The lifts: the nested curve's compression challenges, the fuse's x,
        // y, u and w and the host curve's compression challenges, all squeezed
        // on the other side, from their bits, into the lifts stage in that
        // order, which the other side recomputes. Each fills the slot every
        // other use of the challenge holds its bits' lift to, so it allocates
        // the bits alone and lets the write hold them.
        for id in 0..2 * per_curve + lifted {
            let lift = run.bits(dr, id)?.lift(dr)?;
            run.lifts.write(dr, id, lift)?;
        }
        let fuse_lift = |run: &Run<'_, '_, 'dr, D, C, Nested>, i: usize| run.lift(per_curve + i);

        // The wire bindings on the nested side.
        let expected = vec![
            (nested_scalars::LEFT_X..=nested_scalars::RIGHT_Y)
                .map(|i| Some(run.scalar(i)))
                .collect(),
            vec![None; tables.bindings[1].len()],
            vec![
                None,
                None,
                None,
                Some(run.scalar(nested_scalars::A_AT_U)),
                Some(run.scalar(nested_scalars::B_AT_U)),
                None,
            ],
        ];

        // The ab bridge's values, whose digits the other side scales by: the
        // coordinates of the host curve's A, B and points-ab commitments and
        // the stage's alpha, bridge_alpha squared.
        let ab = [
            native_position::<Standard>(native::RxComponent::AbA),
            native_position::<Standard>(native::RxComponent::AbB),
        ];
        let extra_digits = {
            let a = coordinates(dr, &run.commitment(ab[0]))?;
            let b = coordinates(dr, &run.commitment(ab[1]))?;
            let points_ab =
                native_position::<Standard>(native::RxComponent::Rx(native::RxIndex::PointsAb));
            let points_ab = coordinates(dr, &run.commitment(points_ab))?;
            let mut digits = Vec::with_capacity(tables.ab_terms.len());
            for &(_, which) in &tables.ab_terms {
                digits.push(match which {
                    AbValue::A(i) => a[i].clone(),
                    AbValue::B(i) => b[i].clone(),
                    AbValue::PointsAb(i) => points_ab[i].clone(),
                    AbValue::Alpha => run.scalar(nested_scalars::BRIDGE_ALPHA).square(dr)?,
                });
            }
            digits
        };

        // The lifts the lifts stage holds, in `fuse::LIFTED` order for the
        // fuse's, and the children's values as the instance holds them.
        let inputs = vec![
            (run.lift(squeezed::R)?, input::R),
            (run.lift(squeezed::Y)?, input::Y_C),
            (fuse_lift(run, 0)?, input::X),
            (fuse_lift(run, 1)?, input::Y),
            (run.scalar(nested_scalars::LEFT_X), input::LEFT_X),
            (run.scalar(nested_scalars::LEFT_Y), input::LEFT_Y),
            (run.scalar(nested_scalars::RIGHT_X), input::RIGHT_X),
            (run.scalar(nested_scalars::RIGHT_Y), input::RIGHT_Y),
            (fuse_lift(run, 2)?, input::U),
            (fuse_lift(run, 3)?, input::W),
            (run.lift(squeezed::W)?, input::W_C),
        ];
        let targets = nested_targets::<_, C, K>(dr, run)?;
        let opening = [
            fuse_lift(run, 2)?,
            run.scalar(nested_scalars::V),
            run.scalar(nested_scalars::A_AT_U),
            run.scalar(nested_scalars::B_AT_U),
        ];
        // The registry's evaluations, then the reduction the side checks in its
        // field, leaving v and c b z, whose digits, c's and the ab bridge's
        // terms' the circuit-field side scales by.
        let registry = run.registry(dr, expected, &inputs)?;
        let [v, cbz] = run.reduction::<K>(dr, targets, registry, opening, None)?;
        let mut digits = vec![v, run.message_scalars().c().clone(), cbz];
        digits.extend(extra_digits);
        // The point checks of the host curve under the native reduction's
        // challenges, taken from their bits, leaving G', then every point the
        // stages hold on the curve.
        let point_challenge = |i| Challenge::bits(per_curve + lifted + i);
        let g_prime = run.point_checks::<K>(
            dr,
            &point_challenge,
            native_components::<Standard>().count(),
            ab,
        )?;
        run.points_on_curve(dr)?;

        // The binding claim ties these commitments to the aggregator's PCS.
        // Under the decompression flag, its application slots carry the wallet
        // proof's own commitments, and the native batch's s(X) commits to G'.
        let mut outputs = Vec::with_capacity(crate::header::NUM_ONLINE_FP_POLYS);
        for i in 0..crate::header::NUM_ONLINE_FP_POLYS {
            let value = run.witness.as_ref().map(|w| w.supplied.outputs[i]);
            outputs.push(Point::alloc(dr, value)?);
        }
        let host_ipa = Point::alloc(dr, run.witness.as_ref().map(|w| w.supplied.host_ipa))?;
        let wallet_start = instance
            .commitments
            .at(instance.commitments.len - outputs.len());
        let pairs: Vec<[Point<'dr, D, C::HostCurve>; 2]> = outputs
            .iter()
            .enumerate()
            .map(|(i, output)| {
                [
                    output.clone(),
                    run.instance.points[wallet_start + i].clone(),
                ]
            })
            .chain([[host_ipa.clone(), g_prime]])
            .collect();
        run.equal_if(dr, 0, &pairs)?;

        let digits_sum = run.digits_sum(dr)?;
        let exposed: Vec<_> = once(digits_sum).chain(outputs).chain([host_ipa]).collect();
        assert_eq!(
            digits.len(),
            3 + AB_TERMS,
            "the ab bridge's terms are pinned"
        );
        run.write_digits(dr, &digits, &[])?;
        if exposed.len() != <Nested as Side<C>>::exposed::<K>() {
            return Err(Error::InvalidWitness(
                "the side's verifier exposes the side's points".into(),
            ));
        }
        let written = run.written(&exposed)?;
        // The zero every extension circuit's output ends with: the circuit
        // writes it, so the check holds the last page to it.
        let exposed = WithSuffix::new(FixedVec::try_from(exposed)?, Element::zero(dr));
        Ok(WithAux::new(exposed, written))
    }
}

impl<C, K, R, const HEADER_SIZE: usize> Pageable<C::ScalarField, R>
    for Circuit<'_, C, K, R, HEADER_SIZE>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Runs,
    R: Rank,
{
    type Carry = Carried<C, Nested>;
}

/// The claims' targets of the scalar-field side's reduction, as the
/// circuit-field side's: allocates the nested unified instance, binds it to
/// the instance stage and to the lifts of the fuse's challenges, and
/// derives the targets.
pub(super) fn nested_targets<'dr, D, C, K>(
    dr: &mut D,
    run: &Run<'_, '_, 'dr, D, C, Nested>,
) -> Result<Vec<Element<'dr, D>>>
where
    D: Driver<'dr, F = C::ScalarField>,
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
{
    let output = nested_unified::Output::<D, C::HostCurve>::alloc(
        dr,
        &mut (),
        run.witness.as_ref().map(|w| &w.extra.unified),
    )?;
    // The fuse's x, y and u, in `fuse::LIFTED` order after the nested
    // curve's compression challenges in the lifts stage.
    let fuse_lifts = challenges_per_curve::<K>();
    for (i, ours) in [&output.x, &output.y, &output.u].into_iter().enumerate() {
        ours.enforce_equal(dr, &run.lift(fuse_lifts + i)?)?;
    }
    output.c.enforce_equal(dr, &run.scalar(nested_scalars::C))?;
    output.v.enforce_equal(dr, &run.scalar(nested_scalars::V))?;
    let listed = native_components::<Standard>().count();
    let exported: [usize; nested_unified::NUM_EXPORTED] = {
        use native::{RxComponent::*, RxIndex::*};
        [
            native_position::<Standard>(Rx(Preamble)),
            native_position::<Standard>(Rx(InnerError)),
            native_position::<Standard>(Rx(OuterError)),
            native_position::<Standard>(Rx(Query)),
            native_position::<Standard>(Rx(Eval)),
            native_position::<Standard>(AbA),
            native_position::<Standard>(AbB),
            listed,
            listed + 1,
            native_position::<Standard>(Rx(PointsBinding)),
            native_position::<Standard>(Rx(PointsPreamble)),
            native_position::<Standard>(Rx(PointsRegistryWx)),
            native_position::<Standard>(Rx(PointsAb)),
            native_position::<Standard>(Rx(PointsF)),
            listed + 2,
            listed + 3,
        ]
    };
    for (position, theirs) in exported.iter().zip(output.exported.iter()) {
        run.commitment(*position).enforce_equal(dr, theirs)?;
    }
    let y = run.lift(squeezed::Y)?;
    let targets = NestedTargets {
        c: run.scalar(nested_scalars::C),
        unified: output.ky(dr, &y)?,
        one: Element::one(),
        zero: Element::zero(dr),
    };
    Ok(nested_ky_values::<Standard, _>(&targets)
        .take(run.tables.claims.len())
        .collect())
}

/// The scalar-field side's own parts of its verifier: the challenges it
/// takes from their bits and the equalities it holds under the
/// circuit-field side's flags.
impl<'dr, D, C> Run<'_, '_, 'dr, D, C, Nested>
where
    D: Driver<'dr, F = C::ScalarField>,
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
{
    /// The endoscalar of the challenge at `id` of the side's challenge
    /// bits, allocated from them and held to nothing: what the side lifts
    /// into the lifts stage's slot every other use holds its bits to.
    pub(super) fn bits(&self, dr: &mut D, id: usize) -> Result<Endoscalar<'dr, D>> {
        let bits = self.witness.as_ref().map(|w| w.aux.challenge_bits[id]);
        Endoscalar::alloc(dr, bits)
    }

    /// Holds the points of each pair equal under the other side's flag
    /// `flag`: its bit, by index into the side's foreign flags, which the
    /// side allocates as a witness and the other side's digits stage
    /// binds, its signed digit's part of that stage's commitment riding
    /// along as a scaling's digits' does. A flag is taken once.
    ///
    /// # Panics
    ///
    /// Panics if the flag was taken before.
    pub(super) fn equal_if(
        &mut self,
        dr: &mut D,
        flag: usize,
        pairs: &[[Point<'dr, D, C::HostCurve>; 2]],
    ) -> Result<()> {
        assert!(
            self.flag_bound[flag].is_none(),
            "a foreign flag binds its digit once"
        );
        // Bind the flag once to the digit sent by the other side, and use
        // the same bit for each point comparison.
        let value = self.witness.as_ref().map(|w| w.aux.flags[flag]);
        let bit = Boolean::alloc(dr, &mut (), value)?;
        for [left, right] in pairs {
            let left = coordinates(dr, left)?;
            let right = coordinates(dr, right)?;
            for (left, right) in left.iter().zip(&right) {
                let gap = left.sub(dr, right);
                bit.element().mul(dr, &gap)?.enforce_zero(dr)?;
            }
        }
        let width = derive::digit_width::<C::CircuitField>();
        let generator = self.tables.foreign[self.bound.len() * width + flag];
        let digit = Digits::of_flag(bit);
        self.flag_bound[flag] = Some(self.bind_sum(dr, &digit, &[generator], None)?);
        Ok(())
    }

    /// The part of the other side's digits stage commitment over `digits`:
    /// each digit's generator, `generators` names them, added or
    /// subtracted by its bit, onto `init` or from nothing.
    pub(super) fn bind_sum(
        &self,
        dr: &mut D,
        digits: &Digits<'dr, D>,
        generators: &[usize],
        init: Option<Point<'dr, D, C::HostCurve>>,
    ) -> Result<Point<'dr, D, C::HostCurve>> {
        assert_eq!(generators.len(), digits.len(), "one generator per digit");
        let mut acc = init;
        NonzeroBank::scope(dr, |dr, bank| {
            for (bit, &generator) in digits.bits().iter().zip(generators) {
                let base = Point::constant(dr, self.generators[generator])?;
                let negate = bit.not(dr);
                let term = base.conditional_negate(dr, &negate)?;
                acc = Some(match acc.take() {
                    None => term,
                    Some(acc) => acc.add_incomplete(dr, &term, bank)?,
                });
            }
            acc.ok_or_else(|| Error::InvalidWitness("a scalar has a digit".into()))
        })
    }
}

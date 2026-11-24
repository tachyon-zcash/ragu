//! The chunk circuits: one circuit per group of chunks of a side's
//! schedule ([`Schedule::circuits`]), loading the side's stages and
//! holding the chunks' results to their wires.
//!
//! Every chunk circuit of a side has the same shape: the stages loaded
//! unenforced, as the fuse's endoscaling steps load theirs, then its
//! chunks' own gates, in order. A [`Circuit`] loads the aggregator's two
//! online stages ([`OnlineInputStage`] and [`OnlineQueryStage`]), then the
//! side's front stages (see [`Front`]), the lifts stage and the work stage;
//! a [`TranscriptCircuit`], for transcript chunks, loads the transcript
//! stage after them as well, so that only those chunks pay for the sponge
//! states; a [`DigitsCircuit`], for the digits chunks, loads the digits
//! stage after the work stage instead. Which chunks a circuit runs is
//! fixed by its index into the schedule, so the family of chunk circuits
//! is as fixed as the schedule, and the stages' masks bind the layout the
//! chunks read.
//!
//! A chunk circuit at rank `R` verifies a compressed proof at rank `K`:
//! its schedule is cut for `R`'s gate budget, and what it loads and checks
//! is sized by `K`. An aggregator runs the chunks at
//! [`AggregatorRank`](ragu_circuits::polynomials::AggregatorRank) over
//! wallets' proofs at the wallet rank.
//!
//! Beside the chunks, a [`StatementCircuit`] loads the online stages and
//! the instance stage, and no other, and exposes the output header the
//! chunks verified, then the step binding, as its public output, the one
//! place the decompressed statement reaches a claim; and a
//! [`BindingCircuit`] loads the stages a [`Circuit`] does and exposes, off
//! the work stage, the other side's stage commitments the side absorbed or
//! recomputed and what it took of the step's own online polynomials
//! ([`Regions::exposed`](super::program::Regions::exposed) and
//! [`Regions::exposed_elements`](super::program::Regions::exposed_elements))
//! as its public output, which the proof's consumer holds to those
//! commitments and openings through the circuit's claim (see
//! [`Binding`](crate::profile::Binding)).
//!
//! Every chunk circuit runs its chunks through [`execute`], over the
//! loaded stages, and holds what each writes to the work, lifts,
//! transcript and digits stages' wires ([`enforce`]). The prover's
//! native run of the same chunks ([`Prepared::run`]) stores those writes
//! instead. The chunk kinds are the same on both sides; what differs, the
//! targets and their order, goes through the [`Side`].

use alloc::{sync::Arc, vec::Vec};
use core::marker::PhantomData;

use ragu_circuits::{
    WithAux,
    polynomials::Rank,
    staging::{MultiStage, MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Coeff, Cycle, Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Boolean, Element, Endoscalar, EndoscalarChallenge, GadgetExt, NonzeroBank, Point, Uendo,
    consistent::Consistent,
    poseidon::{Sponge, SpongeState},
    vec::{ConstLen, FixedVec, Len},
};
use udon::{
    curve::{EndomorphismAffine as Affine, Projective},
    field::Field,
};

use super::{
    gadgets::{
        batch,
        derive::{self, Digits},
        ipa, revdot,
    },
    online,
    program::{
        Bind, ChainChunk, ChallengeRef, Chunk, ElementSrc, FixedPointSrc, Last, Op, PointSrc,
        ScalarRef, Schedule, Step, squeezed,
    },
    side::Side,
    stages::{
        self, DigitsStage, Front, InstanceStage, LiftsStage, MessageScalars, OnlineInputStage,
        OnlineQueryStage, TranscriptStage, Values, WorkStage, step,
    },
};
use crate::compress::{
    instance::OPENED,
    revdot::{
        OpeningClaim,
        claims::Kind,
        fold::{Derived, Weights},
    },
};

/// The last stage circuit `index` of `schedule` loads, which says whether
/// it is a [`Circuit`], a [`TranscriptCircuit`] or a [`DigitsCircuit`].
pub(crate) fn last(schedule: &Schedule, index: usize) -> Last {
    schedule.circuits[index].last
}

/// What the chunk circuit types hold.
struct Inner<'p, C: Cycle> {
    index: usize,
    schedule: Arc<Schedule>,
    params: &'p C::Params,
}

impl<C: Cycle> Clone for Inner<'_, C> {
    fn clone(&self) -> Self {
        Inner {
            index: self.index,
            schedule: self.schedule.clone(),
            params: self.params,
        }
    }
}

impl<'p, C: Cycle> Inner<'p, C> {
    fn new(index: usize, schedule: Arc<Schedule>, params: &'p C::Params, last: Last) -> Self {
        assert!(
            index < schedule.circuits.len(),
            "circuit {index} is within the schedule's {}",
            schedule.circuits.len()
        );
        assert_eq!(
            schedule.circuits[index].last, last,
            "circuit {index} loads the stages of its kind"
        );
        Inner {
            index,
            schedule,
            params,
        }
    }

    /// Runs the circuit's chunks over the loaded stages, in order, and
    /// holds their writes.
    fn synthesize<'dr, D, S, K, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        loaded: Loaded<'_, 'dr, D, S::P>,
        witness: DriverValue<D, &Prepared<C, S>>,
    ) -> Result<()>
    where
        'p: 'dr,
        D: Driver<'dr, F = S::F>,
        S: Side<C>,
        K: Rank,
    {
        let ctx = Ctx {
            loaded,
            schedule: &self.schedule,
            generators: S::generators(self.params),
            u: S::u(self.params),
            poseidon: S::poseidon(self.params),
            witness,
        };
        let plan = &self.schedule.circuits[self.index];
        for &index in &plan.chunks {
            let chunk = &self.schedule.chunks[index];
            let writes = execute::<_, C, S, K, HEADER_SIZE>(dr, chunk, &ctx)?;
            enforce(dr, loaded, writes)?;
        }
        Ok(())
    }
}

/// Defines a chunk circuit type whose last stage is `$Last`, loaded after
/// the common four as `$extra`, with `$kind` its [`Last`].
macro_rules! chunk_circuit {
    (
        $(#[$meta:meta])*
        $Circuit:ident, $kind:expr, $Last:ident, $extra:ident,
        |$loaded:ident| $view:expr
    ) => {
        $(#[$meta])*
        pub(crate) struct $Circuit<'p, C: Cycle, S, K, R, const HEADER_SIZE: usize> {
            inner: Inner<'p, C>,
            _marker: PhantomData<fn() -> (S, K, R)>,
        }

        impl<C: Cycle, S, K, R, const HEADER_SIZE: usize> Clone
            for $Circuit<'_, C, S, K, R, HEADER_SIZE>
        {
            fn clone(&self) -> Self {
                $Circuit {
                    inner: self.inner.clone(),
                    _marker: PhantomData,
                }
            }
        }

        impl<'p, C: Cycle, S: Front<C, K, R, HEADER_SIZE>, K: Rank, R: Rank, const HEADER_SIZE: usize>
            $Circuit<'p, C, S, K, R, HEADER_SIZE>
        {
            /// The circuit at `index` of `schedule`.
            ///
            /// # Panics
            ///
            /// Panics if `index` is not a circuit of the schedule, or runs
            /// chunks of another kind.
            pub(crate) fn new(
                index: usize,
                schedule: Arc<Schedule>,
                params: &'p C::Params,
            ) -> MultiStage<S::F, R, Self> {
                MultiStage::new($Circuit {
                    inner: Inner::new(index, schedule, params, $kind),
                    _marker: PhantomData,
                })
            }
        }

        impl<C: Cycle, S: Front<C, K, R, HEADER_SIZE>, K: Rank, R: Rank, const HEADER_SIZE: usize>
            MultiStageCircuit<S::F, R> for $Circuit<'_, C, S, K, R, HEADER_SIZE>
        {
            type Last = $Last<C, S, K, R, HEADER_SIZE>;
            type Instance<'source> = ();
            type Witness<'source> = &'source Prepared<C, S>;
            type Output = S::Output;
            type Aux<'source> = ();

            fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = S::F>>(
                &self,
                dr: &mut D,
                _: DriverValue<D, ()>,
            ) -> Result<Bound<'dr, D, Self::Output>> {
                Ok(S::output(dr))
            }

            fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = S::F>>(
                &self,
                dr: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
                witness: DriverValue<D, Self::Witness<'source>>,
            ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
            where
                Self: 'dr,
            {
                let (online_input, dr) = dr.add_stage::<OnlineInputStage<C, S, R>>()?;
                let (online_query, dr) = dr.add_stage::<OnlineQueryStage<C, S, R>>()?;
                let (front, dr) = <S as Front<C, K, R, HEADER_SIZE>>::add(dr)?;
                let (lifts, dr) = dr.add_stage::<LiftsStage<C, S, K, R, HEADER_SIZE>>()?;
                let (work, dr) = dr.add_stage::<WorkStage<C, S, K, R, HEADER_SIZE>>()?;
                let ($extra, dr) = chunk_circuit!(@extra dr, $Last, $extra, C, S, K, R, HEADER_SIZE);
                let dr = dr.finish();
                let online_input =
                    online_input.unenforced(dr, witness.as_ref().map(|w| &w.online_input))?;
                let online_query =
                    online_query.unenforced(dr, witness.as_ref().map(|w| &w.online_query))?;
                let front = <S as Front<C, K, R, HEADER_SIZE>>::load(front, dr, &witness)?;
                let lifts = lifts.unenforced(dr, witness.as_ref().map(|w| &w.lifts))?;
                let work = work.unenforced(dr, witness.as_ref().map(|w| &w.work))?;
                let $extra = chunk_circuit!(@load dr, witness, $extra, $extra);
                let $loaded = (&front, &lifts, &work, &$extra);
                let mut loaded = $view;
                loaded.online_input = View::new(&online_input);
                loaded.online_query = View::new(&online_query);
                self.inner
                    .synthesize::<_, S, K, HEADER_SIZE>(dr, loaded, witness)?;
                Ok(WithAux::new(S::output(dr), D::unit()))
            }
        }
    };
    (@extra $dr:ident, WorkStage, $extra:ident, $C:ty, $S:ty, $K:ty, $R:ty, $H:expr) => {
        ((), $dr)
    };
    (@extra $dr:ident, $Last:ident, $extra:ident, $C:ty, $S:ty, $K:ty, $R:ty, $H:expr) => {
        $dr.add_stage::<$Last<$C, $S, $K, $R, $H>>()?
    };
    (@load $dr:ident, $witness:ident, $extra:ident, transcript) => {
        $extra.unenforced($dr, $witness.as_ref().map(|w| &w.transcript))?
    };
    (@load $dr:ident, $witness:ident, $extra:ident, digits) => {
        $extra.unenforced($dr, $witness.as_ref().map(|w| &w.digits))?
    };
    (@load $dr:ident, $witness:ident, $extra:ident, none) => {{
        let _ = &$extra;
    }};
}

chunk_circuit!(
    /// The chunk circuit at an index of side `S`'s schedule, for chunks
    /// that need no stage past the work stage.
    Circuit, Last::Work, WorkStage, none,
    |loaded| {
        let (front, lifts, work, ()) = loaded;
        Loaded {
            instance: front.instance(),
            messages: front.messages(),
            lifts: View::new(lifts),
            work: View::new(work),
            transcript: View::empty(),
            digits: View::empty(),
            online_input: View::empty(),
            online_query: View::empty(),
        }
    }
);

chunk_circuit!(
    /// The chunk circuit at an index of side `S`'s schedule, for transcript
    /// chunks: loads the transcript stage as well.
    TranscriptCircuit, Last::Transcript, TranscriptStage, transcript,
    |loaded| {
        let (front, lifts, work, transcript) = loaded;
        Loaded {
            instance: front.instance(),
            messages: front.messages(),
            lifts: View::new(lifts),
            work: View::new(work),
            transcript: View::new(transcript),
            digits: View::empty(),
            online_input: View::empty(),
            online_query: View::empty(),
        }
    }
);

chunk_circuit!(
    /// The chunk circuit at an index of side `S`'s schedule, for digits
    /// chunks: loads the digits stage as well.
    DigitsCircuit, Last::Digits, DigitsStage, digits,
    |loaded| {
        let (front, lifts, work, digits) = loaded;
        Loaded {
            instance: front.instance(),
            messages: front.messages(),
            lifts: View::new(lifts),
            work: View::new(work),
            transcript: View::empty(),
            digits: View::new(digits),
            online_input: View::empty(),
            online_query: View::empty(),
        }
    }
);

/// The statement circuit of side `S`: the circuit whose public output is
/// the output header of the compressed proof the chunks verified, then the
/// step binding ([`step`]), both read off the instance stage. The chunks
/// bind the header to the proof they verify, so a claim on this circuit's
/// output is a claim on the decompressed proof's statement, which the
/// decompression step's verifier makes through the circuit's $k(y)$ (see
/// [`statement_ky`](crate::internal::native::stages::preamble::ProofInputs::statement_ky)).
/// The same claim binds the decompression flag and staged transcript digest.
pub(crate) struct StatementCircuit<C: Cycle, S, K, R, const HEADER_SIZE: usize> {
    schedule: Arc<Schedule>,
    _marker: PhantomData<fn() -> (C, S, K, R)>,
}

impl<C: Cycle, S, K, R, const HEADER_SIZE: usize> Clone
    for StatementCircuit<C, S, K, R, HEADER_SIZE>
{
    fn clone(&self) -> Self {
        StatementCircuit {
            schedule: self.schedule.clone(),
            _marker: PhantomData,
        }
    }
}

impl<C: Cycle, S: Side<C>, K: Rank, R: Rank, const HEADER_SIZE: usize>
    StatementCircuit<C, S, K, R, HEADER_SIZE>
{
    /// The statement circuit over `schedule`'s instance stage.
    pub(crate) fn new(schedule: Arc<Schedule>) -> MultiStage<S::F, R, Self> {
        MultiStage::new(StatementCircuit {
            schedule,
            _marker: PhantomData,
        })
    }
}

impl<C: Cycle, S: Side<C>, K: Rank, R: Rank, const HEADER_SIZE: usize> MultiStageCircuit<S::F, R>
    for StatementCircuit<C, S, K, R, HEADER_SIZE>
{
    type Last = InstanceStage<C, S, K, R, HEADER_SIZE>;
    /// The output header and the step binding the instance stage holds.
    type Instance<'source> = (
        FixedVec<S::F, ConstLen<HEADER_SIZE>>,
        FixedVec<S::F, ConstLen<{ step::LEN }>>,
    );
    type Witness<'source> = &'source Prepared<C, S>;
    type Output = Kind![S::F; (
        FixedVec<Element<'_, _>, ConstLen<HEADER_SIZE>>,
        FixedVec<Element<'_, _>, ConstLen<{ step::LEN }>>,
    )];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = S::F>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let header = FixedVec::try_from_fn(|i| {
            Element::alloc(dr, &mut (), instance.as_ref().map(|(header, _)| header[i]))
        })?;
        let step = FixedVec::try_from_fn(|i| {
            Element::alloc(dr, &mut (), instance.as_ref().map(|(_, step)| step[i]))
        })?;
        Ok((header, step))
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = S::F>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        let (online_input, dr) = dr.add_stage::<OnlineInputStage<C, S, R>>()?;
        let (online_query, dr) = dr.add_stage::<OnlineQueryStage<C, S, R>>()?;
        let (instance, dr) = dr.add_stage::<InstanceStage<C, S, K, R, HEADER_SIZE>>()?;
        let dr = dr.finish();
        // The online stages come first in every circuit of the side; this
        // one reads nothing off them.
        online_input.unenforced(dr, witness.as_ref().map(|w| &w.online_input))?;
        online_query.unenforced(dr, witness.as_ref().map(|w| &w.online_query))?;
        let instance = instance.unenforced(dr, witness.as_ref().map(|w| &w.instance))?;
        let layout = self.schedule.layout.instance;
        let read = |span: super::stages::Span| {
            span.positions()
                .map(|position| instance.elements[position].clone())
                .collect::<alloc::vec::Vec<_>>()
        };
        let header = FixedVec::try_from(read(layout.output_header))?;
        let step = FixedVec::try_from(read(layout.step))?;
        Ok(WithAux::new((header, step), D::unit()))
    }
}

/// Length type for the elements side `S`'s binding circuit exposes after
/// its points: [`Side::EXPOSED_ELEMENTS`].
pub(crate) struct ExposedElements<C, S>(PhantomData<fn() -> (C, S)>);

impl<C: Cycle, S: Side<C>> Len for ExposedElements<C, S> {
    fn len() -> usize {
        S::EXPOSED_ELEMENTS
    }
}

/// Length type for the points side `S`'s binding circuit exposes for a
/// proof at rank `K`: [`Side::exposed`].
pub(crate) struct Exposed<C, S, K>(PhantomData<fn() -> (C, S, K)>);

impl<C: Cycle, S: Side<C>, K: Rank> Len for Exposed<C, S, K> {
    fn len() -> usize {
        S::exposed::<K>()
    }
}

/// The binding circuit of side `S`: the circuit whose public output is the
/// other side's stage commitments the side absorbed or recomputed and what
/// it took of the step's own online polynomials, points then elements,
/// read off the work stage where the chunks left them
/// ([`Regions::exposed`](super::program::Regions::exposed) and
/// [`Regions::exposed_elements`](super::program::Regions::exposed_elements)). The chunks
/// bind those slots to the values the side took from the other side, so a
/// claim on this circuit's output at the $k(y)$ of the other side's actual
/// stage commitments, which the proof's consumer computes, holds only if
/// the two sides agree (see [`Binding`](crate::profile::Binding) and
/// [`binding_ky`](crate::internal::ky::binding_ky)).
pub(crate) struct BindingCircuit<C: Cycle, S, K, R, const HEADER_SIZE: usize> {
    schedule: Arc<Schedule>,
    _marker: PhantomData<fn() -> (C, S, K, R)>,
}

impl<C: Cycle, S, K, R, const HEADER_SIZE: usize> Clone
    for BindingCircuit<C, S, K, R, HEADER_SIZE>
{
    fn clone(&self) -> Self {
        BindingCircuit {
            schedule: self.schedule.clone(),
            _marker: PhantomData,
        }
    }
}

impl<C: Cycle, S: Front<C, K, R, HEADER_SIZE>, K: Rank, R: Rank, const HEADER_SIZE: usize>
    BindingCircuit<C, S, K, R, HEADER_SIZE>
{
    /// The binding circuit over `schedule`'s stages.
    pub(crate) fn new(schedule: Arc<Schedule>) -> MultiStage<S::F, R, Self> {
        assert_eq!(
            schedule.regions.exposed.len(),
            S::exposed::<K>(),
            "the schedule exposes the side's points"
        );
        MultiStage::new(BindingCircuit {
            schedule,
            _marker: PhantomData,
        })
    }
}

impl<C: Cycle, S: Front<C, K, R, HEADER_SIZE>, K: Rank, R: Rank, const HEADER_SIZE: usize>
    MultiStageCircuit<S::F, R> for BindingCircuit<C, S, K, R, HEADER_SIZE>
{
    type Last = WorkStage<C, S, K, R, HEADER_SIZE>;
    /// The exposed points, then the exposed elements.
    type Instance<'source> = (
        FixedVec<S::P, Exposed<C, S, K>>,
        FixedVec<S::F, ExposedElements<C, S>>,
    );
    type Witness<'source> = &'source Prepared<C, S>;
    type Output = Kind![S::F; (
        FixedVec<Point<'_, _, S::P>, Exposed<C, S, K>>,
        FixedVec<Element<'_, _>, ExposedElements<C, S>>,
    )];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = S::F>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let points = FixedVec::try_from_fn(|i| {
            Point::alloc(dr, instance.as_ref().map(|(points, _)| points[i]))
        })?;
        let elements = FixedVec::try_from_fn(|i| {
            Element::alloc(
                dr,
                &mut (),
                instance.as_ref().map(|(_, elements)| elements[i]),
            )
        })?;
        Ok((points, elements))
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = S::F>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        let (online_input, dr) = dr.add_stage::<OnlineInputStage<C, S, R>>()?;
        let (online_query, dr) = dr.add_stage::<OnlineQueryStage<C, S, R>>()?;
        let (front, dr) = <S as Front<C, K, R, HEADER_SIZE>>::add(dr)?;
        let (lifts, dr) = dr.add_stage::<LiftsStage<C, S, K, R, HEADER_SIZE>>()?;
        let (work, dr) = dr.add_stage::<WorkStage<C, S, K, R, HEADER_SIZE>>()?;
        let dr = dr.finish();
        online_input.unenforced(dr, witness.as_ref().map(|w| &w.online_input))?;
        online_query.unenforced(dr, witness.as_ref().map(|w| &w.online_query))?;
        let front = <S as Front<C, K, R, HEADER_SIZE>>::load(front, dr, &witness)?;
        let lifts = lifts.unenforced(dr, witness.as_ref().map(|w| &w.lifts))?;
        let work = work.unenforced(dr, witness.as_ref().map(|w| &w.work))?;
        let _ = (front, lifts);
        let exposed = self
            .schedule
            .regions
            .exposed
            .iter()
            .map(|&slot| work.points[slot].clone())
            .collect::<alloc::vec::Vec<_>>();
        let elements = self
            .schedule
            .regions
            .exposed_elements
            .iter()
            .map(|&slot| work.elements[slot].clone())
            .collect::<alloc::vec::Vec<_>>();
        Ok(WithAux::new(
            (FixedVec::try_from(exposed)?, FixedVec::try_from(elements)?),
            D::unit(),
        ))
    }
}

/// A chunk's result: the value a slot of the work stage, of the lifts
/// stage for a lift, of the transcript stage for a sponge state, or of the
/// digits stage for a digit, must hold.
pub(crate) enum Write<'dr, D: Driver<'dr>, P: Affine<Base = D::F>> {
    Element(usize, Element<'dr, D>),
    Point(usize, Point<'dr, D, P>),
    Lift(usize, Element<'dr, D>),
    State(usize, Element<'dr, D>),
    Digit(usize, Element<'dr, D>),
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
    pub lifts: View<'a, 'dr, D, P>,
    pub work: View<'a, 'dr, D, P>,
    pub transcript: View<'a, 'dr, D, P>,
    pub digits: View<'a, 'dr, D, P>,
    /// The online input stage's values, as the fuse lays them out.
    pub online_input: View<'a, 'dr, D, P>,
    /// The online query stage's values, likewise.
    pub online_query: View<'a, 'dr, D, P>,
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
#[derive(Clone)]
pub(crate) struct Aux<G> {
    /// Every compression challenge the side did not squeeze, in the order
    /// the schedule's [`ChallengeRef::Bits`] indexes them: the reduction
    /// it checks in its field, the fuse's $x$, $y$, $u$ and $w$, then the
    /// reduction whose points it checks.
    pub challenge_bits: Vec<Uendo>,
    /// The other field's values, in [`ScalarRef::Bits`] order: $v$, $c$
    /// and $c b z$ of the reduction whose points the side checks, then
    /// what the side's [`Prepare::foreign`](super::prover::Prepare::foreign) adds.
    pub foreign: Vec<G>,
    /// The other side's flags, by [`Chunk::EqualIf`]'s index: unset until
    /// the step that proves the chunks sets them.
    pub flags: Vec<bool>,
}

/// Everything a side's chunks need: the stages' values, the lifts, work,
/// transcript and digits stages filled, the auxiliary witnesses and the
/// schedule.
pub(crate) struct Prepared<C: Cycle, S: Side<C>> {
    pub schedule: Arc<Schedule>,
    pub instance: Values<S::F, S::P>,
    pub messages: Values<S::F, S::P>,
    pub lifts: Values<S::F, S::P>,
    pub work: Values<S::F, S::P>,
    pub transcript: Values<S::F, S::P>,
    pub digits: Values<S::F, S::P>,
    /// The aggregator's online input stage of the side's field, elements
    /// alone, in the order the fuse lays the stage out. Prepared with the
    /// proof's inputs; the step that proves the chunks sets the rest, the
    /// stage its fuse committed
    /// ([`with_online`](Self::with_online)).
    pub online_input: Values<S::F, S::P>,
    /// The online query stage, likewise: prepared with the evaluations the
    /// chunks read, as the native verifier computed them.
    pub online_query: Values<S::F, S::P>,
    pub aux: Aux<S::Other>,
    pub extra: Arc<S::Extra>,
}

impl<C: Cycle, S: Side<C>> Clone for Prepared<C, S> {
    fn clone(&self) -> Self {
        Prepared {
            schedule: self.schedule.clone(),
            instance: self.instance.clone(),
            messages: self.messages.clone(),
            lifts: self.lifts.clone(),
            work: self.work.clone(),
            transcript: self.transcript.clone(),
            digits: self.digits.clone(),
            online_input: self.online_input.clone(),
            online_query: self.online_query.clone(),
            aux: self.aux.clone(),
            extra: self.extra.clone(),
        }
    }
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
            PointSrc::Work(slot) => l.work.points[slot].clone(),
            PointSrc::Generator(i) => Point::constant(dr, self.generators[i])?,
            PointSrc::U => Point::constant(dr, self.u)?,
            PointSrc::FixedMultiple(source, multiple) => Point::constant(
                dr,
                (self.fixed_source(source) * S::Other::from(multiple)).to_affine(),
            )?,
            PointSrc::ScaleCorrection(source, multiple) => {
                let width = Digits::<'dr, D>::width::<S::Other>();
                let offset = derive::scale_offset(self.fixed_source(source), width);
                Point::constant(dr, (offset * S::Other::from(multiple)).to_affine())?.negate(dr)
            }
        })
    }

    fn element(&self, dr: &mut D, src: ElementSrc) -> Result<Element<'dr, D>> {
        let l = &self.loaded;
        Ok(match src {
            ElementSrc::Instance(i) => l.instance.elements[i].clone(),
            ElementSrc::Message(i) => l.messages.elements[i].clone(),
            ElementSrc::Work(slot) => l.work.elements[slot].clone(),
            ElementSrc::Lift(slot) => l.lifts.elements[slot].clone(),
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

    /// The lifts stage element at `slot`: a challenge's lift.
    pub(crate) fn lift(&self, slot: usize) -> Element<'dr, D> {
        self.loaded.lifts.elements[slot].clone()
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

    /// The other side's flag at `id` of the side's foreign flags.
    fn flag(&self, id: usize) -> DriverValue<D, bool> {
        self.witness.as_ref().map(|w| w.aux.flags[id])
    }

    /// A challenge's endoscalar: read off the squeezed element,
    /// constrained into range, or allocated from its bits and held, by
    /// its lift, to the challenge's lifts stage slot
    /// ([`Regions::bits_lifts`](super::program::Regions::bits_lifts)),
    /// which the other side's recomputation of that stage binds to the
    /// challenge it squeezed. The bits are the chunk's own witnesses, so
    /// every chunk that scales by a challenge from bits pays for the lift
    /// that holds them.
    fn endoscalar(&self, dr: &mut D, challenge: ChallengeRef) -> Result<Endoscalar<'dr, D>> {
        Ok(match challenge {
            ChallengeRef::Raw(slot) => Endoscalar::extract(EndoscalarChallenge::from_element(
                dr,
                &mut (),
                self.work(slot),
            )?),
            ChallengeRef::Bits(id) => {
                let endoscalar = self.bits(dr, id)?;
                let slot = self.schedule.regions.bits_lifts[id];
                endoscalar.lift(dr)?.enforce_equal(dr, &self.lift(slot))?;
                endoscalar
            }
        })
    }

    /// The endoscalar of the challenge at `id` of the side's challenge
    /// bits, allocated from them and held to nothing: what the lift chunk
    /// lifts into the lifts stage slot every other use holds its bits to.
    fn bits(&self, dr: &mut D, id: usize) -> Result<Endoscalar<'dr, D>> {
        let bits = self.witness.as_ref().map(|w| w.aux.challenge_bits[id]);
        Endoscalar::alloc(dr, bits)
    }

    /// A fixed point's value, for a scaling's offset.
    fn fixed(&self, src: PointSrc) -> S::P {
        match src {
            PointSrc::Generator(i) => self.generators[i],
            PointSrc::U => self.u,
            PointSrc::FixedMultiple(source, multiple) => {
                (self.fixed_source(source) * S::Other::from(multiple)).to_affine()
            }
            _ => panic!("an offset is a fixed point"),
        }
    }

    fn fixed_source(&self, src: FixedPointSrc) -> S::P {
        match src {
            FixedPointSrc::Generator(i) => self.generators[i],
            FixedPointSrc::U => self.u,
        }
    }

    /// The reduction's challenges from this side's lifts.
    fn revdot_challenges(&self) -> revdot::Challenges<'dr, D> {
        let lifts = &self.schedule.regions.lifts;
        revdot::Challenges {
            z: self.lift(lifts[squeezed::Z]),
            weights: Weights {
                mu: self.lift(lifts[squeezed::MU]),
                nu: self.lift(lifts[squeezed::NU]),
                mu_prime: self.lift(lifts[squeezed::MU_PRIME]),
                nu_prime: self.lift(lifts[squeezed::NU_PRIME]),
            },
            rho: self.lift(lifts[squeezed::RHO]),
            r: self.lift(lifts[squeezed::R]),
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
            #[cfg(test)]
            sigma: self.lift(regions.lifts[squeezed::SIGMA]),
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
                &self.lift(lifts[squeezed::W]),
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
                alpha: self.lift(lifts[squeezed::ALPHA]),
                u: self.lift(lifts[squeezed::U]),
                beta: self.lift(lifts[squeezed::BETA]),
            },
            &batch::Messages {
                evaluations: m.evaluations().to_vec(),
            },
        )?;
        let rounds: Vec<Element<'dr, D>> = lifts[squeezed::ROUNDS..]
            .iter()
            .map(|&slot| self.lift(slot))
            .collect();
        // The batch opens the host IPA helper at y. The other side binds
        // the helper's commitment to G' under the same flag.
        let step = self.schedule.layout.instance.step;
        if step.len != 0 {
            let elements = self.loaded.instance.elements;
            let flag = &elements[step.at(stages::step::FLAG)];
            let query = self.loaded.online_query.elements;
            let point = &query[super::online::QUERY_Y];
            let opening =
                &query[super::online::Values::value_at(super::online::Values::NATIVE.host_ipa())];
            let expected = ipa::s_at(dr, &rounds, point)?;
            let gap = opening.sub(dr, &expected);
            flag.mul(dr, &gap)?.enforce_zero(dr)?;
            // And the digest the step staged before its challenge is the
            // transcript's last squeeze: the round messages of both
            // curves' IPAs, and so both challenge polynomials, were fixed
            // before the point either is opened at.
            let digest = regions
                .digest
                .expect("the side whose instance carries a step binding squeezes the digest");
            let staged = &elements[step.at(stages::step::DIGEST)];
            let gap = staged.sub(dr, &self.work(digest));
            flag.mul(dr, &gap)?.enforce_zero(dr)?;
        }
        // The same for the nested curve's G', in every step: the
        // polynomial the step committed in its online Fq slot takes the
        // value of s(X) at the point the step's nested `compute_v` opened
        // it, so its commitment, which the other side holds its G' to, is
        // that of s(X).
        if let Some([x, y]) = regions.fq_opening {
            let expected = ipa::s_at(dr, &rounds, &self.work(x))?;
            self.work(y).enforce_equal(dr, &expected)?;
        }
        let scalars = ipa::verify(
            dr,
            &batched.point,
            &batched.value,
            &ipa::Challenges {
                xi: self.lift(lifts[squeezed::XI]),
                z: self.lift(lifts[squeezed::IPA_Z]),
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

/// The part of the other side's digits stage commitment over `digits`:
/// each digit's generator, `bind` names them, added or subtracted by its
/// bit, from the accumulator at `bind.init` or from nothing.
fn bind_sum<'dr, D, C, S>(
    dr: &mut D,
    ctx: &Ctx<'_, '_, 'dr, D, C, S>,
    digits: &Digits<'dr, D>,
    bind: &Bind,
) -> Result<Point<'dr, D, S::P>>
where
    D: Driver<'dr>,
    C: Cycle,
    S: Side<C, F = D::F>,
{
    assert_eq!(
        bind.generators.len(),
        digits.len(),
        "one generator per digit"
    );
    let mut acc = bind.init.map(|slot| ctx.loaded.work.points[slot].clone());
    NonzeroBank::scope(dr, |dr, bank| {
        for (bit, &generator) in digits.bits().iter().zip(&bind.generators) {
            let base = Point::constant(dr, ctx.generators[generator])?;
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
                // The lift chunk fills the slot every other use of a
                // challenge from bits holds its lift to, so it allocates
                // the bits alone and lets the write hold them.
                let endoscalar = match challenge {
                    ChallengeRef::Raw(_) => ctx.endoscalar(dr, challenge)?,
                    ChallengeRef::Bits(id) => ctx.bits(dr, id)?,
                };
                writes.push(Write::Lift(out, endoscalar.lift(dr)?));
            }
        }
        Chunk::Targets { out, .. } => {
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
            let sigma = ctx.lift(regions.lifts[squeezed::SIGMA]);
            let r = ctx.lift(regions.lifts[squeezed::R]);
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
        Chunk::Digits { scalars, flags } => {
            // Each scalar's digits, bound to it, as the signed digits
            // 2b - 1 the other side scales by, into the digits stage.
            for &(src, first) in scalars {
                let element = ctx.element(dr, src)?;
                let digits = Digits::alloc_bound(dr, &element)?;
                for (i, bit) in digits.bits().iter().enumerate() {
                    let digit = bit.element().scale(dr, Coeff::Two).add_coeff(
                        dr,
                        &Element::one(),
                        Coeff::NegativeOne,
                    );
                    writes.push(Write::Digit(first + i, digit));
                }
            }
            // A flag is zero or one where the side binds it, so 2f - 1 is
            // its signed digit.
            for &(src, slot) in flags {
                let digit = ctx.element(dr, src)?.scale(dr, Coeff::Two).add_coeff(
                    dr,
                    &Element::one(),
                    Coeff::NegativeOne,
                );
                writes.push(Write::Digit(slot, digit));
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
            bind,
        } => {
            let width = Digits::<'dr, D>::width::<S::Other>();
            let point = ctx.point(dr, *point)?;
            let ScalarRef::Bits(id) = *scalar;
            let digits = Digits::alloc_range(dr, ctx.foreign(id), *lo..*hi)?;
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
            // The same digits' part of the other side's digits stage
            // commitment, over the digits scaled by.
            if let Some(bind) = bind {
                writes.push(Write::Point(bind.out, bind_sum(dr, ctx, &digits, bind)?));
            }
        }
        Chunk::Sign { generator, out } => {
            // The verifier of a proof reads the base case off its circuit
            // id: a proof that took it is one of the bootstrap step.
            let bootstrap = crate::step::InternalStepIndex::Bootstrap
                .circuit_index::<crate::profile::Standard>()?;
            let bootstrap = Element::constant(dr, bootstrap.omega_j());
            let elements = ctx.loaded.instance.elements;
            let id = &elements[layout.instance.scalars.at(stages::native_scalars::OMEGA_J)];
            let base_case = id.is_equal(dr, &mut (), &bootstrap)?;
            let negate = base_case.not(dr);
            let point = Point::constant(dr, ctx.generators[*generator])?;
            writes.push(Write::Point(*out, point.conditional_negate(dr, &negate)?));
        }
        Chunk::Equal { left, right } => {
            let left = ctx.point(dr, *left)?;
            let right = ctx.point(dr, *right)?;
            left.enforce_equal(dr, &right)?;
        }
        Chunk::Online { values, inputs } => {
            for &(src, wire) in values {
                let wire = &ctx.loaded.online_query.elements[online::Values::value_at(wire)];
                ctx.element(dr, src)?.enforce_equal(dr, wire)?;
            }
            for &(src, index) in inputs {
                let wire = &ctx.loaded.online_input.elements[online::Values::input_at(index)];
                ctx.element(dr, src)?.enforce_equal(dr, wire)?;
            }
        }
        Chunk::EqualIf { flag, pairs, bind } => {
            // Bind the flag once to the digit sent by the other side, and
            // use the same bit for each point comparison.
            let bit = Boolean::alloc(dr, &mut (), ctx.flag(*flag))?;
            for &[left, right] in pairs {
                let mut left_coordinates = Vec::with_capacity(2);
                GadgetExt::write(&ctx.point(dr, left)?, dr, &mut left_coordinates)?;
                let mut right_coordinates = Vec::with_capacity(2);
                GadgetExt::write(&ctx.point(dr, right)?, dr, &mut right_coordinates)?;
                for (left, right) in left_coordinates.iter().zip(&right_coordinates) {
                    let gap = left.sub(dr, right);
                    bit.element().mul(dr, &gap)?.enforce_zero(dr)?;
                }
            }
            let digit = Digits::of_flag(bit);
            writes.push(Write::Point(bind.out, bind_sum(dr, ctx, &digit, bind)?));
        }
        Chunk::Curve { points } => {
            // The stages are loaded unenforced, so the curve equation a
            // point's allocation emits reaches no chunk circuit: re-emit it
            // here for every point the prover supplies, once per side.
            for &src in points {
                ctx.point(dr, src)?.enforce_consistent(dr)?;
            }
        }
    }
    Ok(writes)
}

/// Holds a chunk's writes to the work, lifts, transcript and digits
/// stages' wires.
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
            Write::Lift(slot, element) => {
                element.enforce_equal(dr, &loaded.lifts.elements[slot])?
            }
            Write::State(slot, element) => {
                element.enforce_equal(dr, &loaded.transcript.elements[slot])?
            }
            Write::Digit(slot, element) => {
                element.enforce_equal(dr, &loaded.digits.elements[slot])?
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/decompression/circuits.rs"]
mod tests;

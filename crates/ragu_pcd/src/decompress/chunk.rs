//! The chunk circuits: one circuit per run of chunks of a side's schedule
//! ([`Schedule::circuits`]), loading the side's stages and holding the
//! chunks' results to their wires.
//!
//! Every chunk circuit of a side has the same shape: the stages loaded
//! unenforced, as the fuse's endoscaling steps load theirs, then its
//! chunks' own gates, in order. A [`Circuit`] loads the instance, messages,
//! lifts and work stages; a [`TranscriptCircuit`], for transcript chunks
//! and the bridge sums, loads the transcript stage after them as well, so
//! that only those chunks pay for the bridges and the sponge states; a
//! [`DigitsCircuit`], for the digits chunks, loads the digits stage after
//! the work stage instead. Which chunks a circuit runs is fixed by its
//! index into the schedule, so the family of chunk circuits is as fixed as
//! the schedule, and the stages' masks bind the layout the chunks read.
//!
//! A chunk circuit at rank `R` verifies a compressed proof at rank `K`:
//! its schedule is cut for `R`'s gate budget, and what it loads and checks
//! is sized by `K`. An aggregator runs the chunks at
//! [`AggregatorRank`](ragu_circuits::polynomials::AggregatorRank) over
//! wallets' proofs at the production rank.
//!
//! Beside the chunks, a [`StatementCircuit`] loads the instance stage alone
//! and exposes the output header the chunks verified as its public output,
//! the one place the decompressed statement reaches a claim; and a
//! [`BindingCircuit`] loads the work stage and exposes the side's
//! recomputations of the other side's stage commitments
//! ([`Regions::exposed`](super::program::Regions::exposed)) as its public
//! output, which the proof's consumer holds to those commitments through
//! the circuit's claim (see [`Binding`](crate::profile::Binding)).

use alloc::sync::Arc;
use core::marker::PhantomData;

use ragu_circuits::{
    WithAux,
    polynomials::Rank,
    staging::{MultiStage, MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Cycle, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element, Point,
    vec::{ConstLen, FixedVec, Len},
};

use super::{
    program::{Last, Schedule},
    run::{self, Ctx, Loaded, Prepared, View},
    side::Side,
    stages::{DigitsStage, InstanceStage, LiftsStage, MessagesStage, TranscriptStage, WorkStage},
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
        for chunk in &self.schedule.chunks[plan.chunks.clone()] {
            let writes = run::execute::<_, C, S, K, HEADER_SIZE>(dr, chunk, &ctx)?;
            run::enforce(dr, loaded, writes)?;
        }
        Ok(())
    }
}

/// The stages every circuit of a side loads, loaded unenforced: the
/// instance, messages, lifts and work stages.
macro_rules! load_common {
    ($dr:ident, $witness:ident, $instance:ident, $messages:ident, $lifts:ident, $work:ident) => {
        let $instance = $instance.unenforced($dr, $witness.as_ref().map(|w| &w.instance))?;
        let $messages = $messages.unenforced($dr, $witness.as_ref().map(|w| &w.messages))?;
        let $lifts = $lifts.unenforced($dr, $witness.as_ref().map(|w| &w.lifts))?;
        let $work = $work.unenforced($dr, $witness.as_ref().map(|w| &w.work))?;
    };
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

        impl<'p, C: Cycle, S: Side<C>, K: Rank, R: Rank, const HEADER_SIZE: usize>
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

        impl<C: Cycle, S: Side<C>, K: Rank, R: Rank, const HEADER_SIZE: usize>
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
                let (instance, dr) = dr.add_stage::<InstanceStage<C, S, K, R, HEADER_SIZE>>()?;
                let (messages, dr) = dr.add_stage::<MessagesStage<C, S, K, R, HEADER_SIZE>>()?;
                let (lifts, dr) = dr.add_stage::<LiftsStage<C, S, K, R, HEADER_SIZE>>()?;
                let (work, dr) = dr.add_stage::<WorkStage<C, S, K, R, HEADER_SIZE>>()?;
                let ($extra, dr) = chunk_circuit!(@extra dr, $Last, $extra, C, S, K, R, HEADER_SIZE);
                let dr = dr.finish();
                load_common!(dr, witness, instance, messages, lifts, work);
                let $extra = chunk_circuit!(@load dr, witness, $extra, $extra);
                let $loaded = (instance, messages, lifts, work, $extra);
                let loaded = $view;
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
        let (instance, messages, lifts, work, ()) = &loaded;
        Loaded {
            instance: View::new(instance),
            messages: View::new(messages),
            lifts: View::new(lifts),
            work: View::new(work),
            transcript: View::empty(),
            digits: View::empty(),
        }
    }
);

chunk_circuit!(
    /// The chunk circuit at an index of side `S`'s schedule, for transcript
    /// chunks and the bridge sums: loads the transcript stage as well.
    TranscriptCircuit, Last::Transcript, TranscriptStage, transcript,
    |loaded| {
        let (instance, messages, lifts, work, transcript) = &loaded;
        Loaded {
            instance: View::new(instance),
            messages: View::new(messages),
            lifts: View::new(lifts),
            work: View::new(work),
            transcript: View::new(transcript),
            digits: View::empty(),
        }
    }
);

chunk_circuit!(
    /// The chunk circuit at an index of side `S`'s schedule, for digits
    /// chunks: loads the digits stage as well.
    DigitsCircuit, Last::Digits, DigitsStage, digits,
    |loaded| {
        let (instance, messages, lifts, work, digits) = &loaded;
        Loaded {
            instance: View::new(instance),
            messages: View::new(messages),
            lifts: View::new(lifts),
            work: View::new(work),
            transcript: View::empty(),
            digits: View::new(digits),
        }
    }
);

/// The statement circuit of side `S`: the circuit whose public output is
/// the output header of the compressed proof the chunks verified, read off
/// the instance stage. The chunks bind every value of that stage to the
/// proof they verify, so a claim on this circuit's output is a claim on the
/// decompressed proof's statement, which the decompression step's verifier
/// makes through the circuit's $k(y)$ (see
/// [`statement_ky`](crate::internal::native::stages::preamble::ProofInputs::statement_ky)).
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
    /// The output header the instance stage holds.
    type Instance<'source> = FixedVec<S::F, ConstLen<HEADER_SIZE>>;
    type Witness<'source> = &'source Prepared<C, S>;
    type Output = Kind![S::F; FixedVec<Element<'_, _>, ConstLen<HEADER_SIZE>>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = S::F>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        FixedVec::try_from_fn(|i| {
            Element::alloc(dr, &mut (), instance.as_ref().map(|header| header[i]))
        })
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = S::F>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        let (instance, dr) = dr.add_stage::<InstanceStage<C, S, K, R, HEADER_SIZE>>()?;
        let dr = dr.finish();
        let instance = instance.unenforced(dr, witness.as_ref().map(|w| &w.instance))?;
        let span = self.schedule.layout.instance.output_header;
        let header = span
            .positions()
            .map(|position| instance.elements[position].clone())
            .collect::<alloc::vec::Vec<_>>();
        Ok(WithAux::new(FixedVec::try_from(header)?, D::unit()))
    }
}

/// Length type for the points side `S`'s binding circuit exposes:
/// [`Side::EXPOSED`].
pub(crate) struct Exposed<C, S>(PhantomData<fn() -> (C, S)>);

impl<C: Cycle, S: Side<C>> Len for Exposed<C, S> {
    fn len() -> usize {
        S::EXPOSED
    }
}

/// The binding circuit of side `S`: the circuit whose public output is the
/// side's recomputations of the other side's stage commitments, read off
/// the work stage where the chunks left them
/// ([`Regions::exposed`](super::program::Regions::exposed)). The chunks
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

impl<C: Cycle, S: Side<C>, K: Rank, R: Rank, const HEADER_SIZE: usize>
    BindingCircuit<C, S, K, R, HEADER_SIZE>
{
    /// The binding circuit over `schedule`'s stages.
    pub(crate) fn new(schedule: Arc<Schedule>) -> MultiStage<S::F, R, Self> {
        assert_eq!(
            schedule.regions.exposed.len(),
            S::EXPOSED,
            "the schedule exposes the side's points"
        );
        MultiStage::new(BindingCircuit {
            schedule,
            _marker: PhantomData,
        })
    }
}

impl<C: Cycle, S: Side<C>, K: Rank, R: Rank, const HEADER_SIZE: usize> MultiStageCircuit<S::F, R>
    for BindingCircuit<C, S, K, R, HEADER_SIZE>
{
    type Last = WorkStage<C, S, K, R, HEADER_SIZE>;
    /// The exposed points.
    type Instance<'source> = FixedVec<S::P, Exposed<C, S>>;
    type Witness<'source> = &'source Prepared<C, S>;
    type Output = Kind![S::F; FixedVec<Point<'_, _, S::P>, Exposed<C, S>>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = S::F>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        FixedVec::try_from_fn(|i| Point::alloc(dr, instance.as_ref().map(|points| points[i])))
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = S::F>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        let (instance, dr) = dr.add_stage::<InstanceStage<C, S, K, R, HEADER_SIZE>>()?;
        let (messages, dr) = dr.add_stage::<MessagesStage<C, S, K, R, HEADER_SIZE>>()?;
        let (lifts, dr) = dr.add_stage::<LiftsStage<C, S, K, R, HEADER_SIZE>>()?;
        let (work, dr) = dr.add_stage::<WorkStage<C, S, K, R, HEADER_SIZE>>()?;
        let dr = dr.finish();
        load_common!(dr, witness, instance, messages, lifts, work);
        let _ = (instance, messages, lifts);
        let exposed = self
            .schedule
            .regions
            .exposed
            .iter()
            .map(|&slot| work.points[slot].clone())
            .collect::<alloc::vec::Vec<_>>();
        Ok(WithAux::new(FixedVec::try_from(exposed)?, D::unit()))
    }
}

#[cfg(test)]
#[path = "../../tests/decompress_chunk.rs"]
mod tests;

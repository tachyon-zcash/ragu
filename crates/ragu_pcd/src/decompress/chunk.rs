//! The chunk circuits: one circuit per [`Chunk`] of
//! a side's schedule, loading the side's stages and holding the chunk's
//! results to their wires.
//!
//! Every chunk circuit of a side has the same shape: the stages loaded
//! unenforced, as the fuse's endoscaling steps load theirs, then the
//! chunk's own gates. A [`Circuit`] loads the instance, messages and work
//! stages; a [`TranscriptCircuit`], for a transcript chunk, loads the
//! transcript stage after them as well, so that only the transcript chunks
//! pay for the bridges and the sponge states. Which chunk a circuit runs
//! is fixed by its index into the schedule, so the family of chunk
//! circuits is as fixed as the schedule, and the stages' masks bind the
//! layout the chunks read.
//!
//! A chunk circuit at rank `R` verifies a compressed proof at rank `K`:
//! its schedule is cut for `R`'s gate budget, and what it loads and checks
//! is sized by `K`. An aggregator runs the chunks at
//! [`AggregatorRank`](ragu_circuits::polynomials::AggregatorRank) over
//! wallets' proofs at the production rank.

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
    gadgets::Bound,
    maybe::Maybe,
};

use super::{
    program::{Chunk, Schedule},
    run::{self, Ctx, Loaded, Prepared, View},
    side::Side,
    stages::{InstanceStage, MessagesStage, TranscriptStage, WorkStage},
};

/// Whether the chunk at `index` of `schedule` is a transcript chunk, run
/// by a [`TranscriptCircuit`] rather than a [`Circuit`].
pub(crate) fn is_transcript(schedule: &Schedule, index: usize) -> bool {
    matches!(schedule.chunks[index], Chunk::Transcript { .. })
}

/// What both circuit types hold.
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
    fn new(index: usize, schedule: Arc<Schedule>, params: &'p C::Params) -> Self {
        assert!(
            index < schedule.chunks.len(),
            "chunk {index} is within the schedule's {}",
            schedule.chunks.len()
        );
        Inner {
            index,
            schedule,
            params,
        }
    }

    /// Runs the chunk over the loaded stages and holds its writes.
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
        let writes =
            run::execute::<_, C, S, K, HEADER_SIZE>(dr, &self.schedule.chunks[self.index], &ctx)?;
        run::enforce(dr, loaded, writes)
    }
}

/// The chunk circuit at an index of side `S`'s schedule, for a chunk
/// other than a transcript chunk.
pub(crate) struct Circuit<'p, C: Cycle, S, K, R, const HEADER_SIZE: usize> {
    inner: Inner<'p, C>,
    _marker: PhantomData<fn() -> (S, K, R)>,
}

impl<C: Cycle, S, K, R, const HEADER_SIZE: usize> Clone for Circuit<'_, C, S, K, R, HEADER_SIZE> {
    fn clone(&self) -> Self {
        Circuit {
            inner: self.inner.clone(),
            _marker: PhantomData,
        }
    }
}

impl<'p, C: Cycle, S: Side<C>, K: Rank, R: Rank, const HEADER_SIZE: usize>
    Circuit<'p, C, S, K, R, HEADER_SIZE>
{
    /// The circuit running chunk `index` of `schedule`.
    ///
    /// # Panics
    ///
    /// Panics if `index` is not a chunk of the schedule, or is a
    /// transcript chunk.
    pub(crate) fn new(
        index: usize,
        schedule: Arc<Schedule>,
        params: &'p C::Params,
    ) -> MultiStage<S::F, R, Self> {
        assert!(
            !is_transcript(&schedule, index),
            "chunk {index} is a transcript chunk"
        );
        MultiStage::new(Circuit {
            inner: Inner::new(index, schedule, params),
            _marker: PhantomData,
        })
    }
}

impl<C: Cycle, S: Side<C>, K: Rank, R: Rank, const HEADER_SIZE: usize> MultiStageCircuit<S::F, R>
    for Circuit<'_, C, S, K, R, HEADER_SIZE>
{
    type Last = WorkStage<C, S, K, R, HEADER_SIZE>;
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
        let (work, dr) = dr.add_stage::<WorkStage<C, S, K, R, HEADER_SIZE>>()?;
        let dr = dr.finish();

        let instance = instance.unenforced(dr, witness.as_ref().map(|w| &w.instance))?;
        let messages = messages.unenforced(dr, witness.as_ref().map(|w| &w.messages))?;
        let work = work.unenforced(dr, witness.as_ref().map(|w| &w.work))?;
        let loaded = Loaded {
            instance: View::new(&instance),
            messages: View::new(&messages),
            work: View::new(&work),
            transcript: View::empty(),
        };
        self.inner
            .synthesize::<_, S, K, HEADER_SIZE>(dr, loaded, witness)?;
        Ok(WithAux::new(S::output(dr), D::unit()))
    }
}

/// The chunk circuit at an index of side `S`'s schedule, for a transcript
/// chunk: loads the transcript stage as well.
pub(crate) struct TranscriptCircuit<'p, C: Cycle, S, K, R, const HEADER_SIZE: usize> {
    inner: Inner<'p, C>,
    _marker: PhantomData<fn() -> (S, K, R)>,
}

impl<C: Cycle, S, K, R, const HEADER_SIZE: usize> Clone
    for TranscriptCircuit<'_, C, S, K, R, HEADER_SIZE>
{
    fn clone(&self) -> Self {
        TranscriptCircuit {
            inner: self.inner.clone(),
            _marker: PhantomData,
        }
    }
}

impl<'p, C: Cycle, S: Side<C>, K: Rank, R: Rank, const HEADER_SIZE: usize>
    TranscriptCircuit<'p, C, S, K, R, HEADER_SIZE>
{
    /// The circuit running the transcript chunk `index` of `schedule`.
    ///
    /// # Panics
    ///
    /// Panics if `index` is not a transcript chunk of the schedule.
    pub(crate) fn new(
        index: usize,
        schedule: Arc<Schedule>,
        params: &'p C::Params,
    ) -> MultiStage<S::F, R, Self> {
        assert!(
            is_transcript(&schedule, index),
            "chunk {index} is not a transcript chunk"
        );
        MultiStage::new(TranscriptCircuit {
            inner: Inner::new(index, schedule, params),
            _marker: PhantomData,
        })
    }
}

impl<C: Cycle, S: Side<C>, K: Rank, R: Rank, const HEADER_SIZE: usize> MultiStageCircuit<S::F, R>
    for TranscriptCircuit<'_, C, S, K, R, HEADER_SIZE>
{
    type Last = TranscriptStage<C, S, K, R, HEADER_SIZE>;
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
        let (work, dr) = dr.add_stage::<WorkStage<C, S, K, R, HEADER_SIZE>>()?;
        let (transcript, dr) = dr.add_stage::<TranscriptStage<C, S, K, R, HEADER_SIZE>>()?;
        let dr = dr.finish();

        let instance = instance.unenforced(dr, witness.as_ref().map(|w| &w.instance))?;
        let messages = messages.unenforced(dr, witness.as_ref().map(|w| &w.messages))?;
        let work = work.unenforced(dr, witness.as_ref().map(|w| &w.work))?;
        let transcript = transcript.unenforced(dr, witness.as_ref().map(|w| &w.transcript))?;
        let loaded = Loaded {
            instance: View::new(&instance),
            messages: View::new(&messages),
            work: View::new(&work),
            transcript: View::new(&transcript),
        };
        self.inner
            .synthesize::<_, S, K, HEADER_SIZE>(dr, loaded, witness)?;
        Ok(WithAux::new(S::output(dr), D::unit()))
    }
}

#[cfg(test)]
#[path = "../../tests/decompress_chunk.rs"]
mod tests;

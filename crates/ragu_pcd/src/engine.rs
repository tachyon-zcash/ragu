use ragu_circuits::polynomials::Rank;
use ragu_core::Error;

use crate::{accumulator::Accumulator, cycle::CurveCycle, prover::AccumulationProver};

/// Engine that drives cycling between pasta curves.
///
/// TODO: https://github.com/ebfull/ragu/issues/17.
pub struct CurveCycleEngine<C, R>
where
    C: CurveCycle,
    R: Rank,
{
    /// Prover for primary curve (C).
    primary_prover: AccumulationProver<C, R>,
    /// Prover for the paired curve (C::Pair).
    paired_prover: AccumulationProver<C::Pair, R>,
}

impl<C: CurveCycle, R: Rank> CurveCycleEngine<C, R> {
    /// Create a curve cycle engine from pre-configured provers.
    pub fn from_provers(
        primary_prover: AccumulationProver<C, R>,
        paired_prover: AccumulationProver<C::Pair, R>,
    ) -> Self {
        Self {
            primary_prover,
            paired_prover,
        }
    }

    /// Get a reference to the primary curve prover.
    pub fn primary_prover(&self) -> &AccumulationProver<C, R> {
        &self.primary_prover
    }

    /// Get a reference to the paired curve prover.
    pub fn paired_prover(&self) -> &AccumulationProver<C::Pair, R> {
        &self.paired_prover
    }

    /// Initialize a new curve cycle engine.
    pub fn new() -> Self {
        Self {
            primary_prover: AccumulationProver::new(),
            paired_prover: AccumulationProver::new(),
        }
    }

    /// Execute one PCD step with curve cycling.
    ///
    /// RecursionSession::step (higher-level) calls into this lower-level step function.
    /// The engine determines which prover to use based on step count (alternates curves).
    pub fn step(
        &mut self,
        prev: Accumulator<C, R>,
        circuit_tag: &str,
        witness: &[C::ScalarExt],
        step_number: usize,
    ) -> Result<Accumulator<C, R>, Error> {
        if step_number % 2 == 0 {
            self.step_on_primary(prev, circuit_tag, witness)
        } else {
            self.step_on_paired(prev, circuit_tag, witness)
        }
    }

    /// Prove on the primary curve (C) – Pallas.
    pub fn step_on_primary(
        &mut self,
        _prev: Accumulator<C, R>,
        _circuit_tag: &str,
        _witness: &[C::ScalarExt],
    ) -> Result<Accumulator<C, R>, Error> {
        // TODO: Call `step()` on the primary_prover.
        todo!()
    }

    /// Prove on the paired curve (C::Paired) – Vesta.
    pub fn step_on_paired(
        &mut self,
        _prev: Accumulator<C, R>,
        _circuit_tag: &str,
        _witness: &[C::ScalarExt],
    ) -> Result<Accumulator<C, R>, Error> {
        // TODO: Call `step()` on the paired_prover.
        todo!()
    }
}

impl<C: CurveCycle, R: Rank> Default for CurveCycleEngine<C, R> {
    fn default() -> Self {
        Self::new()
    }
}

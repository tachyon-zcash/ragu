//! Mid-Level: Orchestration layer that concerns itself with knowing about both curves,
//! pattern matches on the curve, and routes to the correct prover in thd cycle.

use ragu_circuits::polynomials::Rank;
use ragu_core::Error;

use crate::{
    accumulator::Accumulator,
    cycle::{CurveCycle, CycleState},
    prover::AccumulationProver,
};

/// Routing engine that drives cycling between pasta curves.
///
/// TODO: https://github.com/ebfull/ragu/issues/17.
pub struct CurveCycleEngine<C, R>
where
    C: CurveCycle,
    R: Rank,
{
    /// Prover for `Pallas` primary curve (C).
    primary_prover: AccumulationProver<C, R>,

    /// Prover for the `Vesta` paired curve (C::Pair).
    paired_prover: AccumulationProver<C::Pair, R>,

    /// Current state in the cycle.
    state: CycleState<C, R>,

    /// Depth of the recursion in the session.
    depth: usize,
}

impl<C: CurveCycle, R: Rank> CurveCycleEngine<C, R> {
    /// Create a curve cycle engine from pre-configured provers.
    pub fn from_provers(
        primary_prover: AccumulationProver<C, R>,
        paired_prover: AccumulationProver<C::Pair, R>,
        state: CycleState<C, R>,
        depth: usize,
    ) -> Self {
        Self {
            primary_prover,
            paired_prover,
            state,
            depth,
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
            state: CycleState::OnPaired {
                primary: Accumulator::base(),
                paired: Accumulator::base(),
            },
            depth: 0usize,
        }
    }

    /// Execute one PCD step, alternating between curves.
    pub fn step(&mut self, circuit_tag: &str, witness: &[C::ScalarExt]) -> Result<(), Error> {
        self.state = match std::mem::replace(&mut self.state, unsafe { std::mem::zeroed() }) {
            CycleState::OnPrimary { primary, paired } => {
                // Prove on primary, verifying paired.
                let new_primary = self.primary_prover.step(primary, circuit_tag, witness)?;

                CycleState::OnPaired {
                    primary: Accumulator::Uncompressed(Box::new(new_primary)),
                    paired,
                }
            }
            CycleState::OnPaired { primary, paired } => {
                // Prove on paired, verifying primary.
                let new_paired = self.paired_prover.step(paired, circuit_tag, &[])?;

                CycleState::OnPrimary {
                    primary,
                    paired: Accumulator::Uncompressed(Box::new(new_paired)),
                }
            }
        };

        self.depth += 1;

        Ok(())
    }
}

impl<C: CurveCycle, R: Rank> Default for CurveCycleEngine<C, R> {
    fn default() -> Self {
        Self::new()
    }
}

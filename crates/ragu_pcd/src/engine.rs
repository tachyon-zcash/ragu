use ragu_circuits::polynomials::Rank;

use crate::{cycle::CurveCycle, prover::AccumulationProver};

/// Engine that drives cycling between pasta curves.
///
/// TODO: https://github.com/ebfull/ragu/issues/17.
pub struct CurveCycleEngine<C, R>
where
    C: CurveCycle,
    R: Rank,
{
    /// Prover for primary curve.
    prover_c1: AccumulationProver<C, R>,
    /// Prover for the paired curve.
    prover_c2: AccumulationProver<C::Pair, R>,
}

impl<C: CurveCycle, R: Rank> CurveCycleEngine<C, R> {
    /// Create a curve cycle engine from pre-configured provers.
    pub fn from_provers(
        prover_c1: AccumulationProver<C, R>,
        prover_c2: AccumulationProver<C::Pair, R>,
    ) -> Self {
        Self {
            prover_c1,
            prover_c2,
        }
    }

    /// Get a reference to the primary curve prover.
    pub fn prover_c1(&self) -> &AccumulationProver<C, R> {
        &self.prover_c1
    }

    /// Get a reference to the paired curve prover.
    pub fn prover_c2(&self) -> &AccumulationProver<C::Pair, R> {
        &self.prover_c2
    }

    /// Initialize a new curve cycle engine.
    pub fn new() -> Self {
        Self {
            prover_c1: AccumulationProver::new(),
            prover_c2: AccumulationProver::new(),
        }
    }
}

impl<C: CurveCycle, R: Rank> Default for CurveCycleEngine<C, R> {
    fn default() -> Self {
        Self::new()
    }
}

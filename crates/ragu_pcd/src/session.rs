//! User-facing API
//!
//! The API we're exposing should ideally remain agnostic with respect to the underlying curve
//! choice, allowing the user to choose either Pallas or Vesta as the application curve.
//! Conceptually, the 'RecursionSession' serves as the main user-facing entry point (builder interface)
//! encapsulating the `CurveCycleEngine` that drives the accumulation logic under the hood.
//!
//! This design abstracts away the underlying complex machinery, which users shouldn't need to concern
//! themselves with. Some of these lower-level primitives are accumulators, dummy proofs, curve cycles, mesh
//! management, etc.

use crate::accumulator::Accumulator;
use crate::cycle::{CurveCycle, CycleState};
use crate::engine::CurveCycleEngine;
use crate::prover::AccumulationProver;
use ragu_circuits::Circuit;
use ragu_circuits::polynomials::Rank;
use ragu_core::Error;

/// A stateful session for building recursive proofs in a PCD chain.
///
/// The session maintains an accumulator for chaining proofs, staying
/// in uncompressed form for efficient composition. When finished,
/// the session can be finalized to produce a compressed proof and
/// associated decision procedure to check the veracity of the
/// accumulation.
#[allow(dead_code)]
pub struct RecursionSession<C, R>
where
    C: CurveCycle,
    R: Rank,
    // TODO: append 'CombinationRules' field (https://github.com/tachyon-zcash/ragu/issues/5)
{
    /// `CurveCycleEngine` is the orchestrator, a lower-level abstraction that handles
    /// the underlying PCD curve cycling between the primary and paired provers
    /// operating over the Pallas and Vesta curves.
    engine: CurveCycleEngine<C, R>,

    /// Handle to the accumulator.
    accumulator: Option<Accumulator<C, R>>,

    /// Track the number of recursive steps.
    depth: usize,
}

impl<C, R> RecursionSession<C, R>
where
    C: CurveCycle,
    R: Rank,
{
    /// Create a new recursion session.
    ///
    /// The paired curve is automatically determined from `C`.
    /// If `C = Pallas`, then `C::Pair = Vesta` automatically.
    pub fn new() -> Result<Self, Error> {
        // Create accumulation provers.
        let primary_prover: AccumulationProver<C, R> = AccumulationProver::new();
        let paired_prover = AccumulationProver::new();
        let state = CycleState::OnPaired {
            primary: Accumulator::base(),
            paired: Accumulator::base(),
        };
        let depth = 0usize;

        // Create curve cycling engine.
        let engine = CurveCycleEngine::from_provers(primary_prover, paired_prover, state, depth);

        Ok(Self {
            engine,
            accumulator: Some(Accumulator::base()),
            depth: 0,
        })
    }

    /// Circuit registration.
    pub fn circuit_registration<Circ>(
        &mut self,
        _tag: impl Into<String>,
        _circuit: Circ,
    ) -> Result<(), Error>
    where
        Circ: Circuit<C::ScalarExt> + Send + 'static,
    {
        // TODO: Delegates call to engine to register circuits on both meshes.
        todo!()
    }

    /// PCD step.
    pub fn step(&mut self, _circuit_tag: &str, _witness: &[C::Scalar]) -> Result<(), Error> {
        // TODO: Delegates call to engine to perform an accumulation step.
        todo!()
    }

    /// Perform the decision procedure to determine if accumulation is valid.
    pub fn decision(&self) -> bool {
        // TODO: Delegates call to engine to perform an decision procedure.
        todo!()
    }

    /// Compress an accumulator from uncompressed to compressed form.
    pub fn compress(accumulator: Accumulator<C, R>) -> Result<Accumulator<C, R>, Error> {
        // TODO: Delegate to engine to perform an accumulator compression.
        match accumulator {
            Accumulator::Uncompressed(_uncompressed) => {
                todo!()
            }
            Accumulator::Compressed(compressed) => Ok(Accumulator::Compressed(compressed)),
        }
    }

    /// Depth of recursion.
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Check if this session is at the base.
    pub fn is_base(&self) -> bool {
        self.depth == 0
    }

    /// Query statistics about the current session.
    pub fn statistics(&self) {
        todo!()
    }

    /// Checkpoint the current state.
    pub fn checkpoint(&self) {
        todo!()
    }

    /// Restore the checkpointed state.
    pub fn restore(&self) {
        todo!()
    }
}

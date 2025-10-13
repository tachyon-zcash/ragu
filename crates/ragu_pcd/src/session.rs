//! High-Level: User-facing API
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
use crate::engine::{CycleEngine, CycleState};
use crate::prover::AccumulationProver;
use arithmetic::Cycle;
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
    C: Cycle,
    R: Rank,
    // TODO: append 'CombinationRules' field (https://github.com/tachyon-zcash/ragu/issues/5)
{
    /// `CurveCycleEngine` is the orchestrator, a lower-level abstraction that handles
    /// the underlying PCD curve cycling between the primary and paired provers
    /// operating over the Pallas and Vesta curves.
    engine: CycleEngine<C, R>,

    /// Track the number of recursive steps.
    depth: usize,
}

impl<C, R> RecursionSession<C, R>
where
    C: Cycle,
    R: Rank,
{
    /// Create a new recursion session for the given cycle with meshes
    /// supporting up to 2^log2_circuits circuits.
    pub fn new(log2_circuits: u32) -> Result<Self, Error> {
        // Create accumulation provers.
        let nested_prover: AccumulationProver<C::NestedCurve, R> =
            AccumulationProver::new(log2_circuits);
        let host_prover: AccumulationProver<C::HostCurve, R> =
            AccumulationProver::new(log2_circuits);
        let state = CycleState::Host {
            nested: Accumulator::base(),
            host: Accumulator::base(),
        };
        let depth = 0;

        // Create curve cycling engine.
        let engine = CycleEngine::from_provers(nested_prover, host_prover, state, depth);

        Ok(Self { engine, depth })
    }

    /// Register a circuit that operates over the circuit field.
    pub fn register_circuit<Circ>(&mut self, circuit: Circ) -> Result<(), Error>
    where
        Circ: Circuit<C::CircuitField> + Send + 'static,
    {
        self.engine.register_circuit(circuit)?;

        Ok(())
    }

    /// PCD step with supplied witnesses.
    pub fn step(&mut self, witnesses: &[Vec<C::CircuitField>]) -> Result<(), Error> {
        self.engine.step(witnesses)?;
        self.depth += 1;

        Ok(())
    }

    /// Perform the decision procedure to determine if accumulation is valid.
    pub fn decision(&self) -> bool {
        // TODO: Delegates call to engine to perform an decision procedure.
        todo!()
    }

    /// Get the current recursion depth.
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

//! The API we’re exposing should ideally remain agnostic with respect to the underlying curve
//! choice, allowing the user to choose either Pallas or Vesta as the application curve.
//! Conceptually, the 'RecursionSession' serves the user-facing interface (builder interface)
//! encapsulating the `CurveCycleEngine` that drives the accumulation logic the hood.
//!
//! This abstracts away the underlying complex machinery which the user shouldn't need to concern
//! themselves with:
//! * Accumulators
//! * Dummy proofs
//! * Curve cycle
//! * Accumulation internals
//! * Mesh management

use crate::accumulator::Accumulator;
use crate::cycle::CurveCycle;
use crate::engine::CurveCycleEngine;
use crate::prover::AccumulationProver;
use ragu_circuits::Circuit;
use ragu_circuits::polynomials::Rank;
use ragu_core::Error;

/// A stateful session for building recursive proofs in a PCD chain.
///
/// The session maintains an accumulator for chaining proofs, staying
/// in uncompressed form for efficient composition. When finished,
/// the session can be finalized to produce a compressed proof.
#[allow(dead_code)]
pub struct RecursionSession<C, R>
where
    C: CurveCycle,
    R: Rank,
    // TODO: append 'CombinationRules' field (https://github.com/tachyon-zcash/ragu/issues/5)
{
    /// Lower-level abstraction handling the underlying PCD curve cycling.
    /// The `CurveCycleEngine` is the orchestrator.
    engine: CurveCycleEngine<C, R>,
    /// Opaque handle that hides curve alternation details. TODO: fix type.
    accumulator: Option<Accumulator<C, R>>,
    /// Track the number of recursive steps.
    depth: usize,
}

/// TODO: Query statistics about the current session.
/// TODO: Support for checkpointing the current state, and restoring the state.
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
        let prover_c1 = AccumulationProver::new();
        let prover_c2 = AccumulationProver::new();

        // Create curve cycling engine.
        let engine = CurveCycleEngine::from_provers(prover_c1, prover_c2);

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
        // TODO: Delegate to engine to register circuits on both meshes.
        todo!()
    }

    pub fn step(&mut self, _circuit_tag: &str, _witness: &[C::Scalar]) -> Result<(), Error> {
        // TODO: Delegate to engine to perform an accumulation step.
        todo!()
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn is_base(&self) -> bool {
        self.depth == 0
    }
}

//! High-Level: User-facing API
//!
//! The API we're exposing should ideally remain agnostic with respect to the underlying curve cycle.
//! Conceptually, the 'RecursionSession' serves as the main user-facing entry point (builder interface)
//! encapsulating the underlying `CycleEngine` that drives the recursion under the hood.
//!
//! This design abstracts away the underlying complex machinery, which users shouldn't need to concern
//! themselves with. Some of these lower-level primitives are accumulators, dummy proofs, curve cycles, mesh
//! management, etc.

use crate::engine::CycleEngine;
use arithmetic::Cycle;
use ragu_circuits::Circuit;
use ragu_circuits::polynomials::Rank;
use ragu_core::Error;
use ragu_pasta::Fp;

/// A stateful session for building recursive proofs in a PCD chain.
///
/// The session maintains an engine that orchestrates the curve cycle.
pub struct RecursionSession<'a, C, R>
where
    C: Cycle,
    R: Rank,
{
    /// `CycleEngine` is the curve orchestrator.
    engine: CycleEngine<'a, C, R>,
}

impl<'a, C, R> RecursionSession<'a, C, R>
where
    C: Cycle + Default,
    R: Rank,
{
    /// Create a new recursion session for the given cycle with meshes.
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            engine: CycleEngine::new(),
        })
    }

    /// Register an application circuit that operates over the circuit field.
    ///
    /// Circuits are registered before the first `step()` invocation, and
    /// circuit registration is closed once execution begins.
    pub fn register_circuit<Circ>(&mut self, circuit: Circ) -> Result<(), Error>
    where
        Circ: Circuit<C::CircuitField> + Send + 'static,
    {
        self.engine.register_circuit(circuit)?;

        Ok(())
    }

    /// Execute one PCD step with the provided witnesses.
    ///
    /// Mesh finalization automatically happens on the first call.
    pub fn step(&'a mut self, application_witnesses: &Vec<C::CircuitField>) -> Result<(), Error>
    where
        C: Cycle<CircuitField = Fp>,
    {
        if application_witnesses.is_empty() {
            return Err(Error::InvalidWitness("witnesses cannot be empty".into()));
        }

        self.engine.step(application_witnesses)?;

        Ok(())
    }

    /// Perform the decision procedure to determine if accumulation is valid.
    pub fn decision(&self) -> bool {
        todo!()
    }
}

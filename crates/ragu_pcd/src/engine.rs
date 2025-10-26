//! Cycle engine orchestration layer for simultaneous CycleFold-style accumulation
//! that directly manages meshes, generators, and the curve states.
//!
//! The Pallas and Vesta curves are tightly-cuppled: steps happen at the exact
//! same time on both curves, they share the same transcript over Fp, and only
//! perform native arithmetic.

use crate::accumulator::CycleAccumulator;
use arithmetic::Cycle;
use ragu_circuits::{
    Circuit,
    mesh::{Mesh, MeshBuilder},
    polynomials::Rank,
};
use ragu_core::Error;

/// CycleFold-style simultaneous state.
pub struct CycleState<C, R>
where
    C: Cycle,
    R: Rank,
{
    pub pallas_accumulator: CycleAccumulator<C::NestedCurve, C::HostCurve, R>,
    pub vesta_accumulator: CycleAccumulator<C::HostCurve, C::NestedCurve, R>,
    // TODO: Append single unified transcript over Fp.
}

enum EngineState<'a, C: Cycle, R: Rank> {
    Building {
        pallas_builder: MeshBuilder<'a, C::ScalarField, R>,
        vesta_builder: MeshBuilder<'a, C::CircuitField, R>,
    },
    Finalized {
        /// Meshes for both curves.
        pallas_mesh: Mesh<'a, C::ScalarField, R>,
        vesta_mesh: Mesh<'a, C::CircuitField, R>,

        /// Current cycle state for the accumulators.
        state: CycleState<C, R>,
    },
}

/// Single unified prover operating on both curves simultaneously.
pub struct CycleEngine<'a, C, R>
where
    C: Cycle,
    R: Rank,
{
    /// Cycle that provides generators.
    cycle: C,

    /// Engine state for meshes and accumulators.
    engine_state: EngineState<'a, C, R>,

    /// Depth of the recursion in the session.
    depth: usize,
}

impl<'a, C: Cycle + Default, R: Rank> CycleEngine<'a, C, R> {
    /// Initialize a new curve cycle engine.
    pub fn new() -> Self {
        Self {
            cycle: C::default(),
            engine_state: EngineState::Building {
                pallas_builder: MeshBuilder::<C::ScalarField, R>::new(),
                vesta_builder: MeshBuilder::<C::CircuitField, R>::new(),
            },
            depth: 0,
        }
    }

    /// Register an application circuit on the host prover's mesh.
    pub fn register_circuit<Circ>(&mut self, circuit: Circ) -> Result<(), Error>
    where
        Circ: Circuit<C::CircuitField> + 'static,
    {
        // TODO: have been wondering where r(X) generation fits relative to mesh registration.
        // The current construction seems to imply a strict dependency where it has to occur before
        // registration, since registration in some sense is “lossy” and the circuit gets type-erased,
        // so you can’t call ::rx() on the stored `CircuitObject`.
        //
        // After the circuit gets registered, it's a `CircuitObject` that's type-erased,
        // so we can't generate the witness polynomial for it, r(X). Maybe, we should store
        // the raw circuit *for now* so we can generate the witness, but there should
        // be a good way to do this. Additionally, we've discussed probably needing to commit
        // to the mesh before starting the accumulation procedure. Intuitively this makes sense
        // for binding purposes where the mesh can't be changed later, but we should delineate
        // the explicit safety properties for doing this.

        let dummy = EngineState::Building {
            pallas_builder: MeshBuilder::<'static, C::ScalarField, R>::new(),
            vesta_builder: MeshBuilder::<'static, C::CircuitField, R>::new(),
        };

        self.engine_state = match std::mem::replace(&mut self.engine_state, dummy) {
            EngineState::Building {
                pallas_builder,
                vesta_builder,
            } => EngineState::Building {
                pallas_builder,
                vesta_builder: vesta_builder.register_circuit(circuit)?,
            },
            EngineState::Finalized { .. } => {
                return Err(Error::InvalidWitness(
                    "cannot register circuits after finalization".into(),
                ));
            }
        };

        Ok(())
    }

    /// Execute one PCD step on both curves simultaneously.
    ///
    /// This advances both the Vesta (host) and Pallas (nested) accumulators.
    pub fn step(
        &mut self,
        // Application circuit witnesses.
        application_witnesses: &Vec<C::CircuitField>,
    ) -> Result<(), Error> {
        // Finalize the mesh on first step invocation.
        if matches!(self.engine_state, EngineState::Building { .. }) {
            self.finalize_internal()?;
        }

        if let EngineState::Finalized {
            pallas_mesh,
            vesta_mesh,
            state,
        } = &mut self.engine_state
        {
            // Handoff: each side's deferred becomes the other's endoscalars.
            let vesta_deferred = std::mem::take(&mut state.vesta_accumulator.deferreds);
            state.pallas_accumulator.endoscalars = vesta_deferred;

            let pallas_deferred = std::mem::take(&mut state.pallas_accumulator.deferreds);
            state.vesta_accumulator.endoscalars = pallas_deferred;

            // Execute both sides of the curve cycle simulatenously.
            // TODO: add rayon::join() for parallel processing.
            Self::step_pallas_side(pallas_mesh, &[], &mut state.pallas_accumulator, &self.cycle)?;
            Self::step_vesta_side(
                vesta_mesh,
                application_witnesses,
                &mut state.vesta_accumulator,
                &self.cycle,
            )?;
        }

        Ok(())
    }

    /// Executes the Pallas-side accumulation step.
    ///
    /// This is the Fq round — computations are done over Fq, and commitments
    /// are made on the Pallas host curve.
    pub fn step_pallas_side(
        mesh: &Mesh<'_, C::ScalarField, R>,
        witnesses: &[C::ScalarField],
        accumulator: &mut CycleAccumulator<C::NestedCurve, C::HostCurve, R>,
        cycle: &C,
    ) -> Result<(), Error> {
        todo!()
    }

    /// Executes the Vesta-side accumulation step.
    ///
    /// This is an Fp round: computations occur over Fp, and commitments
    /// are made on the Vesta host curve.
    pub fn step_vesta_side(
        mesh: &Mesh<'_, C::CircuitField, R>,
        witnesses: &[C::CircuitField],
        accumulator: &mut CycleAccumulator<<C as Cycle>::HostCurve, <C as Cycle>::NestedCurve, R>,
        cycle: &C,
    ) -> Result<(), Error> {
        todo!()
    }

    /// Finalize the mesh builders and initialize base accumulators.
    ///
    /// This transitions the engine from the 'Building' state to the 'Finalized'
    /// state, creating the finalized mesh structures and seeding the accumulators.
    pub fn finalize_internal(&mut self) -> Result<(), Error> {
        let dummy = EngineState::Building {
            pallas_builder: MeshBuilder::<C::ScalarField, R>::new(),
            vesta_builder: MeshBuilder::<C::CircuitField, R>::new(),
        };

        match std::mem::replace(&mut self.engine_state, dummy) {
            EngineState::Building {
                pallas_builder,
                vesta_builder,
            } => {
                // Finalize the mesh builders.
                let pallas_mesh = pallas_builder.finalize().expect("pallas mesh");
                let vesta_mesh = vesta_builder.finalize().expect("vesta mesh");

                // Retrieve generators for both curves in the cycle.
                let nested_generators = self.cycle.nested_generators();
                let host_generators = self.cycle.host_generators();

                // Initialize base CycleAccumulators for both curves
                let pallas_accumulator = CycleAccumulator::base(&pallas_mesh, nested_generators);
                let vesta_accumulator = CycleAccumulator::base(&vesta_mesh, host_generators);

                // Intialize cycle state.
                let state = CycleState {
                    pallas_accumulator,
                    vesta_accumulator,
                };

                // Transition to a finalized 'Mesh' stat that can be used.
                self.engine_state = EngineState::Finalized {
                    pallas_mesh,
                    vesta_mesh,
                    state,
                };

                Ok(())
            }
            EngineState::Finalized {
                pallas_mesh,
                vesta_mesh,
                state,
            } => {
                // Already finalized, restore state and return error.
                self.engine_state = EngineState::Finalized {
                    pallas_mesh,
                    vesta_mesh,
                    state,
                };

                Err(Error::MeshAlreadyFinalized)
            }
        }
    }
}

impl<'a, C: Cycle + Default, R: Rank> Default for CycleEngine<'a, C, R> {
    fn default() -> Self {
        Self::new()
    }
}

//! Cycle engine orchestration layer for simultaneous CycleFold-style accumulation
//! that directly manages meshes, generators, and the curve states.
//!
//! The Pallas and Vesta curves are tightly-cuppled: steps happen at the exact
//! same time on both curves, they share the same transcript over Fp, and only
//! perform native arithmetic.

use arithmetic::Cycle;
use ragu_circuits::{
    Circuit,
    mesh::{Mesh, MeshBuilder},
    polynomials::Rank,
};
use ragu_core::Error;

use crate::accumulator::UncompressedAccumulator;

/// CycleFold-style simultaneous state.
pub struct CycleState<C, R>
where
    C: Cycle,
    R: Rank,
{
    pub pallas_accumulator: UncompressedAccumulator<C::NestedCurve, R>,
    pub vesta_accumulator: UncompressedAccumulator<C::HostCurve, R>,
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
        Circ: Circuit<C::CircuitField> + Send + 'static,
    {
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
    pub fn step(&'a mut self, witnesses: &[Vec<C::CircuitField>]) -> Result<(), Error> {
        // Finalize the mesh on first step invocation.
        if matches!(self.engine_state, EngineState::Building { .. }) {
            self.finalize_internal()?;
        }

        // TODO: Accumulation logic branches from here.

        Ok(())
    }

    /// Finalize the mesh builders and initialize base accumulators.
    ///
    /// This transitions the engine from the 'Building' state to the 'Finalized'
    /// state, creating the finalized mesh structures and seeding the accumulators.
    pub fn finalize_internal(&'a mut self) -> Result<(), Error> {
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

                // Initialize base accumulators for both curves in the cycle.
                let pallas_accumulator =
                    UncompressedAccumulator::base(&pallas_mesh, nested_generators);
                let vesta_accumulator = UncompressedAccumulator::base(&vesta_mesh, host_generators);

                // Intialize cycle state.
                let state = CycleState {
                    pallas_accumulator,
                    vesta_accumulator,
                };

                // Transition to a finalized state.
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

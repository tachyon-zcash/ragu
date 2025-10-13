//! Mid-Level: Orchestration layer that concerns itself with knowing about both curves,
//! pattern matches on the curve, and routes to the correct prover in the cycle.

use arithmetic::Cycle;
use ragu_circuits::{Circuit, polynomials::Rank};
use ragu_core::Error;

use crate::{accumulator::Accumulator, prover::AccumulationProver};

/// Represents which curve is currently active in the PCD cycle.
pub enum CycleState<C, R>
where
    C: Cycle,
    R: Rank,
{
    /// Nested curve (Pallas).
    Nested {
        nested: Accumulator<C::NestedCurve, R>,
        host: Accumulator<C::HostCurve, R>,
    },
    /// Host curve (Vesta).
    Host {
        nested: Accumulator<C::NestedCurve, R>,
        host: Accumulator<C::HostCurve, R>,
    },
}

/// Routing engine that manages cycling between the Pasta curves.
/// The engine maintains provers and accumulators for both the nested
/// curve and the host curve.
pub struct CycleEngine<C, R>
where
    C: Cycle,
    R: Rank,
{
    /// Prover for `Pallas` primary curve (C).
    nested_prover: AccumulationProver<C::NestedCurve, R>,

    /// Prover for the `Vesta` paired curve (C::Pair).
    host_prover: AccumulationProver<C::HostCurve, R>,

    /// Current state in the cycle.
    state: CycleState<C, R>,

    /// Depth of the recursion in the session.
    depth: usize,
}

impl<C: Cycle, R: Rank> CycleEngine<C, R> {
    /// Create a curve cycle engine from pre-configured provers.
    pub fn from_provers(
        nested_prover: AccumulationProver<C::NestedCurve, R>,
        host_prover: AccumulationProver<C::HostCurve, R>,
        state: CycleState<C, R>,
        depth: usize,
    ) -> Self {
        Self {
            nested_prover,
            host_prover,
            state,
            depth,
        }
    }

    /// Get a reference to the primary curve prover.
    pub fn nested_prover(&self) -> &AccumulationProver<C::NestedCurve, R> {
        &self.nested_prover
    }

    /// Get a reference to the paired curve prover.
    pub fn host_prover(&self) -> &AccumulationProver<C::HostCurve, R> {
        &self.host_prover
    }

    /// Initialize a new curve cycle engine.
    pub fn new(log2_circuits: u32) -> Self {
        Self {
            nested_prover: AccumulationProver::new(log2_circuits),
            host_prover: AccumulationProver::new(log2_circuits),
            state: CycleState::Host {
                nested: Accumulator::base(),
                host: Accumulator::base(),
            },
            depth: 0,
        }
    }

    /// Register an application circuit on the host prover's mesh.
    pub fn register_circuit<Circ>(&mut self, circuit: Circ) -> Result<(), Error>
    where
        Circ: Circuit<C::CircuitField> + Send + 'static,
    {
        self.host_prover.register_circuit(circuit)?;

        Ok(())
    }

    /// Execute one PCD step, alternating between curves.
    ///
    /// Each step proves execution of all application circuits in the mesh
    /// and recursively verifies the other curve's accumulator.
    pub fn step(&mut self, witnesses: &[Vec<C::CircuitField>]) -> Result<(), Error> {
        self.state = match std::mem::replace(&mut self.state, unsafe { std::mem::zeroed() }) {
            CycleState::Nested { nested, host } => {
                // Prove on nested curve (Pallas), verifying host accumulator.
                let new_nested = self.nested_prover.step(nested, None)?;

                CycleState::Host {
                    nested: Accumulator::Uncompressed(Box::new(new_nested)),
                    host,
                }
            }
            CycleState::Host { nested, host } => {
                //  Prove on host curve (Vesta), verifying nested accumulator.
                let new_host = self.host_prover.step(host, Some(witnesses))?;

                CycleState::Nested {
                    nested,
                    host: Accumulator::Uncompressed(Box::new(new_host)),
                }
            }
        };

        self.depth += 1;

        Ok(())
    }
}

impl<C: Cycle, R: Rank> Default for CycleEngine<C, R> {
    fn default() -> Self {
        Self::new(4)
    }
}

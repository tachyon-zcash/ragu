//! Orchestration layer for CycleFold-inspired accumulation.
//!
//! The engine design models a two-phase architecture: (1) `CycleEngineBuilder`
//! for mutable (stateful) circuit registration, (2) `CycleEngine` for immutable (stateless)
//! folding with proof-carrying data.
//!
//! The API we're exposing should ideally remain agnostic with respect to the underlying curve cycle.
//! Conceptually, `CycleEngineBuilder` serves as the main user-facing entry point (builder interface)
//! encapsulating the underlying `CycleEngine` that drives the accumulation under the hood.
//!
//! This design abstracts away any underlying complex machinery, which users shouldn't need to concern
//! themselves with. Some of these lower-level primitives are accumulators, dummy proofs, curve cycles,
//! mesh management, etc.

use crate::{
    accumulator::Accumulator,
    staging::circuits::{
        d_stage::{DCValueComputationStagedCircuit, DChallengeDerivationStagedCircuit},
        e_stage::EChallengeDerivationStagedCircuit,
        g_stage::GVComputationStagedCircuit,
    },
};
use arithmetic::Cycle;
use ragu_circuits::{
    Circuit,
    mesh::{Mesh, MeshBuilder},
    polynomials::Rank,
    staging::Staged,
};
use ragu_core::Result;
use ragu_pasta::Fp;

/// Builder for registering circuits into the mesh.
pub struct CycleMeshBuilder<'a, C, R>
where
    C: Cycle,
    R: Rank,
{
    /// Curve generators.
    params: &'a C,

    /// Mesh builders.
    pallas_builder: MeshBuilder<'a, C::ScalarField, R>,
    vesta_builder: MeshBuilder<'a, C::CircuitField, R>,
}

/// Stateless orchestrator engine with finalized meshes.
pub struct CycleEngine<'a, C, R>
where
    C: Cycle,
    R: Rank,
{
    /// Curve generators.
    params: &'a C,

    /// Finalized meshes for both curves.
    pallas_mesh: Mesh<'a, C::ScalarField, R>,
    vesta_mesh: Mesh<'a, C::CircuitField, R>,
}

/// Proof-carrying data for the cycle.
pub struct CycleProof<C, R>
where
    C: Cycle,
    R: Rank,
{
    /// Pallas-side accumulator state.
    pub pallas_accumulator: Accumulator<C::NestedCurve, C::HostCurve, R>,

    /// Vesta-side accumulator state.
    pub vesta_accumulator: Accumulator<C::HostCurve, C::NestedCurve, R>,

    /// Recursion depth.
    pub depth: usize,
}

impl<'a, C: Cycle, R: Rank> CycleMeshBuilder<'a, C, R> {
    /// Initialize empty mesh builders.
    pub fn new(params: &'a C) -> Self {
        Self {
            params,
            pallas_builder: MeshBuilder::<C::ScalarField, R>::new(),
            vesta_builder: MeshBuilder::<C::CircuitField, R>::new(),
        }
    }

    /// Register application circuits on the host prover's mesh.
    pub fn register_circuit<Circ>(&mut self, circuit: Circ) -> Result<()>
    where
        Circ: Circuit<C::CircuitField> + 'static,
    {
        // TODO: have been wondering where r(X) generation fits relative to mesh registration.
        // The current construction seems to imply a strict dependency where it has to occur before
        // registration, since registration in some sense is "lossy" and the circuit gets type-erased,
        // so you can't call ::rx() on the stored `CircuitObject`.
        //
        // After the circuit gets registered, it's a `CircuitObject` that's type-erased,
        // so we can't generate the witness polynomial for it, r(X). Maybe, we should store
        // the raw circuit *for now* so we can generate the witness, but there should
        // be a good way to do this. Additionally, we've discussed probably needing to commit
        // to the mesh before starting the accumulation procedure. Intuitively this makes sense
        // for binding purposes where the mesh can't be changed later, but we should delineate
        // the explicit safety properties for doing this.

        let builder = std::mem::replace(
            &mut self.vesta_builder,
            MeshBuilder::<C::CircuitField, R>::new(),
        );

        self.vesta_builder = builder.register_circuit(circuit)?;

        Ok(())
    }

    /// Mesh finalization and seed the base accumulators.
    ///
    /// Caller must provide derived const generic parameters.
    /// Use the `finalize_with_n!` macro to compute these automatically from N.
    pub fn finalize<
        const NUM_CIRCUITS: usize,
        const MAX_CROSS: usize,
        const TOTAL_KY_COEFFS: usize,
    >(
        mut self,
    ) -> Result<CycleEngine<'a, C, R>>
    where
        C: Cycle<CircuitField = Fp>,
    {
        // JIT-register all recursion circuits to the Vesta mesh before finalization.
        self.vesta_builder = self
            .vesta_builder
            .register_circuit(Staged::<C::CircuitField, R, _>::new(
                DChallengeDerivationStagedCircuit::<C::NestedCurve, MAX_CROSS>::new(),
            ))?
            .register_circuit(Staged::<C::CircuitField, R, _>::new(
                DCValueComputationStagedCircuit::<
                    C::NestedCurve,
                    MAX_CROSS,
                    TOTAL_KY_COEFFS,
                    NUM_CIRCUITS,
                >::new(),
            ))?
            .register_circuit(Staged::<C::CircuitField, R, _>::new(
                EChallengeDerivationStagedCircuit::<C::NestedCurve>::new(),
            ))?
            .register_circuit(Staged::<C::CircuitField, R, _>::new(
                GVComputationStagedCircuit::<C::NestedCurve>::new(),
            ))?;

        // TODO: The pallas builder will be used for registering circuits purely for endoscalings.

        // Finalize the mesh builders.
        let pallas_mesh = self.pallas_builder.finalize()?;
        let vesta_mesh = self.vesta_builder.finalize()?;

        Ok(CycleEngine {
            params: self.params,
            pallas_mesh,
            vesta_mesh,
        })
    }
}

impl<'a, C: Cycle, R: Rank> CycleEngine<'a, C, R> {
    /// Create base proof with empty accumulators.
    pub fn base(&self) -> CycleProof<C, R> {
        let nested_generators = self.params.nested_generators();
        let host_generators = self.params.host_generators();

        CycleProof {
            pallas_accumulator: Accumulator::base(&self.pallas_mesh, nested_generators),
            vesta_accumulator: Accumulator::base(&self.vesta_mesh, host_generators),
            depth: 0,
        }
    }

    /// Execute one PCD step on both curves simultaneously.
    ///
    /// This is a pure function that doesn't mutate the engine state.
    pub fn fold(
        &self,
        left_proof: CycleProof<C, R>,
        right_proof: CycleProof<C, R>,
        application_witnesses: &[C::CircuitField],
    ) -> Result<CycleProof<C, R>>
    where
        C: Cycle<CircuitField = Fp>,
    {
        let mut vesta_accumulator = left_proof.vesta_accumulator;
        let mut pallas_accumulator = right_proof.pallas_accumulator;

        // Handoff: each side's deferred becomes the other's endoscalars.
        let vesta_deferred = std::mem::take(&mut vesta_accumulator.deferreds);
        pallas_accumulator.endoscalars = vesta_deferred;
        let pallas_deferred = std::mem::take(&mut pallas_accumulator.deferreds);
        vesta_accumulator.endoscalars = pallas_deferred;

        // Execute both sides of the curve cycle simultaneously. Temporarily,
        // we duplicate the Vesta and Pallas accumulators we're folding
        // for *testing* purposes.
        Self::accumulation_vesta(
            &self.vesta_mesh,
            application_witnesses,
            &vesta_accumulator,
            &vesta_accumulator,
            &self.params,
        )?;

        Self::accumulation_pallas(
            &self.pallas_mesh,
            &[],
            &pallas_accumulator,
            &pallas_accumulator,
            &self.params,
        )?;

        // TODO: use rayon to execute these in parallel closures.

        Ok(CycleProof {
            pallas_accumulator,
            vesta_accumulator,
            depth: left_proof.depth.max(right_proof.depth) + 1,
        })
    }
}

// Rust doesn't support const operations on generic parameters by default.
#[macro_export]
macro_rules! finalize {
    ($builder:expr, N = $n:expr, R = $r:expr) => {{
        const NUM_CIRCUITS: usize = $n + 2;
        const MAX_CROSS: usize = NUM_CIRCUITS * (NUM_CIRCUITS - 1);
        const KY_DEGREE: usize = 1 << $r;
        const TOTAL_KY_COEFFS: usize = $n * KY_DEGREE;
        $builder.finalize::<NUM_CIRCUITS, MAX_CROSS, TOTAL_KY_COEFFS>()
    }};
}

use crate::accumulator::CycleAccumulator;
use crate::engine::CycleEngine;
use crate::nested_encoding::b_stage::{InnerStageB, StagingCircuitB};
use crate::nested_encoding::d_stage::StagingCircuitD;
use crate::utilities::dummy_circuits::Circuits;
use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::CircuitExt;
use ragu_circuits::mesh::Mesh;
use ragu_circuits::{
    polynomials::Rank,
    staging::{StageExt, Staged},
};
use ragu_core::{Error, Result};
use ragu_pasta::{EpAffine, Fp};
use rand::thread_rng;

impl<'a, C: Cycle + Default, R: Rank> CycleEngine<'a, C, R> {
    /// Executes the Vesta-side accumulation step.
    ///
    /// This is an Fp round: computations occur over Fp, and commitments
    /// are made on the Vesta host curve.
    pub fn accumulation_vesta(
        mesh: &Mesh<'_, C::CircuitField, R>,
        witnesses: &[C::CircuitField],
        acc1: &mut CycleAccumulator<C::HostCurve, C::NestedCurve, R>,
        acc2: &CycleAccumulator<C::NestedCurve, C::HostCurve, R>,
        cycle: &C,
    ) -> Result<()> {
        // Dummy circuits used in the mesh.
        const N: usize = 4;
        let circuits = Circuits::new();
        let circuit_list = [&circuits.s3, &circuits.s4, &circuits.s10, &circuits.s19];

        ////////////////// 1. Process the application circuits //////////////////

        let mut a_polys = Vec::with_capacity(N);
        let mut ky = Vec::with_capacity(N);

        // The witness polynomials r(X) are over Fp, and produce commitments to Vesta points.
        for (&witness, circuit) in witnesses.iter().zip(circuit_list.iter()) {
            let (rx_poly, instance) = circuit.rx::<R>(witness)?;
            a_polys.push(rx_poly.commit(
                cycle.host_generators(),
                C::CircuitField::random(thread_rng()),
            ));
            ky.push(circuit.ky(instance)?);
        }

        // -------- 2. Construct B staging polynomial -------- //

        // We're building a two-layer staged B to wire properly handle the non-native arithemtic.

        let a_commitments_array: [C::HostCurve; N] = a_polys
            .try_into()
            .map_err(|_| Error::CircuitBoundExceeded(N))?;

        // Build inner staging polynomial over Fq that allocates these Vesta points.
        let inner_rx_fq = <InnerStageB<C::HostCurve, N> as StageExt<C::ScalarField, R>>::rx(
            &a_commitments_array,
        )?;

        // Create a "nested encoding" by committing to the staging polynomial using the nested generators (Pallas).
        let b_inner_commit_pallas = inner_rx_fq.commit(
            cycle.nested_generators(),
            C::ScalarField::random(thread_rng()),
        );

        // Outer staging polynomial over Fp carries this nested commitment.
        let b_stage =
            Staged::<C::CircuitField, R, _>::new(StagingCircuitB::<C::NestedCurve>::new());
        let (_b_outer_rx_fp, b_point_nested) = b_stage.rx::<R>(b_inner_commit_pallas)?;

        // -------- 3. Construct D staging polynomial -------- //

        // Hash the B commitment to generate challenge w.
        let d_stage = Staged::<Fp, R, _>::new(StagingCircuitD::<EpAffine>::new());
        let (_w_rx, w_instance) =
            d_stage.rx::<R>(unsafe { std::mem::transmute_copy(&b_point_nested) })?;

        Ok(())
    }
}

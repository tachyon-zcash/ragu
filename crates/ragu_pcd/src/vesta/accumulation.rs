use crate::accumulator::CycleAccumulator;
use crate::nested_encoding::d_stage::{DStage, DStagingCircuit};
use crate::utilities::dummy_circuits::Circuits;
use crate::{
    engine::CycleEngine,
    nested_encoding::b_stage::{
        InnerStage as InnerStageB, OuterStage as OuterStageB, StagingCircuit as StagingCircuitB,
    },
};
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
        accumulator: &mut CycleAccumulator<<C as Cycle>::HostCurve, <C as Cycle>::NestedCurve, R>,
        cycle: &C,
    ) -> Result<()> {
        // *Temporary*: use dummy circuits for generating witneses polynomials.
        // These correspond to the same circuits registered in the mesh.
        const N: usize = 4;
        let circuits = Circuits::new();

        // 1. Process the user's application circuits and compute the witness polynomials.
        let mut r_commitments = Vec::new();

        for (circuit_id, &witness) in witnesses.iter().enumerate() {
            let circuit = match circuit_id {
                0 => &circuits.s3,
                1 => &circuits.s4,
                2 => &circuits.s10,
                3 => &circuits.s19,
                _ => return Err(Error::CircuitBoundExceeded(circuit_id)),
            };

            let (rx_poly, _instance) = circuit.rx::<R>(witness)?;

            let r_commitment = rx_poly.commit(
                cycle.host_generators(),
                C::CircuitField::random(thread_rng()),
            );

            r_commitments.push(r_commitment);
        }

        // 2. Construct B staging polynomial.
        let r_commitments_array: [C::HostCurve; N] = r_commitments
            .try_into()
            .map_err(|_| Error::CircuitBoundExceeded(N))?;

        let inner_rx_fq = <InnerStageB<C::HostCurve, N> as StageExt<C::ScalarField, R>>::rx(
            &r_commitments_array,
        )?;
        let ep_commit = inner_rx_fq.commit(
            cycle.nested_generators(),
            C::ScalarField::random(thread_rng()),
        );

        let b_poly = Staged::<C::CircuitField, R, _>::new(StagingCircuitB::<C::NestedCurve>::new());
        let (_outer_rx, ep_point_value) = b_poly.rx::<R>(ep_commit)?;

        let outer_s = <OuterStageB<EpAffine> as StageExt<Fp, R>>::final_into_object()?;

        // 3. Construct D staging polynomial.
        let w_poly = Staged::<C::CircuitField, R, _>::new(DStagingCircuit::<C::NestedCurve>::new());

        Ok(())
    }
}

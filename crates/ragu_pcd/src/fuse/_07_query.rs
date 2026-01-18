//! Commit to the polynomial query claims at various points (typically $x$,
//! $xz$, $w$).
//!
//! This creates the [`proof::Query`] component of the proof, which contains
//! claimed evaluations (corresponding to each polynomial query) usually at
//! points like $x$, $xz$, and $w$.
//!
//! This phase of the fuse operation is also used to commit to the $m(W, x, y)$
//! restriction.

use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::{polynomials::Rank, staging::StageExt};
use ragu_core::{
    Result,
    drivers::Driver,
    maybe::{Always, Maybe},
};
use ragu_primitives::Element;
use rand::Rng;

use crate::{
    Application, Proof,
    circuits::{self, native, native::stages::query, nested},
    proof,
};
use native::InternalCircuitIndex;

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    pub(super) fn compute_query<'dr, D, RNG: Rng>(
        &self,
        rng: &mut RNG,
        w: &Element<'dr, D>,
        x: &Element<'dr, D>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        error_m: &proof::ErrorM<C, R>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
    ) -> Result<(
        proof::Query<C, R>,
        circuits::native::stages::query::Witness<C>,
    )>
    where
        D: Driver<'dr, F = C::CircuitField, MaybeKind = Always<()>>,
    {
        use InternalCircuitIndex::*;

        let w = *w.value().take();
        let x = *x.value().take();
        let y = *y.value().take();
        let xz = x * *z.value().take();

        let mesh_xy_poly = self.native_mesh.xy(x, y);
        let mesh_xy_blind = C::CircuitField::random(&mut *rng);
        let mesh_xy_commitment =
            mesh_xy_poly.commit(C::host_generators(self.params), mesh_xy_blind);

        let mesh_at = |idx: InternalCircuitIndex| -> C::CircuitField {
            let circuit_id = idx.circuit_index(self.num_application_steps);
            mesh_xy_poly.eval(circuit_id.omega_j())
        };

        let query_witness = query::Witness {
            fixed_mesh: query::FixedMeshWitness {
                // TODO: these can all be evaluated at the same time; in fact,
                // that's what mesh.xy is supposed to allow.
                preamble_stage: mesh_at(PreambleStage),
                error_m_stage: mesh_at(ErrorMStage),
                error_n_stage: mesh_at(ErrorNStage),
                query_stage: mesh_at(QueryStage),
                eval_stage: mesh_at(EvalStage),
                error_m_final_staged: mesh_at(ErrorMFinalStaged),
                error_n_final_staged: mesh_at(ErrorNFinalStaged),
                eval_final_staged: mesh_at(EvalFinalStaged),
                hashes_1_circuit: mesh_at(Hashes1Circuit),
                hashes_2_circuit: mesh_at(Hashes2Circuit),
                partial_collapse_circuit: mesh_at(PartialCollapseCircuit),
                full_collapse_circuit: mesh_at(FullCollapseCircuit),
                compute_v_circuit: mesh_at(ComputeVCircuit),
            },
            mesh_wxy: mesh_xy_poly.eval(w),
            left: query::ChildEvaluationsWitness::from_proof(
                left,
                w,
                x,
                xz,
                &mesh_xy_poly,
                &error_m.mesh_wy_poly,
            ),
            right: query::ChildEvaluationsWitness::from_proof(
                right,
                w,
                x,
                xz,
                &mesh_xy_poly,
                &error_m.mesh_wy_poly,
            ),
        };

        let native_rx = query::Stage::<C, R, HEADER_SIZE>::rx(&query_witness)?;
        let native_blind = C::CircuitField::random(&mut *rng);
        let native_commitment = native_rx.commit(C::host_generators(self.params), native_blind);

        let nested_query_witness = nested::stages::query::Witness {
            native_query: native_commitment,
            mesh_xy: mesh_xy_commitment,
        };
        let nested_rx = nested::stages::query::Stage::<C::HostCurve, R>::rx(&nested_query_witness)?;
        let nested_blind = C::ScalarField::random(&mut *rng);
        let nested_commitment = nested_rx.commit(C::nested_generators(self.params), nested_blind);

        Ok((
            proof::Query {
                mesh_xy_poly,
                mesh_xy_blind,
                mesh_xy_commitment,
                native_rx,
                native_blind,
                native_commitment,
                nested_rx,
                nested_blind,
                nested_commitment,
            },
            query_witness,
        ))
    }
}

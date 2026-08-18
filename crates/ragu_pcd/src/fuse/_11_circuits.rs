use ragu_arithmetic::{Cycle, rand::CryptoRng};
use ragu_circuits::{CircuitExt, polynomials::Rank};
use ragu_core::Result;

use crate::{
    Application,
    internal::{native, native::total_circuit_counts},
    proof::ProofBuilder,
};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, B: ragu_backend::Backend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    pub(super) fn compute_internal_circuits<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        preamble_witness: &native::stages::preamble::Witness<'_, C, R, HEADER_SIZE>,
        outer_error_witness: &native::stages::outer_error::Witness<C, native::RevdotParameters>,
        inner_error_witness: &native::stages::inner_error::Witness<C, native::RevdotParameters>,
        query_witness: &native::stages::query::Witness<C>,
        eval_witness: &native::stages::eval::Witness<C::CircuitField>,
        builder: &mut ProofBuilder<'_, C, R>,
    ) -> Result<()> {
        let unified = native::unified::Instance {
            bridge_preamble_commitment: builder.bridge_preamble_commitment(),
            w: builder.w(),
            bridge_s_prime_commitment: builder.bridge_s_prime_commitment(),
            y: builder.y(),
            z: builder.z(),
            bridge_inner_error_commitment: builder.bridge_inner_error_commitment(),
            mu: builder.mu(),
            nu: builder.nu(),
            bridge_outer_error_commitment: builder.bridge_outer_error_commitment()?,
            mu_prime: builder.mu_prime(),
            nu_prime: builder.nu_prime(),
            c: builder.c::<B>(),
            bridge_ab_commitment: builder.bridge_ab_commitment()?,
            x: builder.x(),
            bridge_query_commitment: builder.bridge_query_commitment()?,
            alpha: builder.alpha(),
            bridge_f_commitment: builder.bridge_f_commitment(),
            u: builder.u(),
            bridge_eval_commitment: builder.bridge_eval_commitment()?,
            pre_beta: builder.pre_beta(),
            v: builder.v::<B>(),
            coverage: Default::default(),
        };

        let (hashes_1_trace, unified) = native::circuits::hashes_1::Circuit::<
            C,
            R,
            HEADER_SIZE,
            native::RevdotParameters,
        >::new(
            self.params,
            total_circuit_counts(self.num_application_steps).1,
        )
        .trace(native::circuits::hashes_1::Witness {
            unified,
            preamble_witness,
            outer_error_witness,
        })?
        .into_parts();
        let hashes_1_rx = self.native_registry.assemble(
            &hashes_1_trace,
            native::InternalCircuitIndex::Hashes1Circuit.circuit_index(),
            &mut *rng,
        )?;

        let (hashes_2_trace, unified) = native::circuits::hashes_2::Circuit::<
            C,
            R,
            HEADER_SIZE,
            native::RevdotParameters,
        >::new(self.params)
        .trace(native::circuits::hashes_2::Witness {
            unified,
            outer_error_witness,
        })?
        .into_parts();
        let hashes_2_rx = self.native_registry.assemble(
            &hashes_2_trace,
            native::InternalCircuitIndex::Hashes2Circuit.circuit_index(),
            &mut *rng,
        )?;

        let (inner_collapse_trace, unified) = native::circuits::inner_collapse::Circuit::<
            C,
            R,
            HEADER_SIZE,
            native::RevdotParameters,
        >::new()
        .trace(native::circuits::inner_collapse::Witness {
            preamble_witness,
            unified,
            outer_error_witness,
            inner_error_witness,
        })?
        .into_parts();
        let inner_collapse_rx = self.native_registry.assemble(
            &inner_collapse_trace,
            native::InternalCircuitIndex::InnerCollapseCircuit.circuit_index(),
            &mut *rng,
        )?;

        let (outer_collapse_trace, unified) = native::circuits::outer_collapse::Circuit::<
            C,
            R,
            HEADER_SIZE,
            native::RevdotParameters,
        >::new()
        .trace(native::circuits::outer_collapse::Witness {
            unified,
            preamble_witness,
            outer_error_witness,
        })?
        .into_parts();
        let outer_collapse_rx = self.native_registry.assemble(
            &outer_collapse_trace,
            native::InternalCircuitIndex::OuterCollapseCircuit.circuit_index(),
            &mut *rng,
        )?;

        let (compute_v_trace, unified) =
            native::circuits::compute_v::Circuit::<C, R, HEADER_SIZE>::new()
                .trace(native::circuits::compute_v::Witness {
                    unified,
                    preamble_witness,
                    query_witness,
                    eval_witness,
                })?
                .into_parts();
        let compute_v_rx = self.native_registry.assemble(
            &compute_v_trace,
            native::InternalCircuitIndex::ComputeVCircuit.circuit_index(),
            &mut *rng,
        )?;

        // Cross-circuit coverage validation (prover-time development assertion,
        // not a verifier check): all internal recursion circuits together must
        // cover every slot exactly once. Overlap is caught eagerly by finish();
        // missing slots are caught here.
        unified.assert_complete();

        builder.set_native_hashes_1_rx(hashes_1_rx);
        builder.set_native_hashes_2_rx(hashes_2_rx);
        builder.set_native_inner_collapse_rx(inner_collapse_rx);
        builder.set_native_outer_collapse_rx(outer_collapse_rx);
        builder.set_native_compute_v_rx(compute_v_rx);

        Ok(())
    }
}

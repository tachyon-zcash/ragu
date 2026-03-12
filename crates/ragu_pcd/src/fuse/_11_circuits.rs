use alloc::sync::Arc;
use ff::Field;
use ragu_arithmetic::Cycle;
use ragu_circuits::{CircuitExt, polynomials::Rank};
use ragu_core::Result;
use rand::CryptoRng;

use crate::{
    Application,
    circuits::{self, native, native::total_circuit_counts},
    components::fold_revdot::NativeParameters,
    proof,
};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    pub(super) fn compute_internal_circuits<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        preamble: &proof::Preamble<C, R>,
        s_prime: &proof::SPrime<C, R>,
        error_n: &proof::ErrorN<C, R>,
        error_m: &proof::ErrorM<C, R>,
        ab: &proof::AB<C, R>,
        query: &proof::Query<C, R>,
        f: &proof::F<C, R>,
        eval: &proof::Eval<C, R>,
        p: &proof::P<C, R>,
        preamble_witness: Arc<native::stages::preamble::Witness<C, R, HEADER_SIZE>>,
        error_n_witness: Arc<native::stages::error_n::Witness<C, NativeParameters>>,
        error_m_witness: Arc<native::stages::error_m::Witness<C, NativeParameters>>,
        query_witness: Arc<circuits::native::stages::query::Witness<C>>,
        eval_witness: Arc<circuits::native::stages::eval::Witness<C::CircuitField>>,
        challenges: &proof::Challenges<C>,
    ) -> Result<proof::InternalCircuits<C, R>> {
        let unified = native::unified::Instance {
            nested_preamble_commitment: preamble.nested_commitment,
            w: challenges.w,
            nested_s_prime_commitment: s_prime.nested_s_prime_commitment,
            y: challenges.y,
            z: challenges.z,
            nested_error_m_commitment: error_m.nested_commitment,
            mu: challenges.mu,
            nu: challenges.nu,
            nested_error_n_commitment: error_n.nested_commitment,
            mu_prime: challenges.mu_prime,
            nu_prime: challenges.nu_prime,
            c: ab.c,
            nested_ab_commitment: ab.nested_commitment,
            x: challenges.x,
            nested_query_commitment: query.nested_commitment,
            alpha: challenges.alpha,
            nested_f_commitment: f.nested_commitment,
            u: challenges.u,
            nested_eval_commitment: eval.nested_commitment,
            pre_beta: challenges.pre_beta,
            v: p.v,
            coverage: Default::default(),
        };
        let (hashes_1_trace, unified) =
            native::hashes_1::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new(
                self.params,
                total_circuit_counts(self.num_application_steps).1,
            )
            .rx(native::hashes_1::Witness {
                unified,
                preamble_witness: preamble_witness.clone(),
                error_n_witness: error_n_witness.clone(),
            })?;
        let hashes_1_rx = self.native_registry.assemble(
            &hashes_1_trace,
            native::hashes_1::CIRCUIT_ID.circuit_index(),
        )?;
        let hashes_1_rx_blind = C::CircuitField::random(&mut *rng);

        let (hashes_2_trace, unified) =
            native::hashes_2::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new(self.params).rx(
                native::hashes_2::Witness {
                    unified,
                    error_n_witness: error_n_witness.clone(),
                },
            )?;
        let hashes_2_rx = self.native_registry.assemble(
            &hashes_2_trace,
            native::hashes_2::CIRCUIT_ID.circuit_index(),
        )?;
        let hashes_2_rx_blind = C::CircuitField::random(&mut *rng);

        let (partial_collapse_trace, unified) =
            native::partial_collapse::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new().rx(
                native::partial_collapse::Witness {
                    preamble_witness: preamble_witness.clone(),
                    unified,
                    error_n_witness: error_n_witness.clone(),
                    error_m_witness,
                },
            )?;
        let partial_collapse_rx = self.native_registry.assemble(
            &partial_collapse_trace,
            native::partial_collapse::CIRCUIT_ID.circuit_index(),
        )?;
        let partial_collapse_rx_blind = C::CircuitField::random(&mut *rng);

        let (full_collapse_trace, unified) =
            native::full_collapse::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new().rx(
                native::full_collapse::Witness {
                    unified,
                    preamble_witness: preamble_witness.clone(),
                    error_n_witness,
                },
            )?;
        let full_collapse_rx = self.native_registry.assemble(
            &full_collapse_trace,
            native::full_collapse::CIRCUIT_ID.circuit_index(),
        )?;
        let full_collapse_rx_blind = C::CircuitField::random(&mut *rng);

        let (compute_v_trace, unified) = native::compute_v::Circuit::<C, R, HEADER_SIZE>::new()
            .rx(native::compute_v::Witness {
                unified,
                preamble_witness,
                query_witness,
                eval_witness,
            })?;
        let compute_v_rx = self.native_registry.assemble(
            &compute_v_trace,
            native::compute_v::CIRCUIT_ID.circuit_index(),
        )?;
        let compute_v_rx_blind = C::CircuitField::random(&mut *rng);

        // Cross-circuit coverage validation (prover-time development assertion,
        // not a verifier check): all internal recursion circuits together must
        // cover every slot exactly once. Overlap is caught eagerly by finish();
        // missing slots are caught here.
        unified.assert_complete();

        let host_gen = C::host_generators(self.params);
        let [
            hashes_1_rx_commitment,
            hashes_2_rx_commitment,
            partial_collapse_rx_commitment,
            full_collapse_rx_commitment,
            compute_v_rx_commitment,
        ] = ragu_arithmetic::batch_to_affine([
            hashes_1_rx.commit(host_gen, hashes_1_rx_blind),
            hashes_2_rx.commit(host_gen, hashes_2_rx_blind),
            partial_collapse_rx.commit(host_gen, partial_collapse_rx_blind),
            full_collapse_rx.commit(host_gen, full_collapse_rx_blind),
            compute_v_rx.commit(host_gen, compute_v_rx_blind),
        ]);

        Ok(proof::InternalCircuits {
            hashes_1_rx,
            hashes_1_blind: hashes_1_rx_blind,
            hashes_1_commitment: hashes_1_rx_commitment,
            hashes_2_rx,
            hashes_2_blind: hashes_2_rx_blind,
            hashes_2_commitment: hashes_2_rx_commitment,
            partial_collapse_rx,
            partial_collapse_blind: partial_collapse_rx_blind,
            partial_collapse_commitment: partial_collapse_rx_commitment,
            full_collapse_rx,
            full_collapse_blind: full_collapse_rx_blind,
            full_collapse_commitment: full_collapse_rx_commitment,
            compute_v_rx,
            compute_v_blind: compute_v_rx_blind,
            compute_v_commitment: compute_v_rx_commitment,
        })
    }
}

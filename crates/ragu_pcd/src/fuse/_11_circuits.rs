use ragu_arithmetic::Cycle;
use ragu_circuits::{
    CircuitExt,
    polynomials::{Rank, structured},
};
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
        preamble_witness: &native::stages::preamble::Witness<'_, C, R, HEADER_SIZE>,
        error_n_witness: &native::stages::error_n::Witness<C, NativeParameters>,
        error_m_witness: &native::stages::error_m::Witness<C, NativeParameters>,
        query_witness: &circuits::native::stages::query::Witness<C>,
        eval_witness: &circuits::native::stages::eval::Witness<C::CircuitField>,
        challenges: &proof::Challenges<C>,
    ) -> Result<proof::InternalCircuits<C, R>> {
        let unified = native::unified::Instance {
            nested_preamble_commitment: preamble.nested_rx.commitment(),
            w: challenges.w,
            nested_s_prime_commitment: s_prime.nested_s_prime_rx.commitment(),
            y: challenges.y,
            z: challenges.z,
            nested_error_m_commitment: error_m.nested_rx.commitment(),
            mu: challenges.mu,
            nu: challenges.nu,
            nested_error_n_commitment: error_n.nested_rx.commitment(),
            mu_prime: challenges.mu_prime,
            nu_prime: challenges.nu_prime,
            c: ab.c,
            nested_ab_commitment: ab.nested_rx.commitment(),
            x: challenges.x,
            nested_query_commitment: query.nested_rx.commitment(),
            alpha: challenges.alpha,
            nested_f_commitment: f.nested_rx.commitment(),
            u: challenges.u,
            nested_eval_commitment: eval.nested_rx.commitment(),
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
                preamble_witness,
                error_n_witness,
            })?;
        let hashes_1_poly = self.native_registry.assemble(
            &hashes_1_trace,
            native::hashes_1::CIRCUIT_ID.circuit_index(),
        )?;

        let (hashes_2_trace, unified) =
            native::hashes_2::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new(self.params).rx(
                native::hashes_2::Witness {
                    unified,
                    error_n_witness,
                },
            )?;
        let hashes_2_poly = self.native_registry.assemble(
            &hashes_2_trace,
            native::hashes_2::CIRCUIT_ID.circuit_index(),
        )?;

        let (partial_collapse_trace, unified) =
            native::partial_collapse::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new().rx(
                native::partial_collapse::Witness {
                    preamble_witness,
                    unified,
                    error_n_witness,
                    error_m_witness,
                },
            )?;
        let partial_collapse_poly = self.native_registry.assemble(
            &partial_collapse_trace,
            native::partial_collapse::CIRCUIT_ID.circuit_index(),
        )?;

        let (full_collapse_trace, unified) =
            native::full_collapse::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new().rx(
                native::full_collapse::Witness {
                    unified,
                    preamble_witness,
                    error_n_witness,
                },
            )?;
        let full_collapse_poly = self.native_registry.assemble(
            &full_collapse_trace,
            native::full_collapse::CIRCUIT_ID.circuit_index(),
        )?;

        let (compute_v_trace, unified) = native::compute_v::Circuit::<C, R, HEADER_SIZE>::new()
            .rx(native::compute_v::Witness {
                unified,
                preamble_witness,
                query_witness,
                eval_witness,
            })?;
        let compute_v_poly = self.native_registry.assemble(
            &compute_v_trace,
            native::compute_v::CIRCUIT_ID.circuit_index(),
        )?;

        unified.assert_complete();

        let [
            hashes_1,
            hashes_2,
            partial_collapse,
            full_collapse,
            compute_v,
        ] = structured::batch_commit(
            rng,
            C::host_generators(self.params),
            [
                hashes_1_poly,
                hashes_2_poly,
                partial_collapse_poly,
                full_collapse_poly,
                compute_v_poly,
            ],
        );

        Ok(proof::InternalCircuits {
            hashes_1,
            hashes_2,
            partial_collapse,
            full_collapse,
            compute_v,
        })
    }
}

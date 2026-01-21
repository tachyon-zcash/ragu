use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::{CircuitExt, polynomials::Rank};
use ragu_core::Result;
use rand::Rng;

use crate::{
    Application,
    circuits::{self, native, native::total_circuit_counts},
    components::fold_revdot::NativeParameters,
    proof,
};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    pub(super) fn compute_internal_circuits<RNG: Rng>(
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
        let unified_instance = &native::unified::Instance {
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
        };

        let (hashes_1_rx, _) =
            native::hashes_1::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new(
                self.params,
                total_circuit_counts(self.num_application_steps).1,
            )
            .rx::<R>(
                native::hashes_1::Witness {
                    unified_instance,
                    preamble_witness,
                    error_n_witness,
                },
                self.native_mesh.get_key(),
            )?;
        let hashes_1_rx_blind = C::CircuitField::random(&mut *rng);
        let hashes_1_rx_commitment =
            hashes_1_rx.commit(C::host_generators(self.params), hashes_1_rx_blind);

        let (hashes_2_rx, _) =
            native::hashes_2::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new(self.params)
                .rx::<R>(
                    native::hashes_2::Witness {
                        unified_instance,
                        error_n_witness,
                    },
                    self.native_mesh.get_key(),
                )?;
        let hashes_2_rx_blind = C::CircuitField::random(&mut *rng);
        let hashes_2_rx_commitment =
            hashes_2_rx.commit(C::host_generators(self.params), hashes_2_rx_blind);

        let (partial_collapse_rx, _) =
            native::partial_collapse::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new()
                .rx::<R>(
                    native::partial_collapse::Witness {
                        preamble_witness,
                        unified_instance,
                        error_m_witness,
                        error_n_witness,
                    },
                    self.native_mesh.get_key(),
                )?;
        let partial_collapse_rx_blind = C::CircuitField::random(&mut *rng);
        let partial_collapse_rx_commitment =
            partial_collapse_rx.commit(C::host_generators(self.params), partial_collapse_rx_blind);

        let (full_collapse_rx, _) =
            native::full_collapse::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new().rx::<R>(
                native::full_collapse::Witness {
                    unified_instance,
                    preamble_witness,
                    error_n_witness,
                },
                self.native_mesh.get_key(),
            )?;
        let full_collapse_rx_blind = C::CircuitField::random(&mut *rng);
        let full_collapse_rx_commitment =
            full_collapse_rx.commit(C::host_generators(self.params), full_collapse_rx_blind);

        let (compute_v_rx, _) =
            native::compute_v::Circuit::<C, R, HEADER_SIZE>::new(self.num_application_steps)
                .rx::<R>(
                    native::compute_v::Witness {
                        unified_instance,
                        preamble_witness,
                        query_witness,
                        eval_witness,
                    },
                    self.native_mesh.get_key(),
                )?;
        let compute_v_rx_blind = C::CircuitField::random(&mut *rng);
        let compute_v_rx_commitment =
            compute_v_rx.commit(C::host_generators(self.params), compute_v_rx_blind);

        let (endoscale_challenges_rx, _) =
            native::endoscale_challenges::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new()
                .rx::<R>(
                    native::endoscale_challenges::Witness {
                        unified_instance,
                        preamble_witness,
                        error_n_witness,
                    },
                    self.native_mesh.get_key(),
                )?;
        let endoscale_challenges_rx_blind = C::CircuitField::random(&mut *rng);
        let endoscale_challenges_rx_commitment = endoscale_challenges_rx.commit(
            C::host_generators(self.params),
            endoscale_challenges_rx_blind,
        );

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
            endoscale_challenges_rx,
            endoscale_challenges_blind: endoscale_challenges_rx_blind,
            endoscale_challenges_commitment: endoscale_challenges_rx_commitment,
        })
    }
}

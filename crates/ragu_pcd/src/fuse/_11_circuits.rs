use ff::Field;
use ragu_arithmetic::Cycle;
use ragu_circuits::{CircuitExt, polynomials::Rank};
use ragu_core::Result;
use rand::CryptoRng;

use crate::{
    Application,
    internal::{native, native::total_circuit_counts},
    proof,
};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    pub(super) fn compute_internal_circuits<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        preamble: &proof::Preamble<C, R>,
        s_prime: &proof::SPrime<C, R>,
        outer_error: &proof::OuterError<C, R>,
        inner_error: &proof::InnerError<C, R>,
        ab: &proof::AB<C, R>,
        query: &proof::Query<C, R>,
        f: &proof::F<C, R>,
        eval: &proof::Eval<C, R>,
        p: &proof::P<C, R>,
        preamble_witness: &native::stages::preamble::Witness<'_, C, R, HEADER_SIZE>,
        outer_error_witness: &native::stages::outer_error::Witness<C, native::RevdotParameters>,
        inner_error_witness: &native::stages::inner_error::Witness<C, native::RevdotParameters>,
        query_witness: &native::stages::query::Witness<C>,
        eval_witness: &native::stages::eval::Witness<C::CircuitField>,
        challenges: &proof::Challenges<C>,
    ) -> Result<proof::InternalCircuits<C, R>> {
        let unified = native::unified::Instance {
            bridge_preamble_commitment: preamble.bridge.commitment,
            w: *challenges.w,
            bridge_s_prime_commitment: s_prime.bridge.commitment,
            y: *challenges.y,
            z: *challenges.z,
            bridge_inner_error_commitment: inner_error.bridge.commitment,
            mu: *challenges.mu,
            nu: *challenges.nu,
            bridge_outer_error_commitment: outer_error.bridge.commitment,
            mu_prime: *challenges.mu_prime,
            nu_prime: *challenges.nu_prime,
            c: ab.native.c,
            bridge_ab_commitment: ab.bridge.commitment,
            x: *challenges.x,
            bridge_query_commitment: query.bridge.commitment,
            alpha: *challenges.alpha,
            bridge_f_commitment: f.bridge.commitment,
            u: *challenges.u,
            bridge_eval_commitment: eval.bridge.commitment,
            pre_beta: *challenges.pre_beta,
            v: p.native.v,
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
        .rx(native::circuits::hashes_1::Witness {
            unified,
            preamble_witness,
            outer_error_witness,
        })?;
        let hashes_1_rx = self.native_registry.assemble(
            &hashes_1_trace,
            native::InternalCircuitIndex::Hashes1Circuit.circuit_index(),
        )?;
        let hashes_1_blind = C::CircuitField::random(&mut *rng);

        let (hashes_2_trace, unified) = native::circuits::hashes_2::Circuit::<
            C,
            R,
            HEADER_SIZE,
            native::RevdotParameters,
        >::new(self.params)
        .rx(native::circuits::hashes_2::Witness {
            unified,
            outer_error_witness,
        })?;
        let hashes_2_rx = self.native_registry.assemble(
            &hashes_2_trace,
            native::InternalCircuitIndex::Hashes2Circuit.circuit_index(),
        )?;
        let hashes_2_blind = C::CircuitField::random(&mut *rng);

        let (inner_collapse_trace, unified) = native::circuits::inner_collapse::Circuit::<
            C,
            R,
            HEADER_SIZE,
            native::RevdotParameters,
        >::new()
        .rx(native::circuits::inner_collapse::Witness {
            preamble_witness,
            unified,
            outer_error_witness,
            inner_error_witness,
        })?;
        let inner_collapse_rx = self.native_registry.assemble(
            &inner_collapse_trace,
            native::InternalCircuitIndex::InnerCollapseCircuit.circuit_index(),
        )?;
        let inner_collapse_blind = C::CircuitField::random(&mut *rng);

        let (outer_collapse_trace, unified) = native::circuits::outer_collapse::Circuit::<
            C,
            R,
            HEADER_SIZE,
            native::RevdotParameters,
        >::new()
        .rx(native::circuits::outer_collapse::Witness {
            unified,
            preamble_witness,
            outer_error_witness,
        })?;
        let outer_collapse_rx = self.native_registry.assemble(
            &outer_collapse_trace,
            native::InternalCircuitIndex::OuterCollapseCircuit.circuit_index(),
        )?;
        let outer_collapse_blind = C::CircuitField::random(&mut *rng);

        let (compute_v_trace, unified) =
            native::circuits::compute_v::Circuit::<C, R, HEADER_SIZE>::new().rx(
                native::circuits::compute_v::Witness {
                    unified,
                    preamble_witness,
                    query_witness,
                    eval_witness,
                },
            )?;
        let compute_v_rx = self.native_registry.assemble(
            &compute_v_trace,
            native::InternalCircuitIndex::ComputeVCircuit.circuit_index(),
        )?;
        let compute_v_blind = C::CircuitField::random(&mut *rng);

        // Cross-circuit coverage validation (prover-time development assertion,
        // not a verifier check): all internal recursion circuits together must
        // cover every slot exactly once. Overlap is caught eagerly by finish();
        // missing slots are caught here.
        unified.assert_complete();

        let host_gen = C::host_generators(self.params);
        let [
            hashes_1_commitment,
            hashes_2_commitment,
            inner_collapse_commitment,
            outer_collapse_commitment,
            compute_v_commitment,
        ] = ragu_arithmetic::batch_to_affine([
            hashes_1_rx.commit(host_gen, hashes_1_blind),
            hashes_2_rx.commit(host_gen, hashes_2_blind),
            inner_collapse_rx.commit(host_gen, inner_collapse_blind),
            outer_collapse_rx.commit(host_gen, outer_collapse_blind),
            compute_v_rx.commit(host_gen, compute_v_blind),
        ]);

        Ok(proof::InternalCircuits {
            hashes_1: proof::RxTriple {
                rx: hashes_1_rx,
                blind: hashes_1_blind,
                commitment: hashes_1_commitment,
            },
            hashes_2: proof::RxTriple {
                rx: hashes_2_rx,
                blind: hashes_2_blind,
                commitment: hashes_2_commitment,
            },
            inner_collapse: proof::RxTriple {
                rx: inner_collapse_rx,
                blind: inner_collapse_blind,
                commitment: inner_collapse_commitment,
            },
            outer_collapse: proof::RxTriple {
                rx: outer_collapse_rx,
                blind: outer_collapse_blind,
                commitment: outer_collapse_commitment,
            },
            compute_v: proof::RxTriple {
                rx: compute_v_rx,
                blind: compute_v_blind,
                commitment: compute_v_commitment,
            },
        })
    }
}

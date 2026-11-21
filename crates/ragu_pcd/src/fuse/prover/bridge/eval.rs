//! Bridge eval prover phase.
use alloc::vec::Vec;

use ragu_circuits::{
    polynomials::{Rank, sparse},
    staging::StageExt,
};
use ragu_core::Result;
use ragu_primitives::vec::FixedVec;
use rand::CryptoRng;
use udon::field::Field;

use crate::{
    Application, Proof,
    fuse::prover::{
        native::{inner_error::RegistryWy, s_prime::NativeSPrime},
        nested::{inner_error::NestedRegistryWy, s_prime::NestedSPrime},
        proof_builder::ProofBuilder,
    },
    multicore::par_join,
    profile::ProfiledCycle,
    protocol::{native::online, nested},
};

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    pub(in crate::fuse::prover) fn compute_eval(
        &self,
        bound_challenges: &[C::CircuitField;
             crate::fuse::circuits::native::bind_challenges::NUM_BOUND],
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        s_prime: &NativeSPrime<C, R>,
        registry_wy: &RegistryWy<C, R>,
        nested_s_prime: &NestedSPrime<C, R>,
        nested_registry_wy: &NestedRegistryWy<C, R>,
        builder: &ProofBuilder<'_, C, R, B>,
    ) -> Result<(
        crate::protocol::native::stages::eval::Witness<C>,
        crate::protocol::nested::stages::eval::Evaluations<C::ScalarField, C::Profile>,
        crate::protocol::nested::stages::challenges::Witness<C::ScalarField>,
    )> {
        // The binding partials over the lifts of the challenges squeezed so
        // far, in challenge-stage order; `u` is the last of them.
        let mut lifts =
            [C::ScalarField::ZERO; crate::fuse::circuits::native::bind_challenges::NUM_BOUND];
        for (lift, challenge) in lifts.iter_mut().zip(bound_challenges) {
            *lift = nested::challenge::<C>(*challenge)?;
        }
        // The binding partials use only the ten lifts and the sign. Beta
        // is filled after `pre_beta` is squeezed, before this witness is committed.
        let nested_challenges =
            crate::protocol::nested::stages::challenges::Witness::new::<_, HEADER_SIZE>(
                lifts,
                builder.left_header(),
                builder.right_header(),
                C::ScalarField::ZERO,
            );
        let partials = crate::protocol::native::stages::eval::BindingPartials::compute::<C, R, B>(
            self.params,
            &nested_challenges,
        );

        let u = bound_challenges[crate::fuse::circuits::native::bind_challenges::NUM_BOUND - 1];
        let u_nested = nested::challenge::<C>(u)?;

        // ProofBuilder contains OnceCell fields and is therefore !Sync.
        // Extract shared references to the already-set polynomials so the
        // closures below capture &Polynomial (which is Sync) rather than
        // &ProofBuilder.
        let native_a_poly = builder.native_a_poly();
        let native_b_poly = builder.native_b_poly();
        let native_registry_xy_poly = builder.native_registry_xy_poly();
        let online_polynomials = online::polys(left, right, builder.online_polynomials());
        let nested_a_poly = builder.nested_a_poly();
        let nested_b_poly = builder.nested_b_poly();
        let nested_registry_xy_poly = builder.nested_registry_xy_poly();

        // Evaluate left/right child witnesses concurrently with the
        // current-step polynomial evaluations at u.
        let (left_witness, right_witness, current) = par_join!(
            || {
                crate::protocol::native::stages::eval::ChildEvaluationsWitness::from_proof::<C, R, B>(
                    left, u,
                )
            },
            || {
                crate::protocol::native::stages::eval::ChildEvaluationsWitness::from_proof::<C, R, B>(
                    right, u,
                )
            },
            || crate::protocol::native::stages::eval::CurrentStepWitness {
                registry_wx0: B::sparse_eval(&s_prime.registry_wx0_poly, u),
                registry_wx1: B::sparse_eval(&s_prime.registry_wx1_poly, u),
                registry_wy: B::sparse_eval(&registry_wy.poly, u),
                a_poly: B::sparse_eval(native_a_poly, u),
                b_poly: B::sparse_eval(native_b_poly, u),
                registry_xy: B::sparse_eval(native_registry_xy_poly, u),
                online: online_polynomials.map(|poly| B::sparse_eval(poly, u)),
            },
        );

        let native = crate::protocol::native::stages::eval::Witness {
            left: left_witness,
            right: right_witness,
            current,
            partials,
        };

        let (left_nested, right_nested, current_nested) = par_join!(
            || {
                crate::protocol::nested::stages::eval::ChildEvaluationsWitness::from_proof::<C, R, B>(
                    left, u_nested,
                )
            },
            || {
                crate::protocol::nested::stages::eval::ChildEvaluationsWitness::from_proof::<C, R, B>(
                    right, u_nested,
                )
            },
            || crate::protocol::nested::stages::eval::CurrentStepWitness {
                registry_wx0: B::sparse_eval(&nested_s_prime.registry_wx0_poly, u_nested),
                registry_wx1: B::sparse_eval(&nested_s_prime.registry_wx1_poly, u_nested),
                registry_wy: B::sparse_eval(&nested_registry_wy.poly, u_nested),
                a_poly: B::sparse_eval(nested_a_poly, u_nested),
                b_poly: B::sparse_eval(nested_b_poly, u_nested),
                registry_xy: B::sparse_eval(nested_registry_xy_poly, u_nested),
            },
        );

        let nested = crate::protocol::nested::stages::eval::Evaluations {
            left: left_nested,
            right: right_nested,
            current: current_nested,
            online_fq: FixedVec::try_from(
                builder
                    .online_fq_polynomials()
                    .iter()
                    .map(|poly| {
                        let value = B::sparse_eval(poly, u_nested);
                        // Test hook: this runs on the thread that calls
                        // `fuse`, outside its parallel jobs, as the hook's
                        // thread-local requires.
                        #[cfg(test)]
                        let value = crate::online_fq_oracles_tests::mutate_eval_value(value);
                        value
                    })
                    .collect::<Vec<_>>(),
            )?,
        };

        Ok((native, nested, nested_challenges))
    }

    /// Samples fresh eval-stage blindings and returns the native eval rx
    /// together with the `eval` bridge stage's rx and commitment.
    ///
    /// The `pre_beta` rejection loop calls this once per attempt, re-deriving
    /// the challenge from a fresh commitment until it lands in range. Only the
    /// accepted rxs are committed to the builder, so this computes the
    /// commitments without populating any builder cell.
    pub(in crate::fuse::prover) fn sample_eval_commitment<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        eval_witness: &crate::protocol::native::stages::eval::Witness<C>,
        nested_eval: &crate::protocol::nested::stages::eval::Evaluations<
            C::ScalarField,
            C::Profile,
        >,
    ) -> Result<(
        sparse::Polynomial<C::CircuitField, R>,
        sparse::Polynomial<C::ScalarField, R>,
        C::NestedCurve,
    )> {
        let eval_rx = crate::protocol::native::stages::eval::Stage::<C, R, HEADER_SIZE>::rx(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            eval_witness,
        )?;
        let native_eval_commitment =
            B::sparse_commit_to_affine(&eval_rx, C::host_generators(self.params));

        let bridge_rx =
            crate::protocol::nested::stages::eval::Stage::<C::HostCurve, R, C::Profile>::rx(
                C::ScalarField::random(|bytes| rng.fill_bytes(bytes)),
                &crate::protocol::nested::stages::eval::Witness {
                    native_eval: native_eval_commitment,
                    nested: nested_eval.clone(),
                },
            )?;
        let bridge_eval_commitment =
            B::sparse_commit_to_affine(&bridge_rx, C::nested_generators(self.params));

        Ok((eval_rx, bridge_rx, bridge_eval_commitment))
    }
}

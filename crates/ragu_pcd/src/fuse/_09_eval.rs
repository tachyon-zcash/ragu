//! Commit to the evaluations of every queried polynomial at $u$.
//!
//! This sets the native `eval` stage containing the claimed evaluations at $u$
//! of every element that was also queried in the `query` stage. The evaluation
//! $f(u)$ is derived from the aforementioned evaluations.
//!
//! The nested evaluations at $u_n$ of every polynomial the nested batch folds
//! into $p_n$ are computed here as well; they ride inside the `eval` bridge
//! stage, whose commitment is what `pre_beta` is squeezed from.
//!
//! The native `eval` stage also carries the running partial sums of the
//! nested challenge binding (see `bind_challenges`), computed here from the
//! lifts of the ten challenges squeezed so far; the binding they complete
//! to goes to the unified instance.

use ragu_arithmetic::{Cycle, ff::Field, par_join, rand::CryptoRng};
use ragu_circuits::{
    polynomials::{Rank, sparse},
    staging::StageExt,
};
use ragu_core::Result;

use super::{NativeSPrime, NestedRegistryWy, NestedSPrime, RegistryWy};
use crate::{
    Application, Proof,
    internal::{native, nested},
    proof::ProofBuilder,
};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    pub(super) fn compute_eval(
        &self,
        bound_challenges: &[C::CircuitField; native::circuits::bind_challenges::NUM_BOUND],
        is_base_case: bool,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        s_prime: &NativeSPrime<C, R>,
        registry_wy: &RegistryWy<C, R>,
        nested_s_prime: &NestedSPrime<C, R>,
        nested_registry_wy: &NestedRegistryWy<C, R>,
        builder: &ProofBuilder<'_, C, R, B>,
    ) -> Result<(
        native::stages::eval::Witness<C>,
        nested::stages::eval::Evaluations<C::ScalarField>,
        C::NestedCurve,
    )> {
        // The binding partials over the lifts of the challenges squeezed so
        // far, in challenge-stage order; `u` is the last of them.
        let mut lifts = [C::ScalarField::ZERO; native::circuits::bind_challenges::NUM_BOUND];
        for (lift, challenge) in lifts.iter_mut().zip(bound_challenges) {
            *lift = nested::challenge::<C>(*challenge)?;
        }
        let partials = native::stages::eval::BindingPartials::compute::<C, R, B>(
            self.params,
            &lifts,
            is_base_case,
        );
        let binding = partials.binding;

        let u = bound_challenges[native::circuits::bind_challenges::NUM_BOUND - 1];
        let u_nested = nested::challenge::<C>(u)?;

        // ProofBuilder contains OnceCell fields and is therefore !Sync.
        // Extract shared references to the already-set polynomials so the
        // closures below capture &Polynomial (which is Sync) rather than
        // &ProofBuilder.
        let native_a_poly = builder.native_a_poly();
        let native_b_poly = builder.native_b_poly();
        let native_registry_xy_poly = builder.native_registry_xy_poly();
        let nested_a_poly = builder.nested_a_poly();
        let nested_b_poly = builder.nested_b_poly();
        let nested_registry_xy_poly = builder.nested_registry_xy_poly();

        // Evaluate left/right child witnesses concurrently with the
        // current-step polynomial evaluations at u.
        let (left_witness, right_witness, current) = par_join!(
            || native::stages::eval::ChildEvaluationsWitness::from_proof::<C, R, B>(left, u),
            || native::stages::eval::ChildEvaluationsWitness::from_proof::<C, R, B>(right, u),
            || native::stages::eval::CurrentStepWitness {
                registry_wx0: B::sparse_eval(&s_prime.registry_wx0_poly, u),
                registry_wx1: B::sparse_eval(&s_prime.registry_wx1_poly, u),
                registry_wy: B::sparse_eval(&registry_wy.poly, u),
                a_poly: B::sparse_eval(native_a_poly, u),
                b_poly: B::sparse_eval(native_b_poly, u),
                registry_xy: B::sparse_eval(native_registry_xy_poly, u),
            },
        );

        let native = native::stages::eval::Witness {
            left: left_witness,
            right: right_witness,
            current,
            partials,
        };

        let (left_nested, right_nested, current_nested) = par_join!(
            || nested::stages::eval::ChildEvaluationsWitness::from_proof::<C, R, B>(left, u_nested),
            || nested::stages::eval::ChildEvaluationsWitness::from_proof::<C, R, B>(
                right, u_nested
            ),
            || nested::stages::eval::CurrentStepWitness {
                registry_wx0: B::sparse_eval(&nested_s_prime.registry_wx0_poly, u_nested),
                registry_wx1: B::sparse_eval(&nested_s_prime.registry_wx1_poly, u_nested),
                registry_wy: B::sparse_eval(&nested_registry_wy.poly, u_nested),
                a_poly: B::sparse_eval(nested_a_poly, u_nested),
                b_poly: B::sparse_eval(nested_b_poly, u_nested),
                registry_xy: B::sparse_eval(nested_registry_xy_poly, u_nested),
            },
        );

        let nested = nested::stages::eval::Evaluations {
            left: left_nested,
            right: right_nested,
            current: current_nested,
        };

        Ok((native, nested, binding))
    }

    /// Samples fresh eval-stage blindings and returns the native eval rx
    /// together with the `eval` bridge stage's rx and commitment.
    ///
    /// The `pre_beta` rejection loop calls this once per attempt, re-deriving
    /// the challenge from a fresh commitment until it lands in range. Only the
    /// accepted rxs are committed to the builder, so this computes the
    /// commitments without populating any builder cell.
    pub(super) fn sample_eval_commitment<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        eval_witness: &native::stages::eval::Witness<C>,
        nested_eval: &nested::stages::eval::Evaluations<C::ScalarField>,
    ) -> Result<(
        sparse::Polynomial<C::CircuitField, R>,
        sparse::Polynomial<C::ScalarField, R>,
        C::NestedCurve,
    )> {
        let eval_rx = native::stages::eval::Stage::<C, R, HEADER_SIZE>::rx(
            C::CircuitField::random(&mut *rng),
            eval_witness,
        )?;
        let native_eval_commitment =
            B::sparse_commit_to_affine(&eval_rx, C::host_generators(self.params));

        let bridge_rx = nested::stages::eval::Stage::<C::HostCurve, R>::rx(
            C::ScalarField::random(&mut *rng),
            &nested::stages::eval::Witness {
                native_eval: native_eval_commitment,
                nested: nested_eval.clone(),
            },
        )?;
        let bridge_eval_commitment =
            B::sparse_commit_to_affine(&bridge_rx, C::nested_generators(self.params));

        Ok((eval_rx, bridge_rx, bridge_eval_commitment))
    }
}

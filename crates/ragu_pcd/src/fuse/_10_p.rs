//! Accumulate $p(X)$.
//!
//! This sets the $p(X)$ polynomial field on the [`ProofBuilder`], containing
//! the accumulated polynomial and its claimed evaluation $p(u) = v$.
//!
//! The commitment is derived as a linear combination of all constituent
//! polynomial commitments using additive homomorphism:
//! $\text{commit}(\sum\_j \beta^j \cdot p\_j) = \sum\_j \beta^j \cdot C\_j$.
//!
//! The commitment is computed via
//! [`PointsWitness`](crate::internal::endoscalar::PointsWitness)
//! Horner evaluation.
//!
//! The nested batch is accumulated the same way into $p_n(X)$, with
//! $\beta_n$ the scalar-field lift of the same endoscalar bits. Its
//! nested-curve commitment $P_n$ is the Horner walk over the batch's
//! nested-curve commitments, performed by the native endoscaling steps over
//! the points inputs stage committed before $\beta$ (see
//! [`prepare_native_points`](crate::Application::prepare_native_points)).

use alloc::vec::Vec;
use core::ops::AddAssign;

use ragu_arithmetic::{Cycle, ff::Field};
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::Result;
use ragu_primitives::{EndoscalarChallenge, lift_endoscalar};

use super::{
    NativeF, NativeFuseEmulator, NativeSPrime, NestedF, NestedRegistryWy, NestedSPrime, RegistryWy,
};
use crate::{
    Application, Proof,
    internal::{
        endoscalar::PointsWitness,
        native::{
            self, RxComponent, RxIndex,
            stages::points::{InputsWitness, InterstitialsWitness},
        },
        nested::{NUM_ENDOSCALING_POINTS, pcs},
    },
    proof::ProofBuilder,
};

/// The native points inputs witness: the nested batch's commitments.
pub(super) type NativeInputs<C> =
    InputsWitness<<C as Cycle>::NestedCurve, { native::NUM_ENDOSCALING_POINTS }>;

/// The native points interstitials witness: the walk's outputs.
pub(super) type NativeInterstitials<C> =
    InterstitialsWitness<<C as Cycle>::NestedCurve, { native::NUM_ENDOSCALING_POINTS }>;

/// Accumulates polynomials with their commitments.
struct Accumulator<'a, C: Cycle, R: Rank> {
    poly: &'a mut sparse::Polynomial<C::CircuitField, R>,
    commitments: &'a mut Vec<C::HostCurve>,
    beta: C::CircuitField,
}

impl<C: Cycle, R: Rank> Accumulator<'_, C, R> {
    fn acc<P>(&mut self, poly: &P, commitment: C::HostCurve)
    where
        for<'p> sparse::Polynomial<C::CircuitField, R>: AddAssign<&'p P>,
    {
        self.poly.scale(self.beta);
        *self.poly += poly;
        self.commitments.push(commitment);
    }
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// Commits the native points inputs stage over the nested batch's
    /// commitments, $f_n$'s first, in [`pcs::Batch::evaluated`] order. Runs
    /// before the `eval` bridge is absorbed, so that the points $P_n$ is
    /// walked over are fixed before $\beta$ is squeezed.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn prepare_native_points<RNG: ragu_arithmetic::rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        nested_f: &NestedF<C, R>,
        nested_s_prime: &NestedSPrime<C, R>,
        nested_registry_wy: &NestedRegistryWy<C, R>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<NativeInputs<C>> {
        let batch = self.nested_batch(builder, nested_s_prime, nested_registry_wy, left, right);
        let current = pcs::CurrentCommitments {
            registry_wx0: nested_s_prime.registry_wx0_commitment,
            registry_wx1: nested_s_prime.registry_wx1_commitment,
            registry_wy: nested_registry_wy.commitment,
            a: builder.nested_a_commitment(),
            b: builder.nested_b_commitment(),
            registry_xy: builder.nested_registry_xy_commitment(),
        };
        let points: Vec<C::NestedCurve> = core::iter::once(nested_f.commitment)
            .chain(batch.commitments(current))
            .collect();
        assert_eq!(points.len(), pcs::NUM_BATCHED_POINTS);
        self.commit_native_points_inputs(rng, &points, builder)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn compute_p<'dr, RNG: ragu_arithmetic::rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        pre_beta: &EndoscalarChallenge<'dr, NativeFuseEmulator<C>>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        s_prime: &NativeSPrime<C, R>,
        registry_wy: &RegistryWy<C, R>,
        f: &NativeF<C, R>,
        nested_s_prime: &NestedSPrime<C, R>,
        nested_registry_wy: &NestedRegistryWy<C, R>,
        nested_f: &NestedF<C, R>,
        native_points: &NativeInputs<C>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<(
        PointsWitness<C::HostCurve, NUM_ENDOSCALING_POINTS>,
        NativeInterstitials<C>,
    )> {
        // Extract endoscalar from pre_beta and compute effective beta. Going
        // through the validated `EndoscalarChallenge` makes the
        // `value < 2^CAPACITY` precondition a type invariant rather than an
        // unchecked argument to `extract_endoscalar`.
        let beta_endo = pre_beta.extract_native();

        let points = self.compute_native_p(
            rng,
            beta_endo,
            left,
            right,
            s_prime,
            registry_wy,
            f,
            builder,
        )?;
        let native_interstitials = self.compute_nested_p(
            rng,
            beta_endo,
            left,
            right,
            nested_s_prime,
            nested_registry_wy,
            nested_f,
            native_points,
            builder,
        )?;

        Ok((points, native_interstitials))
    }

    fn compute_native_p<RNG: ragu_arithmetic::rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        beta_endo: u128,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        s_prime: &NativeSPrime<C, R>,
        registry_wy: &RegistryWy<C, R>,
        f: &NativeF<C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<PointsWitness<C::HostCurve, NUM_ENDOSCALING_POINTS>> {
        let mut poly = f.poly.clone();

        // Collect commitments for PointsWitness construction.
        let mut commitments: Vec<C::HostCurve> = Vec::new();

        // The orderings in this code must match the `Write` serialization
        // order of `native::stages::eval::Output`.
        //
        // We accumulate polynomials while collecting MSM terms for the
        // commitment computation.
        let effective_beta = lift_endoscalar(beta_endo);

        {
            let mut acc: Accumulator<'_, C, R> = Accumulator {
                poly: &mut poly,
                commitments: &mut commitments,
                beta: effective_beta,
            };

            for proof in [left, right] {
                for &id in &RxIndex::ALL {
                    acc.acc(&proof[id], proof.native_rx_commitment(id));
                }
                acc.acc(
                    &proof[RxComponent::AbA],
                    proof.native_commitment(RxComponent::AbA),
                );
                acc.acc(
                    &proof[RxComponent::AbB],
                    proof.native_commitment(RxComponent::AbB),
                );
                acc.acc(
                    proof.native_registry_xy_poly(),
                    proof.native_registry_xy_commitment(),
                );
                acc.acc(proof.native_p_poly(), proof.native_p_commitment());
            }

            acc.acc(&s_prime.registry_wx0_poly, s_prime.registry_wx0_commitment);
            acc.acc(&s_prime.registry_wx1_poly, s_prime.registry_wx1_commitment);
            acc.acc(&registry_wy.poly, registry_wy.commitment);
            acc.acc(builder.native_a_poly(), builder.native_a_commitment());
            acc.acc(builder.native_b_poly(), builder.native_b_commitment());
            acc.acc(
                builder.native_registry_xy_poly(),
                builder.native_registry_xy_commitment(),
            );
        }

        // Build the PointsStage input vector ([f.commitment, commitments..])
        // and delegate to the shared endoscaling helper, which also
        // sets `nested_endoscalar_rx`, `nested_points_rx`, and
        // `nested_endoscaling_step_rxs` on the builder.
        let mut points = Vec::with_capacity(NUM_ENDOSCALING_POINTS);
        points.push(f.commitment);
        points.extend_from_slice(&commitments);

        let endoscalar_alpha = C::ScalarField::random(&mut *rng);
        let points_alpha = C::ScalarField::random(&mut *rng);
        let (p_commitment, points) = self.compute_endoscaling(
            rng,
            beta_endo,
            &points,
            endoscalar_alpha,
            points_alpha,
            builder,
        )?;

        builder.set_native_p_poly(poly, p_commitment);

        Ok(points)
    }

    /// Accumulates the nested batch into $p_n(X)$, in [`pcs::Batch::evaluated`]
    /// order after $f_n$, and runs the native endoscaling over the committed
    /// points: $P_n$ is the walk's last interstitial, which the native steps
    /// enforce.
    #[allow(clippy::too_many_arguments)]
    fn compute_nested_p<RNG: ragu_arithmetic::rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        beta_endo: u128,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        nested_s_prime: &NestedSPrime<C, R>,
        nested_registry_wy: &NestedRegistryWy<C, R>,
        nested_f: &NestedF<C, R>,
        native_points: &NativeInputs<C>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<NativeInterstitials<C>> {
        let beta: C::ScalarField = lift_endoscalar(beta_endo);
        let batch = self.nested_batch(builder, nested_s_prime, nested_registry_wy, left, right);

        let mut poly = nested_f.poly.clone();
        for evaluated in batch.evaluated() {
            poly.scale(beta);
            poly.add_assign(evaluated);
        }

        let (p_commitment, interstitials) =
            self.compute_native_endoscaling(rng, beta_endo, native_points, builder)?;
        debug_assert_eq!(
            B::sparse_commit_to_affine(&poly, C::nested_generators(self.params)),
            p_commitment,
            "nested P must be the Horner walk over the batch's commitments"
        );
        builder.set_nested_p_poly(poly, p_commitment);

        Ok(interstitials)
    }
}

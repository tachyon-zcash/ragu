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

use alloc::vec::Vec;
use core::ops::AddAssign;

use ragu_arithmetic::{Cycle, ff::Field};
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::{Element, extract_endoscalar, lift_endoscalar};

use super::{NativeF, NativeSPrime, RegistryWy};
use crate::{
    Application, Proof,
    framework_hooks::HookConfig,
    internal::{
        native::{RxComponent, RxIndex},
        nested::num_endoscaling_points,
    },
    proof::ProofBuilder,
};

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

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, J: HookConfig>
    Application<'_, C, R, HEADER_SIZE, J>
{
    pub(super) fn compute_p<'dr, D, RNG: ragu_arithmetic::CryptoRngCore>(
        &self,
        rng: &mut RNG,
        pre_beta: &Element<'dr, D>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        s_prime: &NativeSPrime<C, R>,
        registry_wy: &RegistryWy<C, R>,
        f: &NativeF<C, R>,
        builder: &mut ProofBuilder<'_, C, R, J>,
    ) -> Result<()>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let mut poly = f.poly.clone();

        // Collect commitments for PointsWitness construction.
        let mut commitments: Vec<C::HostCurve> = Vec::new();

        // The orderings in this code must match the `Write` serialization
        // order of `native::stages::eval::Output`.
        //
        // We accumulate polynomials while collecting MSM terms for the
        // commitment computation.

        // Extract endoscalar from pre_beta and compute effective beta
        let pre_beta_value = *pre_beta.value().take();
        let beta_endo = extract_endoscalar(pre_beta_value);
        let effective_beta = lift_endoscalar(beta_endo);

        {
            let mut acc: Accumulator<'_, C, R> = Accumulator {
                poly: &mut poly,
                commitments: &mut commitments,
                beta: effective_beta,
            };

            for proof in [left, right] {
                // `RxIndex::ALL` is the one order the eval stage's `Write`
                // impl, `loading`'s point walk, and this accumulation follow.
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
                for (poly, commitment) in proof
                    .witness_polys()
                    .iter()
                    .zip(proof.witness_poly_commitments())
                {
                    acc.acc(poly, commitment);
                }
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
        let mut points =
            Vec::with_capacity(num_endoscaling_points(self.hook_layout().witness_polys));
        points.push(f.commitment);
        points.extend_from_slice(&commitments);

        let endoscalar_alpha = C::ScalarField::random(&mut *rng);
        let points_alpha = C::ScalarField::random(&mut *rng);
        let p_commitment = self.compute_endoscaling(
            rng,
            beta_endo,
            &points,
            endoscalar_alpha,
            points_alpha,
            builder,
        )?;

        builder.set_native_p_poly(poly, p_commitment);

        Ok(())
    }
}

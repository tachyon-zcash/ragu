//! Commit to $m(w, x_i, Y)$ polynomials for the child proofs.
//!
//! This sets the s-prime fields on the [`ProofBuilder`], which commits to the
//! $m(w, x_i, Y)$ polynomials for the $i$th child proof's $x$ challenge. The
//! `s_prime` bridge also carries the commitments of the native preamble stage
//! and of the step's own application trace, so both are fixed before $y$, at
//! which the step folds its application claim.
//!
//! The nested registry's restrictions $m_n(w_n, x_{i,n}, Y)$ are computed
//! here as well, at the nested counterparts of the same challenges. Their
//! nested-curve commitments are committed in the native points stage the
//! endoscaling walk reads them from, whose commitment the `s_prime` bridge
//! carries, so they are fixed before $y$ is squeezed.

use ragu_circuits::{
    Blind,
    polynomials::{Rank, sparse},
    registry::RegistryAt,
    staging::StageExt,
};
use ragu_core::{Cycle, Result};
use rand::CryptoRng;
use udon::curve::Affine;

use super::{_01_application::NativeApplication, randomizer::Randomizers};
use crate::{
    Application, Proof,
    internal::{native::stages::points as native_points, nested},
    profile::ProfiledCycle,
    proof::ProofBuilder,
};

/// Ephemeral native-field data for $s'(X)$, used only during the fuse step.
pub(super) struct NativeSPrime<C: Cycle, R: Rank> {
    pub(super) registry_wx0_poly: sparse::Polynomial<C::CircuitField, R>,
    pub(super) registry_wx0_commitment: C::HostCurve,
    pub(super) registry_wx1_poly: sparse::Polynomial<C::CircuitField, R>,
    pub(super) registry_wx1_commitment: C::HostCurve,
}

/// Ephemeral nested-field data for the $m_n(w_n, x_{i,n}, Y)$ restrictions,
/// used only during the fuse step.
pub(super) struct NestedSPrime<C: Cycle, R: Rank> {
    pub(super) registry_wx0_poly: sparse::Polynomial<C::ScalarField, R>,
    pub(super) registry_wx0_commitment: C::NestedCurve,
    pub(super) registry_wx1_poly: sparse::Polynomial<C::ScalarField, R>,
    pub(super) registry_wx1_commitment: C::NestedCurve,
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    pub(super) fn compute_s_prime<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        native_registry: &RegistryAt<'_, C::CircuitField, R>,
        nested_registry: &RegistryAt<'_, C::ScalarField, R>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        application: &NativeApplication<C, R>,
        randomizers: &Randomizers<C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<(NativeSPrime<C, R>, NestedSPrime<C, R>)> {
        let native = self.compute_native_s_prime(native_registry, left, right)?;
        let nested = self.compute_nested_s_prime(nested_registry, left, right)?;
        // The fold randomizers are fixed here, each side's commitments in
        // the other side's stage, before the challenges of the fold.
        self.commit_native_points_registry_wx(
            rng,
            nested.registry_wx0_commitment,
            nested.registry_wx1_commitment,
            [
                randomizers.nested.a_commitment,
                randomizers.nested.b_commitment,
            ],
            builder,
        )?;
        self.compute_bridge_s_prime(rng, &native, application, randomizers, builder)?;
        Ok((native, nested))
    }

    fn compute_bridge_s_prime<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        native: &NativeSPrime<C, R>,
        application: &NativeApplication<C, R>,
        randomizers: &Randomizers<C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        let bridge_rx = nested::stages::s_prime::Stage::<C::HostCurve, R, C::Profile>::rx(
            Blind::random(rng),
            &nested::stages::s_prime::Witness {
                online_points: builder.native_online_phase::<1>(),
                registry_wx0: native.registry_wx0_commitment,
                registry_wx1: native.registry_wx1_commitment,
                native_preamble: builder.native_preamble_commitment(),
                native_application: application.commitment,
                native_points_registry_wx: builder.native_points_registry_wx_commitment(),
                randomizer_a: randomizers.native.a_commitment,
                randomizer_b: randomizers.native.b_commitment,
            },
        )?;
        let bridge_commitment = self.nested().commit(&bridge_rx);
        builder.set_bridge_s_prime_rx(bridge_rx, bridge_commitment);
        Ok(())
    }

    fn compute_native_s_prime(
        &self,
        native_registry: &RegistryAt<'_, C::CircuitField, R>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
    ) -> Result<NativeSPrime<C, R>> {
        let x0 = left.x();
        let x1 = right.x();

        let registry_wx0_poly = B::registry_at_x(native_registry, x0);
        let registry_wx1_poly = B::registry_at_x(native_registry, x1);
        let mut commitments = [<C::HostCurve as Affine>::identity(); 2];
        <C::HostCurve as Affine>::batch_to_affine(
            &self
                .host()
                .commit_batch([&registry_wx0_poly, &registry_wx1_poly]),
            &mut commitments,
        );
        let [registry_wx0_commitment, registry_wx1_commitment] = commitments;

        Ok(NativeSPrime {
            registry_wx0_poly,
            registry_wx0_commitment,
            registry_wx1_poly,
            registry_wx1_commitment,
        })
    }

    fn compute_nested_s_prime(
        &self,
        nested_registry: &RegistryAt<'_, C::ScalarField, R>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
    ) -> Result<NestedSPrime<C, R>> {
        let x0 = nested::challenge::<C>(left.x())?;
        let x1 = nested::challenge::<C>(right.x())?;

        let registry_wx0_poly = B::registry_at_x(nested_registry, x0);
        let registry_wx1_poly = B::registry_at_x(nested_registry, x1);
        let mut commitments = [<C::NestedCurve as Affine>::identity(); 2];
        <C::NestedCurve as Affine>::batch_to_affine(
            &self
                .nested()
                .commit_batch([&registry_wx0_poly, &registry_wx1_poly]),
            &mut commitments,
        );
        let [registry_wx0_commitment, registry_wx1_commitment] = commitments;

        Ok(NestedSPrime {
            registry_wx0_poly,
            registry_wx0_commitment,
            registry_wx1_poly,
            registry_wx1_commitment,
        })
    }

    /// Commits the native points stage holding the nested `registry_wx`
    /// commitments, before $y$ is squeezed; the `s_prime` bridge carries its
    /// commitment.
    pub(crate) fn commit_native_points_registry_wx<RNG: rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        registry_wx0: C::NestedCurve,
        registry_wx1: C::NestedCurve,
        randomizer: [C::NestedCurve; 2],
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        let witness = native_points::RegistryWxWitness {
            online_points: builder.nested_online_phase::<1>(),
            registry_wx0,
            registry_wx1,
            randomizer_a: randomizer[0],
            randomizer_b: randomizer[1],
        };
        builder.set_native_points_registry_wx_rx(<native_points::RegistryWxStage<
            C::NestedCurve,
            C::Profile,
        > as StageExt<C::CircuitField, R>>::rx(
            Blind::random(rng), &witness
        )?);
        Ok(())
    }
}

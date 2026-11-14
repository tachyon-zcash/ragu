//! Commit to $m(w, x_i, Y)$ polynomials for the child proofs.
//!
//! This sets the s-prime fields on the [`ProofBuilder`], which commits to the
//! $m(w, x_i, Y)$ polynomials for the $i$th child proof's $x$ challenge.
//!
//! The nested registry's restrictions $m_n(w_n, x_{i,n}, Y)$ are computed
//! here as well, at the nested counterparts of the same challenges. Their
//! nested-curve commitments are committed in the native points stage the
//! endoscaling walk reads them from, whose commitment the `s_prime` bridge
//! carries, so they are fixed before $y$ is squeezed.

use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::RegistryAt,
    staging::StageExt,
};
use ragu_core::{Cycle, FixedGenerators, Result};
use rand::CryptoRng;
use udon::{curve::Affine, field::Field};

use super::device::{Devices, registry_x};
use crate::{
    Application, Proof, internal::nested, multicore::par_join, profile::ProfiledCycle,
    proof::ProofBuilder, timing::span,
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
        devices: &mut Devices<'_, C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<(NativeSPrime<C, R>, NestedSPrime<C, R>)> {
        // The four restrictions are independent of each other and of the
        // builder, so they run together; their commitments follow in order.
        let (x0, x1) = (left.x(), right.x());
        let (nested_x0, nested_x1) = (nested::challenge::<C>(x0)?, nested::challenge::<C>(x1)?);
        // A side with a device that holds its registry's wiring matrices
        // restricts there; otherwise the host does, both points together.
        let (native_device, nested_device) =
            (devices.native.as_deref_mut(), devices.nested.as_deref_mut());
        let (native_wired, nested_wired) =
            (devices.native_wired.take(), devices.nested_wired.take());
        let (host_generators, nested_generators) = (
            C::host_generators(self.params),
            C::nested_generators(self.params),
        );
        let (
            ([native_wx0, native_wx1], native_commitments),
            ([nested_wx0, nested_wx1], nested_commitments),
        ) = span("sp.registry_x", || {
            par_join!(
                || native_device
                    .and_then(|device| registry_x::<B, C::HostCurve, R, _, 2>(
                        device,
                        native_registry,
                        [x0, x1],
                        native_wired.as_ref(),
                        host_generators,
                    ))
                    .unwrap_or_else(|| {
                        let (wx0, wx1) =
                            par_join!(|| B::registry_at_x(native_registry, x0), || {
                                B::registry_at_x(native_registry, x1)
                            },);
                        ([wx0, wx1], None)
                    }),
                || nested_device
                    .and_then(|device| registry_x::<B, C::NestedCurve, R, _, 2>(
                        device,
                        nested_registry,
                        [nested_x0, nested_x1],
                        nested_wired.as_ref(),
                        nested_generators,
                    ))
                    .unwrap_or_else(|| {
                        let (wx0, wx1) =
                            par_join!(|| B::registry_at_x(nested_registry, nested_x0), || {
                                B::registry_at_x(nested_registry, nested_x1)
                            },);
                        ([wx0, wx1], None)
                    }),
            )
        });
        // The two sides' commitments are independent, and on different
        // curves. A side whose device restricted has committed already.
        let (native, nested) = span("sp.commit", || {
            par_join!(
                || Self::compute_native_s_prime(
                    host_generators,
                    native_wx0,
                    native_wx1,
                    native_commitments
                ),
                || Self::compute_nested_s_prime(
                    nested_generators,
                    nested_wx0,
                    nested_wx1,
                    nested_commitments
                ),
            )
        });
        span("sp.points", || {
            self.commit_native_points_registry_wx(
                rng,
                nested.registry_wx0_commitment,
                nested.registry_wx1_commitment,
                builder,
            )
        })?;
        span("sp.bridge", || {
            self.compute_bridge_s_prime(rng, &native, builder)
        })?;
        Ok((native, nested))
    }

    fn compute_bridge_s_prime<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        native: &NativeSPrime<C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        let bridge_rx = nested::stages::s_prime::Stage::<C::HostCurve, R, C::Profile>::rx(
            C::ScalarField::random(|bytes| rng.fill_bytes(bytes)),
            &nested::stages::s_prime::Witness {
                registry_wx0: native.registry_wx0_commitment,
                registry_wx1: native.registry_wx1_commitment,
                native_points_registry_wx: builder.native_points_registry_wx_commitment(),
            },
        )?;
        let bridge_commitment =
            B::sparse_commit_to_affine(&bridge_rx, C::nested_generators(self.params));
        builder.set_bridge_s_prime_rx(bridge_rx, bridge_commitment);
        Ok(())
    }

    fn compute_native_s_prime(
        host_gen: &impl FixedGenerators<C::HostCurve>,
        registry_wx0_poly: sparse::Polynomial<C::CircuitField, R>,
        registry_wx1_poly: sparse::Polynomial<C::CircuitField, R>,
        known: Option<[C::HostCurve; 2]>,
    ) -> NativeSPrime<C, R> {
        let [registry_wx0_commitment, registry_wx1_commitment] = known.unwrap_or_else(|| {
            let mut commitments = [<C::HostCurve as Affine>::identity(); 2];
            <C::HostCurve as Affine>::batch_to_affine(
                &B::sparse_commit_batch([&registry_wx0_poly, &registry_wx1_poly], host_gen),
                &mut commitments,
            );
            commitments
        });

        NativeSPrime {
            registry_wx0_poly,
            registry_wx0_commitment,
            registry_wx1_poly,
            registry_wx1_commitment,
        }
    }

    fn compute_nested_s_prime(
        nested_gen: &impl FixedGenerators<C::NestedCurve>,
        registry_wx0_poly: sparse::Polynomial<C::ScalarField, R>,
        registry_wx1_poly: sparse::Polynomial<C::ScalarField, R>,
        known: Option<[C::NestedCurve; 2]>,
    ) -> NestedSPrime<C, R> {
        let [registry_wx0_commitment, registry_wx1_commitment] = known.unwrap_or_else(|| {
            let mut commitments = [<C::NestedCurve as Affine>::identity(); 2];
            <C::NestedCurve as Affine>::batch_to_affine(
                &B::sparse_commit_batch([&registry_wx0_poly, &registry_wx1_poly], nested_gen),
                &mut commitments,
            );
            commitments
        });

        NestedSPrime {
            registry_wx0_poly,
            registry_wx0_commitment,
            registry_wx1_poly,
            registry_wx1_commitment,
        }
    }
}

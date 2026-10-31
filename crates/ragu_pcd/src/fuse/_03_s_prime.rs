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

use ragu_backend::Backend;
use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::RegistryAt,
    staging::StageExt,
};
use ragu_core::{Cycle, FixedGenerators, Result};
use rand::CryptoRng;
use udon::{curve::Affine, field::Field};

use crate::{Application, Proof, internal::nested, profile::ProfiledCycle, proof::ProofBuilder};

/// Registry restrictions at the two child evaluation points and their
/// commitments, over either side's scalar field and commitment curve.
pub(super) struct SPrime<G: Affine, R: Rank> {
    pub(super) registry_wx0_poly: sparse::Polynomial<G::Scalar, R>,
    pub(super) registry_wx0_commitment: G,
    pub(super) registry_wx1_poly: sparse::Polynomial<G::Scalar, R>,
    pub(super) registry_wx1_commitment: G,
}

/// Ephemeral native-field data, committed on the host curve.
pub(super) type NativeSPrime<C, R> = SPrime<<C as Cycle>::HostCurve, R>;

/// Ephemeral nested-field data, committed on the nested curve.
pub(super) type NestedSPrime<C, R> = SPrime<<C as Cycle>::NestedCurve, R>;

impl<G: Affine, R: Rank> SPrime<G, R> {
    /// Compute both restrictions using challenges already in this curve's
    /// scalar field. Challenge conversion and bridge commitments belong to
    /// the caller's orchestration of the two sides.
    fn compute<B: Backend>(
        registry: &RegistryAt<'_, G::Scalar, R>,
        [x0, x1]: [G::Scalar; 2],
        generators: &impl FixedGenerators<G>,
    ) -> Self {
        let registry_wx0_poly = B::registry_at_x(registry, x0);
        let registry_wx1_poly = B::registry_at_x(registry, x1);
        let mut commitments = [G::identity(); 2];
        G::batch_to_affine(
            &B::sparse_commit_batch([&registry_wx0_poly, &registry_wx1_poly], generators),
            &mut commitments,
        );
        let [registry_wx0_commitment, registry_wx1_commitment] = commitments;

        Self {
            registry_wx0_poly,
            registry_wx0_commitment,
            registry_wx1_poly,
            registry_wx1_commitment,
        }
    }
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
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<(NativeSPrime<C, R>, NestedSPrime<C, R>)> {
        let native = NativeSPrime::<C, R>::compute::<B>(
            native_registry,
            [left.x(), right.x()],
            C::host_generators(self.params),
        );
        let nested = NestedSPrime::<C, R>::compute::<B>(
            nested_registry,
            [
                nested::challenge::<C>(left.x())?,
                nested::challenge::<C>(right.x())?,
            ],
            C::nested_generators(self.params),
        );
        self.commit_native_points_registry_wx(
            rng,
            nested.registry_wx0_commitment,
            nested.registry_wx1_commitment,
            builder,
        )?;
        self.compute_bridge_s_prime(rng, &native, builder)?;
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
}

//! Bridge s-prime prover phase.
use ragu_circuits::{polynomials::Rank, registry::RegistryAt, staging::StageExt};
use ragu_core::Result;
use rand::CryptoRng;
use udon::field::Field;

use crate::{Application, fuse::prover::proof_builder::ProofBuilder, profile::ProfiledCycle};

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    pub(in crate::fuse::prover) fn compute_s_prime<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        native_registry: &RegistryAt<'_, C::CircuitField, R>,
        nested_registry: &RegistryAt<'_, C::ScalarField, R>,
        native: &NativeSideFuse<'_, '_, C, R>,
        nested: &NestedSideFuse<'_, '_, C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<(NativeSPrime<C, R>, NestedSPrime<C, R>)> {
        let native = native.s_prime::<B>(native_registry)?;
        let nested = nested.s_prime::<B>(nested_registry)?;
        self.commit_native_points_registry_wx(
            rng,
            nested.registry_wx0_commitment,
            nested.registry_wx1_commitment,
            builder,
        )?;
        self.compute_bridge_s_prime(rng, &native, builder)?;
        Ok((native, nested))
    }

    pub(in crate::fuse::prover) fn compute_bridge_s_prime<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        native: &NativeSPrime<C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        let bridge_rx =
            crate::protocol::nested::stages::s_prime::Stage::<C::HostCurve, R, C::Profile>::rx(
                C::ScalarField::random(|bytes| rng.fill_bytes(bytes)),
                &crate::protocol::nested::stages::s_prime::Witness {
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

use crate::fuse::prover::{
    native::s_prime::NativeSPrime,
    nested::s_prime::NestedSPrime,
    side::{CurveSideFuse, NativeSideFuse, NestedSideFuse},
};

//! Bridge inner-error prover phase.
use ragu_circuits::{polynomials::Rank, registry::RegistryAt, staging::StageExt};
use ragu_core::{Result, drivers::Driver};
use ragu_primitives::{Element, vec::FixedVec};
use rand::CryptoRng;
use udon::field::Field;

use crate::{
    Application,
    profile::ProfiledCycle,
    protocol::{
        fold_revdot::{NumErrorTerms, Parameters},
        native, nested,
    },
    prover::{
        fuse::claims::{NativeFuseBuilder, NestedFuseBuilder},
        proof_builder::ProofBuilder,
    },
};

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    pub(in crate::prover::fuse) fn inner_error_terms<'m, 'dr, 'rx, D, RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        native_registry: &RegistryAt<'_, C::CircuitField, R>,
        nested_registry: &RegistryAt<'_, C::ScalarField, R>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        native_fuser: &NativeSideFuse<'m, 'rx, C, R>,
        nested_fuser: &NestedSideFuse<'m, 'rx, C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<(
        crate::verifier::recursive::native::stages::inner_error::Witness<
            C,
            native::RevdotParameters<C::Profile>,
        >,
        NativeFuseBuilder<'m, 'rx, C::CircuitField, R, B>,
        RegistryWy<C, R>,
        crate::verifier::recursive::nested::stages::inner_error::Witness<C::HostCurve, C::Profile>,
        NestedFuseBuilder<'m, 'rx, C::ScalarField, R, B>,
        NestedRegistryWy<C, R>,
    )>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let (native_inner_error_witness, native_claims, registry_wy) =
            self.compute_native_inner_error(rng, native_registry, y, z, native_fuser, builder)?;
        let (nested_inner_error_terms, nested_claims, nested_registry_wy) =
            self.compute_nested_inner_error(nested_registry, y, z, nested_fuser)?;
        let nested_inner_error_witness =
            self.compute_bridge_inner_error(rng, &registry_wy, nested_inner_error_terms, builder)?;
        Ok((
            native_inner_error_witness,
            native_claims,
            registry_wy,
            nested_inner_error_witness,
            nested_claims,
            nested_registry_wy,
        ))
    }

    /// Commits the nested fold's inner error terms alongside the native
    /// inner-error and registry commitments in the bridge stage.
    pub(in crate::prover::fuse) fn compute_bridge_inner_error<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        registry_wy: &RegistryWy<C, R>,
        error_terms: FixedVec<
            FixedVec<
                C::ScalarField,
                NumErrorTerms<<nested::RevdotParameters<C::Profile> as Parameters>::GroupSize>,
            >,
            <nested::RevdotParameters<C::Profile> as Parameters>::NumGroups,
        >,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<
        crate::verifier::recursive::nested::stages::inner_error::Witness<C::HostCurve, C::Profile>,
    > {
        let nested_inner_error_witness =
            crate::verifier::recursive::nested::stages::inner_error::Witness {
                native_inner_error: builder.native_inner_error_commitment(),
                registry_wy: registry_wy.commitment,
                error_terms,
            };
        let bridge_rx = crate::verifier::recursive::nested::stages::inner_error::Stage::<
            C::HostCurve,
            R,
            C::Profile,
        >::rx(
            C::ScalarField::random(|bytes| rng.fill_bytes(bytes)),
            &nested_inner_error_witness,
        )?;
        let bridge_commitment =
            B::sparse_commit_to_affine(&bridge_rx, C::nested_generators(self.params));
        builder.set_bridge_inner_error_rx(bridge_rx, bridge_commitment);

        Ok(nested_inner_error_witness)
    }
}

use crate::prover::fuse::{
    native::inner_error::RegistryWy,
    nested::inner_error::NestedRegistryWy,
    side::{NativeSideFuse, NestedSideFuse},
};

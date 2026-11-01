//! Commit to the quotient error terms of the first revdot folding layer.
//!
//! This sets the inner-error fields on the [`ProofBuilder`], which commits to
//! the `inner_error` stage.
//!
//! The children's nested claims are folded here as well: their layer-1 error
//! terms ride inside the `inner_error` bridge stage, so they are committed
//! before the first-layer folding challenge is squeezed.
//!
//! This phase of the fuse operation is also used to commit to the $m(w, X, y)$
//! restriction; its nested counterpart's commitment enters the native
//! points stage committed before $x$ (see `_06_ab`).

use ragu_circuits::{polynomials::Rank, registry::RegistryAt, staging::StageExt};
use ragu_core::{Cycle, Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::{Element, vec::FixedVec};
use rand::CryptoRng;
use udon::field::Field;

use super::{
    claims::{NativeFuseBuilder, NestedFuseBuilder},
    side::{CurveSideFuse, NativeSideFuse, NestedSideFuse, RegistryRestriction},
};
use crate::{
    Application,
    internal::{
        fold_revdot::{NumErrorTerms, Parameters},
        native, nested,
    },
    profile::ProfiledCycle,
    proof::ProofBuilder,
};

/// Ephemeral $m(w, X, y)$ registry restriction, used only during the fuse step.
pub(super) type RegistryWy<C, R> = RegistryRestriction<<C as Cycle>::HostCurve, R>;

/// The nested registry restriction, committed on the nested curve.
pub(super) type NestedRegistryWy<C, R> = RegistryRestriction<<C as Cycle>::NestedCurve, R>;

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    pub(super) fn inner_error_terms<'m, 'dr, 'rx, D, RNG: CryptoRng>(
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
        native::stages::inner_error::Witness<C, native::RevdotParameters<C::Profile>>,
        NativeFuseBuilder<'m, 'rx, C::CircuitField, R, B>,
        RegistryWy<C, R>,
        nested::stages::inner_error::Witness<C::HostCurve, C::Profile>,
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

    fn compute_native_inner_error<'m, 'dr, 'rx, D, RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        native_registry: &RegistryAt<'_, C::CircuitField, R>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        native_fuser: &NativeSideFuse<'m, 'rx, C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<(
        native::stages::inner_error::Witness<C, native::RevdotParameters<C::Profile>>,
        NativeFuseBuilder<'m, 'rx, C::CircuitField, R, B>,
        RegistryWy<C, R>,
    )>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let y = *y.value().take();
        let z = *z.value().take();

        let native_claims = native_fuser.claims::<B>(y, z)?;

        let native_inner_error_witness =
            native::stages::inner_error::Witness::<C, native::RevdotParameters<C::Profile>> {
                error_terms: native_fuser.inner_errors::<B>(&native_claims),
            };
        let native_rx = native::stages::inner_error::Stage::<
            C,
            R,
            HEADER_SIZE,
            native::RevdotParameters<C::Profile>,
        >::rx(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            &native_inner_error_witness,
        )?;

        builder.set_native_inner_error_rx(native_rx);

        let registry_wy = native_fuser.registry_wy::<B>(native_registry, y);

        Ok((native_inner_error_witness, native_claims, registry_wy))
    }

    /// Assembles the children's nested claims and computes the layer-1 error
    /// terms of their fold, along with the $m_n(w_n, X, y_n)$ restriction.
    ///
    /// The nested $y$ and $z$ are derived from the native challenges for the
    /// claims' $b$ sides and for folding the bonding claims across the two
    /// children. This prover computation uses the children's polynomials
    /// from the previous step; recursive soundness additionally requires
    /// binding their commitments before $y$ and $z$, binding the lifted
    /// challenges, and checking the fold in-circuit (see [`nested::challenge`]).
    fn compute_nested_inner_error<'m, 'dr, 'rx, D>(
        &self,
        nested_registry: &RegistryAt<'_, C::ScalarField, R>,
        native_y: &Element<'dr, D>,
        native_z: &Element<'dr, D>,
        nested_fuser: &NestedSideFuse<'m, 'rx, C, R>,
    ) -> Result<(
        FixedVec<
            FixedVec<
                C::ScalarField,
                NumErrorTerms<<nested::RevdotParameters<C::Profile> as Parameters>::GroupSize>,
            >,
            <nested::RevdotParameters<C::Profile> as Parameters>::NumGroups,
        >,
        NestedFuseBuilder<'m, 'rx, C::ScalarField, R, B>,
        NestedRegistryWy<C, R>,
    )>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let nested_claims =
            nested_fuser.claims::<B>(*native_y.value().take(), *native_z.value().take())?;
        let error_terms = nested_fuser.inner_errors::<B>(&nested_claims);
        let nested_registry_wy = nested_fuser.registry_wy::<B>(nested_registry, nested_claims.y);

        Ok((error_terms, nested_claims, nested_registry_wy))
    }

    /// Commits the nested fold's inner error terms alongside the native
    /// inner-error and registry commitments in the bridge stage.
    fn compute_bridge_inner_error<RNG: CryptoRng>(
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
    ) -> Result<nested::stages::inner_error::Witness<C::HostCurve, C::Profile>> {
        let nested_inner_error_witness = nested::stages::inner_error::Witness {
            native_inner_error: builder.native_inner_error_commitment(),
            registry_wy: registry_wy.commitment,
            error_terms,
        };
        let bridge_rx = nested::stages::inner_error::Stage::<C::HostCurve, R, C::Profile>::rx(
            C::ScalarField::random(|bytes| rng.fill_bytes(bytes)),
            &nested_inner_error_witness,
        )?;
        let bridge_commitment =
            B::sparse_commit_to_affine(&bridge_rx, C::nested_generators(self.params));
        builder.set_bridge_inner_error_rx(bridge_rx, bridge_commitment);

        Ok(nested_inner_error_witness)
    }
}

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

use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::{Registry, RegistryAt},
    staging::StageExt,
};
use ragu_core::{Cycle, Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::{Element, vec::FixedVec};
use rand::CryptoRng;
use udon::field::Field;

use super::claims::{
    NativeFuseBuilder, NativeFuseClaims, NativeFuseProofSource, NestedFuseBuilder,
    NestedFuseClaims, NestedFuseProofSource,
};
use crate::{
    Application,
    internal::{
        fold_revdot::{self, NumErrorTerms, Parameters},
        native, nested,
    },
    profile::ProfiledCycle,
    proof::ProofBuilder,
};

/// Ephemeral $m(w, X, y)$ registry restriction, used only during the fuse step.
pub(super) struct RegistryWy<C: Cycle, R: Rank> {
    pub(super) poly: sparse::Polynomial<C::CircuitField, R>,
    pub(super) commitment: C::HostCurve,
}

/// Ephemeral $m_n(w_n, X, y_n)$ nested registry restriction, used only
/// during the fuse step.
pub(super) struct NestedRegistryWy<C: Cycle, R: Rank> {
    pub(super) poly: sparse::Polynomial<C::ScalarField, R>,
    pub(super) commitment: C::NestedCurve,
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    pub(super) fn inner_error_terms<'dr, 'rx, D, RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        native_registry: &RegistryAt<'_, C::CircuitField, R>,
        nested_registry: &RegistryAt<'_, C::ScalarField, R>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        native_source: &NativeFuseProofSource<'rx, C, R>,
        nested_source: &NestedFuseProofSource<'rx, C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<(
        native::stages::inner_error::Witness<C, native::RevdotParameters<C::Profile>>,
        NativeFuseClaims<'rx, C::CircuitField, R>,
        RegistryWy<C, R>,
        nested::stages::inner_error::Witness<C::HostCurve, C::Profile>,
        NestedFuseClaims<'rx, C::ScalarField, R>,
        NestedRegistryWy<C, R>,
    )>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let y = *y.value().take();
        let z = *z.value().take();

        // The native and nested halves share no state, so the backend may
        // run them side by side. The native stage's blind is the only
        // randomness either half uses; it is drawn here, where the native
        // half would draw it, so that neither job touches the RNG.
        let blind = C::CircuitField::random(|bytes| rng.fill_bytes(bytes));
        // The application is not `Sync`; the jobs borrow only what they use.
        let (native_circuits, nested_circuits, params) =
            (&self.native_registry, &self.nested_registry, self.params);
        let (native, nested) = B::join(
            || {
                Self::compute_native_inner_error(
                    native_circuits,
                    params,
                    blind,
                    native_registry,
                    y,
                    z,
                    native_source,
                )
            },
            || {
                Self::compute_nested_inner_error(
                    nested_circuits,
                    params,
                    nested_registry,
                    y,
                    z,
                    nested_source,
                )
            },
        );
        let (native_inner_error_witness, native_claims, registry_wy, native_rx) = native?;
        let (nested_inner_error_terms, nested_claims, nested_registry_wy) = nested?;
        builder.set_native_inner_error_rx(native_rx);

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

    /// Assembles the children's native claims and computes the layer-1 error
    /// terms of their fold and the stage polynomial committing to them, with
    /// `blind` as its blinding factor, along with the $m(w, X, y)$
    /// restriction.
    ///
    /// This takes the registry and parameters rather than the application so
    /// that it can run as a job beside [`Self::compute_nested_inner_error`].
    fn compute_native_inner_error<'rx>(
        registry: &Registry<'_, C::CircuitField, R>,
        params: &C::Params,
        blind: C::CircuitField,
        native_registry: &RegistryAt<'_, C::CircuitField, R>,
        y: C::CircuitField,
        z: C::CircuitField,
        native_source: &NativeFuseProofSource<'rx, C, R>,
    ) -> Result<(
        native::stages::inner_error::Witness<C, native::RevdotParameters<C::Profile>>,
        NativeFuseClaims<'rx, C::CircuitField, R>,
        RegistryWy<C, R>,
        sparse::Polynomial<C::CircuitField, R>,
    )> {
        let mut native_claims = NativeFuseBuilder::<C::CircuitField, R, B>::new(registry, y, z);
        native::claims::build::<C::Profile, _, _>(native_source, &mut native_claims)?;
        let native_claims = native_claims.finish();

        let native_inner_error_witness =
            native::stages::inner_error::Witness::<C, native::RevdotParameters<C::Profile>> {
                error_terms: fold_revdot::inner_error_terms_with_backend::<
                    B,
                    _,
                    R,
                    native::RevdotParameters<C::Profile>,
                >(&native_claims.a, &native_claims.b),
            };
        let native_rx = native::stages::inner_error::Stage::<
            C,
            R,
            HEADER_SIZE,
            native::RevdotParameters<C::Profile>,
        >::rx(blind, &native_inner_error_witness)?;

        let registry_wy_poly = B::registry_at_y(native_registry, y);
        let registry_wy_commitment =
            B::sparse_commit_to_affine(&registry_wy_poly, C::host_generators(params));
        let registry_wy = RegistryWy {
            poly: registry_wy_poly,
            commitment: registry_wy_commitment,
        };

        Ok((
            native_inner_error_witness,
            native_claims,
            registry_wy,
            native_rx,
        ))
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
    fn compute_nested_inner_error<'rx>(
        registry: &Registry<'_, C::ScalarField, R>,
        params: &C::Params,
        nested_registry: &RegistryAt<'_, C::ScalarField, R>,
        native_y: C::CircuitField,
        native_z: C::CircuitField,
        nested_source: &NestedFuseProofSource<'rx, C, R>,
    ) -> Result<(
        FixedVec<
            FixedVec<
                C::ScalarField,
                NumErrorTerms<<nested::RevdotParameters<C::Profile> as Parameters>::GroupSize>,
            >,
            <nested::RevdotParameters<C::Profile> as Parameters>::NumGroups,
        >,
        NestedFuseClaims<'rx, C::ScalarField, R>,
        NestedRegistryWy<C, R>,
    )> {
        let nested_y = nested::challenge::<C>(native_y)?;
        let nested_z = nested::challenge::<C>(native_z)?;

        let mut nested_claims =
            NestedFuseBuilder::<C::ScalarField, R, B>::new(registry, nested_y, nested_z);
        nested::claims::build::<C::Profile, _, _>(nested_source, &mut nested_claims)?;
        let nested_claims = nested_claims.finish();

        let error_terms = fold_revdot::inner_error_terms_with_backend::<
            B,
            _,
            R,
            nested::RevdotParameters<C::Profile>,
        >(&nested_claims.a, &nested_claims.b);

        let nested_registry_wy_poly = B::registry_at_y(nested_registry, nested_y);
        let nested_registry_wy_commitment =
            B::sparse_commit_to_affine(&nested_registry_wy_poly, C::nested_generators(params));
        let nested_registry_wy = NestedRegistryWy {
            poly: nested_registry_wy_poly,
            commitment: nested_registry_wy_commitment,
        };

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

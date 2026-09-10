//! Commit to the error (off-diagonal) terms of the first revdot folding
//! reductions.
//!
//! This sets the inner-error fields on the [`ProofBuilder`], which commits to
//! the `inner_error` stage.
//!
//! The children's nested claims are folded here as well: their layer-1 error
//! terms ride inside the `inner_error` bridge stage, so they are committed
//! before $\mu$ and $\nu$ are squeezed without any change to the transcript
//! schedule.
//!
//! This phase of the fuse operation is also used to commit to the $m(w, X, y)$
//! restriction.

use ragu_arithmetic::{Cycle, ff::Field, rand::CryptoRng};
use ragu_circuits::{polynomials::Rank, registry::RegistryAt, staging::StageExt};
use ragu_core::{Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::{Element, vec::FixedVec};

use super::{
    NestedRegistryWy, RegistryWy,
    claims::{NativeFuseBuilder, NativeFuseProofSource, NestedFuseBuilder, NestedFuseProofSource},
};
use crate::{
    Application,
    internal::{
        fold_revdot::{self, NumErrorTerms, Parameters},
        native, nested,
    },
    proof::ProofBuilder,
};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
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
        native::stages::inner_error::Witness<C, native::RevdotParameters>,
        NativeFuseBuilder<'_, 'rx, C::CircuitField, R, B>,
        RegistryWy<C, R>,
        nested::stages::inner_error::Witness<C::HostCurve>,
        NestedFuseBuilder<'_, 'rx, C::ScalarField, R, B>,
        NestedRegistryWy<C, R>,
    )>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let (native_inner_error_witness, native_claims, registry_wy) =
            self.compute_native_inner_error(rng, native_registry, y, z, native_source, builder)?;
        let (nested_inner_error_terms, nested_claims, nested_registry_wy) =
            self.compute_nested_inner_error(nested_registry, y, z, nested_source)?;
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

    fn compute_native_inner_error<'dr, 'rx, D, RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        native_registry: &RegistryAt<'_, C::CircuitField, R>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        native_source: &NativeFuseProofSource<'rx, C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<(
        native::stages::inner_error::Witness<C, native::RevdotParameters>,
        NativeFuseBuilder<'_, 'rx, C::CircuitField, R, B>,
        RegistryWy<C, R>,
    )>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let y = *y.value().take();
        let z = *z.value().take();

        let mut native_claims =
            NativeFuseBuilder::<C::CircuitField, R, B>::new(&self.native_registry, y, z);
        native::claims::build(native_source, &mut native_claims)?;

        let native_inner_error_witness =
            native::stages::inner_error::Witness::<C, native::RevdotParameters> {
                error_terms: fold_revdot::inner_error_terms_with_backend::<
                    B,
                    _,
                    R,
                    native::RevdotParameters,
                >(&native_claims.a, &native_claims.b),
            };
        let native_rx =
            native::stages::inner_error::Stage::<C, R, HEADER_SIZE, native::RevdotParameters>::rx(
                C::CircuitField::random(&mut *rng),
                &native_inner_error_witness,
            )?;

        builder.set_native_inner_error_rx(native_rx);

        let registry_wy_poly = B::registry_at_y(native_registry, y);
        let registry_wy_commitment =
            B::sparse_commit_to_affine(&registry_wy_poly, C::host_generators(self.params));
        let registry_wy = RegistryWy {
            poly: registry_wy_poly,
            commitment: registry_wy_commitment,
        };

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
    fn compute_nested_inner_error<'dr, 'rx, D>(
        &self,
        nested_registry: &RegistryAt<'_, C::ScalarField, R>,
        native_y: &Element<'dr, D>,
        native_z: &Element<'dr, D>,
        nested_source: &NestedFuseProofSource<'rx, C, R>,
    ) -> Result<(
        FixedVec<
            FixedVec<
                C::ScalarField,
                NumErrorTerms<<nested::RevdotParameters as Parameters>::GroupSize>,
            >,
            <nested::RevdotParameters as Parameters>::NumGroups,
        >,
        NestedFuseBuilder<'_, 'rx, C::ScalarField, R, B>,
        NestedRegistryWy<C, R>,
    )>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let nested_y = nested::challenge::<C>(*native_y.value().take())?;
        let nested_z = nested::challenge::<C>(*native_z.value().take())?;

        let mut nested_claims = NestedFuseBuilder::<C::ScalarField, R, B>::new(
            &self.nested_registry,
            nested_y,
            nested_z,
        );
        nested::claims::build(nested_source, &mut nested_claims)?;

        let error_terms =
            fold_revdot::inner_error_terms_with_backend::<B, _, R, nested::RevdotParameters>(
                &nested_claims.a,
                &nested_claims.b,
            );

        let nested_registry_wy_poly = B::registry_at_y(nested_registry, nested_y);
        let nested_registry_wy_commitment =
            B::sparse_commit_to_affine(&nested_registry_wy_poly, C::nested_generators(self.params));
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
                NumErrorTerms<<nested::RevdotParameters as Parameters>::GroupSize>,
            >,
            <nested::RevdotParameters as Parameters>::NumGroups,
        >,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<nested::stages::inner_error::Witness<C::HostCurve>> {
        let nested_inner_error_witness = nested::stages::inner_error::Witness {
            native_inner_error: builder.native_inner_error_commitment(),
            registry_wy: registry_wy.commitment,
            error_terms,
        };
        let bridge_rx = nested::stages::inner_error::Stage::<C::HostCurve, R>::rx(
            C::ScalarField::random(&mut *rng),
            &nested_inner_error_witness,
        )?;
        let bridge_commitment =
            B::sparse_commit_to_affine(&bridge_rx, C::nested_generators(self.params));
        builder.set_bridge_inner_error_rx(bridge_rx, bridge_commitment);

        Ok(nested_inner_error_witness)
    }
}

//! Nested inner-error prover phase.
use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::RegistryAt,
};
use ragu_core::{Cycle, Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::{Element, vec::FixedVec};

use crate::{
    Application,
    profile::ProfiledCycle,
    protocol::{
        fold_revdot,
        fold_revdot::{NumErrorTerms, Parameters},
        nested,
    },
    prover::fuse::claims::{NestedFuseBuilder, NestedFuseProofSource},
};

/// Ephemeral $m_n(w_n, X, y_n)$ nested registry restriction, used only
/// during the fuse step.
pub(in crate::prover::fuse) struct NestedRegistryWy<C: Cycle, R: Rank> {
    pub(in crate::prover::fuse) poly: sparse::Polynomial<C::ScalarField, R>,
    pub(in crate::prover::fuse) commitment: C::NestedCurve,
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// Assembles the children's nested claims and computes the layer-1 error
    /// terms of their fold, along with the $m_n(w_n, X, y_n)$ restriction.
    ///
    /// The nested $y$ and $z$ are derived from the native challenges for the
    /// claims' $b$ sides and for folding the bonding claims across the two
    /// children. This prover computation uses the children's polynomials
    /// from the previous step; recursive soundness additionally requires
    /// binding their commitments before $y$ and $z$, binding the lifted
    /// challenges, and checking the fold in-circuit (see [`nested::challenge`]).
    pub(in crate::prover::fuse) fn compute_nested_inner_error<'dr, 'rx, D>(
        &self,
        nested_registry: &RegistryAt<'_, C::ScalarField, R>,
        native_y: &Element<'dr, D>,
        native_z: &Element<'dr, D>,
        nested_source: &NestedFuseProofSource<'rx, C, R>,
    ) -> Result<(
        FixedVec<
            FixedVec<
                C::ScalarField,
                NumErrorTerms<<nested::RevdotParameters<C::Profile> as Parameters>::GroupSize>,
            >,
            <nested::RevdotParameters<C::Profile> as Parameters>::NumGroups,
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
        nested::claims::build::<C::Profile, _, _>(nested_source, &mut nested_claims)?;

        let error_terms = fold_revdot::inner_error_terms_with_backend::<
            B,
            _,
            R,
            nested::RevdotParameters<C::Profile>,
        >(&nested_claims.a, &nested_claims.b);

        let nested_registry_wy_poly = B::registry_at_y(nested_registry, nested_y);
        let nested_registry_wy_commitment =
            B::sparse_commit_to_affine(&nested_registry_wy_poly, C::nested_generators(self.params));
        let nested_registry_wy = NestedRegistryWy {
            poly: nested_registry_wy_poly,
            commitment: nested_registry_wy_commitment,
        };

        Ok((error_terms, nested_claims, nested_registry_wy))
    }
}

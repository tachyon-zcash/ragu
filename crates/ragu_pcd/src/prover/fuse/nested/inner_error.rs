//! Nested inner-error prover phase.
use ragu_circuits::{polynomials::Rank, registry::RegistryAt};
use ragu_core::{Cycle, Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::{Element, vec::FixedVec};

use crate::{
    Application,
    profile::ProfiledCycle,
    protocol::{
        fold_revdot::{NumErrorTerms, Parameters},
        nested,
    },
    prover::fuse::claims::NestedFuseBuilder,
};

/// Ephemeral $m_n(w_n, X, y_n)$ nested registry restriction, used only
/// during the fuse step.
pub(in crate::prover::fuse) type NestedRegistryWy<C, R> =
    RegistryRestriction<<C as Cycle>::NestedCurve, R>;

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
    pub(in crate::prover::fuse) fn compute_nested_inner_error<'m, 'dr, 'rx, D>(
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
}

use crate::prover::fuse::side::{CurveSideFuse, NestedSideFuse, RegistryRestriction};

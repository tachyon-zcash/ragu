//! Curve-side inputs and the common accumulation phases.
//!
//! Each side supplies its registry, generators, challenge conversion and claim
//! layout. The coordinator interleaves these computations with stage and bridge
//! commitments before advancing the single transcript.

use alloc::borrow::Cow;
use core::borrow::Borrow;

use ragu_backend::Backend;
use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::{Registry, RegistryAt},
};
use ragu_core::{Cycle, FixedGenerators, Result};
use ragu_primitives::vec::FixedVec;
use udon::{curve::Affine, field::Field};

use super::{
    _03_s_prime::SPrime,
    claims::{FoldKey, NativeFuseProofSource, NestedFuseProofSource, TrackedPoly},
};
use crate::{
    internal::{
        claims::Builder,
        fold_revdot::{self, Foldable, NumErrorTerms, Parameters},
        native, nested,
    },
    profile::ProfiledCycle,
};

/// A registry restriction paired with its commitment on the same curve.
pub(super) struct RegistryRestriction<G: Affine, R: Rank> {
    pub(super) poly: sparse::Polynomial<G::Scalar, R>,
    pub(super) commitment: G,
}

/// Polynomials after the first folding layer, retaining native A's tracking.
pub(super) struct FoldedClaims<A, F: Field, R: Rank, P: Parameters> {
    pub(super) mu: F,
    pub(super) a: FixedVec<A, P::NumGroups>,
    pub(super) b: FixedVec<sparse::Polynomial<F, R>, P::NumGroups>,
}

type InnerErrors<F, P> = FixedVec<
    FixedVec<F, NumErrorTerms<<P as Parameters>::GroupSize>>,
    <P as Parameters>::NumGroups,
>;
type OuterErrors<F, P> = FixedVec<F, NumErrorTerms<<P as Parameters>::NumGroups>>;

/// The phases that both curve sides implement in the same field-local form.
///
/// This interface has no transcript or RNG. The coordinator fixes when a phase
/// runs and when its result is committed. Claim layouts and challenge conversion
/// are side-specific; native A retains its commitment decomposition through both
/// folds. Bridge construction and circuit witnesses remain explicit callers.
pub(super) trait CurveSideFuse<'m, 'rx, C: ProfiledCycle, R: Rank> {
    type Field: Field;
    type Curve: Affine<Scalar = Self::Field>;
    type Generators: FixedGenerators<Self::Curve>;
    type Parameters: Parameters;
    type Claim: Borrow<sparse::Polynomial<Self::Field, R>>;
    type FoldedA: Borrow<sparse::Polynomial<Self::Field, R>> + Foldable<Self::Field>;

    fn registry(&self) -> &'m Registry<'m, Self::Field, R>;
    fn generators(&self) -> &'m Self::Generators;
    fn challenge(value: C::CircuitField) -> Result<Self::Field>;
    fn child_x(&self) -> Result<[Self::Field; 2]>;

    fn populate_claims<B: Backend>(
        &self,
        claims: &mut Builder<'m, 'rx, Self::Claim, Self::Field, R, B>,
    ) -> Result<()>;

    fn fold_a(
        claims: &[Self::Claim],
        mu: Self::Field,
    ) -> FixedVec<Self::FoldedA, <Self::Parameters as Parameters>::NumGroups>;

    fn registry_at(&self, w: C::CircuitField) -> Result<RegistryAt<'m, Self::Field, R>> {
        Ok(self.registry().at(Self::challenge(w)?))
    }

    fn s_prime<B: Backend>(
        &self,
        registry: &RegistryAt<'_, Self::Field, R>,
    ) -> Result<SPrime<Self::Curve, R>> {
        Ok(SPrime::compute::<B>(
            registry,
            self.child_x()?,
            self.generators(),
        ))
    }

    fn claims<B: Backend>(
        &self,
        y: C::CircuitField,
        z: C::CircuitField,
    ) -> Result<Builder<'m, 'rx, Self::Claim, Self::Field, R, B>> {
        let y = Self::challenge(y)?;
        let z = Self::challenge(z)?;
        let mut claims = Builder::new(self.registry(), y, z);
        self.populate_claims(&mut claims)?;
        Ok(claims)
    }

    fn inner_errors<B: Backend>(
        &self,
        claims: &Builder<'m, 'rx, Self::Claim, Self::Field, R, B>,
    ) -> InnerErrors<Self::Field, Self::Parameters> {
        fold_revdot::inner_error_terms_with_backend::<B, _, R, Self::Parameters>(
            &claims.a, &claims.b,
        )
    }

    fn registry_wy<B: Backend>(
        &self,
        registry: &RegistryAt<'_, Self::Field, R>,
        y: Self::Field,
    ) -> RegistryRestriction<Self::Curve, R> {
        let poly = B::registry_at_y(registry, y);
        let commitment = B::sparse_commit_to_affine(&poly, self.generators());
        RegistryRestriction { poly, commitment }
    }

    fn fold_claims<B: Backend>(
        &self,
        claims: Builder<'m, 'rx, Self::Claim, Self::Field, R, B>,
        mu: C::CircuitField,
    ) -> Result<FoldedClaims<Self::FoldedA, Self::Field, R, Self::Parameters>> {
        let mu = Self::challenge(mu)?;
        let a = Self::fold_a(&claims.a, mu);
        let b = fold_revdot::fold_inner::<_, _, Self::Parameters>(&claims.b, mu);
        Ok(FoldedClaims { mu, a, b })
    }

    fn outer_errors<B: Backend>(
        &self,
        a: &FixedVec<Self::FoldedA, <Self::Parameters as Parameters>::NumGroups>,
        b: &FixedVec<
            sparse::Polynomial<Self::Field, R>,
            <Self::Parameters as Parameters>::NumGroups,
        >,
    ) -> OuterErrors<Self::Field, Self::Parameters> {
        fold_revdot::outer_error_terms_with_backend::<B, _, R, Self::Parameters>(a, b)
    }

    fn accumulate(
        &self,
        a: FixedVec<Self::FoldedA, <Self::Parameters as Parameters>::NumGroups>,
        b: FixedVec<
            sparse::Polynomial<Self::Field, R>,
            <Self::Parameters as Parameters>::NumGroups,
        >,
        mu_prime: C::CircuitField,
    ) -> Result<(Self::FoldedA, sparse::Polynomial<Self::Field, R>)> {
        let mu_prime = Self::challenge(mu_prime)?;
        Ok((
            fold_revdot::fold_outer::<_, _, Self::Parameters>(a, mu_prime),
            fold_revdot::fold_outer::<_, _, Self::Parameters>(b, mu_prime),
        ))
    }
}

/// Native registry and child-proof view for one fuse invocation.
pub(super) struct NativeSideFuse<'m, 'rx, C: Cycle, R: Rank> {
    pub(super) registry: &'m Registry<'m, C::CircuitField, R>,
    pub(super) generators: &'m C::HostGenerators,
    pub(super) source: NativeFuseProofSource<'rx, C, R>,
}

impl<'m, 'rx, C: ProfiledCycle, R: Rank> CurveSideFuse<'m, 'rx, C, R>
    for NativeSideFuse<'m, 'rx, C, R>
{
    type Field = C::CircuitField;
    type Curve = C::HostCurve;
    type Generators = C::HostGenerators;
    type Parameters = native::RevdotParameters<C::Profile>;
    type Claim = TrackedPoly<'rx, FoldKey, C::CircuitField, R>;
    type FoldedA = Self::Claim;

    fn registry(&self) -> &'m Registry<'m, Self::Field, R> {
        self.registry
    }
    fn generators(&self) -> &'m Self::Generators {
        self.generators
    }
    fn challenge(value: C::CircuitField) -> Result<Self::Field> {
        Ok(value)
    }
    fn child_x(&self) -> Result<[Self::Field; 2]> {
        Ok([self.source.left.x(), self.source.right.x()])
    }
    fn populate_claims<B: Backend>(
        &self,
        claims: &mut Builder<'m, 'rx, Self::Claim, Self::Field, R, B>,
    ) -> Result<()> {
        native::claims::build::<C::Profile, _, _>(&self.source, claims)
    }
    fn fold_a(
        claims: &[Self::Claim],
        mu: Self::Field,
    ) -> FixedVec<Self::FoldedA, <Self::Parameters as Parameters>::NumGroups> {
        fold_revdot::fold_inner::<_, _, Self::Parameters>(claims, mu)
    }
}

/// Nested registry and child-proof view for the same fuse invocation.
pub(super) struct NestedSideFuse<'m, 'rx, C: Cycle, R: Rank> {
    pub(super) registry: &'m Registry<'m, C::ScalarField, R>,
    pub(super) generators: &'m C::NestedGenerators,
    pub(super) source: NestedFuseProofSource<'rx, C, R>,
}

impl<'m, 'rx, C: ProfiledCycle, R: Rank> CurveSideFuse<'m, 'rx, C, R>
    for NestedSideFuse<'m, 'rx, C, R>
{
    type Field = C::ScalarField;
    type Curve = C::NestedCurve;
    type Generators = C::NestedGenerators;
    type Parameters = nested::RevdotParameters<C::Profile>;
    type Claim = Cow<'rx, sparse::Polynomial<C::ScalarField, R>>;
    type FoldedA = sparse::Polynomial<C::ScalarField, R>;

    fn registry(&self) -> &'m Registry<'m, Self::Field, R> {
        self.registry
    }
    fn generators(&self) -> &'m Self::Generators {
        self.generators
    }
    fn challenge(value: C::CircuitField) -> Result<Self::Field> {
        nested::challenge::<C>(value)
    }
    fn child_x(&self) -> Result<[Self::Field; 2]> {
        Ok([
            Self::challenge(self.source.left.x())?,
            Self::challenge(self.source.right.x())?,
        ])
    }
    fn populate_claims<B: Backend>(
        &self,
        claims: &mut Builder<'m, 'rx, Self::Claim, Self::Field, R, B>,
    ) -> Result<()> {
        nested::claims::build::<C::Profile, _, _>(&self.source, claims)
    }
    fn fold_a(
        claims: &[Self::Claim],
        mu: Self::Field,
    ) -> FixedVec<Self::FoldedA, <Self::Parameters as Parameters>::NumGroups> {
        fold_revdot::fold_inner::<sparse::Polynomial<Self::Field, R>, _, Self::Parameters>(
            claims, mu,
        )
    }
}

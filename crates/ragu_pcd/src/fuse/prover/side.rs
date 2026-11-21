//! Field-local phases of the native and nested fuse implementations.
//!
//! The orchestrator owns the transcript, commitment timing, and bridges.
//! This private interface has no transcript or RNG and uses static dispatch.
use core::borrow::Borrow;

use ragu_backend::Backend;
use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::{Registry, RegistryAt},
};
use ragu_core::{FixedGenerators, Result};
use ragu_primitives::vec::FixedVec;
use udon::{curve::Affine, field::Field};

use crate::{
    profile::ProfiledCycle,
    protocol::{
        revdot,
        revdot::{
            Builder,
            fold::{Foldable, NumErrorTerms, Parameters},
        },
    },
};

/// A registry restriction paired with its commitment on the same curve.
pub(in crate::fuse::prover) struct RegistryRestriction<G: Affine, R: Rank> {
    pub(in crate::fuse::prover) poly: sparse::Polynomial<G::Scalar, R>,
    pub(in crate::fuse::prover) commitment: G,
}

/// Polynomials after the first folding layer, retaining native A's tracking.
pub(in crate::fuse::prover) struct FoldedClaims<A, F: Field, R: Rank, P: Parameters> {
    pub(in crate::fuse::prover) mu: F,
    pub(in crate::fuse::prover) a: FixedVec<A, P::NumGroups>,
    pub(in crate::fuse::prover) b: FixedVec<sparse::Polynomial<F, R>, P::NumGroups>,
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
pub(in crate::fuse::prover) trait CurveSideFuse<'m, 'rx, C: ProfiledCycle, R: Rank> {
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
        revdot::fold::inner_error_terms_with_backend::<B, _, R, Self::Parameters>(
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
        let b = revdot::fold::fold_inner::<_, _, Self::Parameters>(&claims.b, mu);
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
        revdot::fold::outer_error_terms_with_backend::<B, _, R, Self::Parameters>(a, b)
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
            revdot::fold::fold_outer::<_, _, Self::Parameters>(a, mu_prime),
            revdot::fold::fold_outer::<_, _, Self::Parameters>(b, mu_prime),
        ))
    }
}

/// Registry restrictions at the two child evaluation points and their
/// commitments, over either side's scalar field and commitment curve.
pub(in crate::fuse::prover) struct SPrime<G: Affine, R: Rank> {
    pub(in crate::fuse::prover) registry_wx0_poly: sparse::Polynomial<G::Scalar, R>,
    pub(in crate::fuse::prover) registry_wx0_commitment: G,
    pub(in crate::fuse::prover) registry_wx1_poly: sparse::Polynomial<G::Scalar, R>,
    pub(in crate::fuse::prover) registry_wx1_commitment: G,
}

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

pub(in crate::fuse::prover) use super::{
    native::side::NativeSideFuse, nested::side::NestedSideFuse,
};

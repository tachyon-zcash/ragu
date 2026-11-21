//! Field-local phases of the native and nested fuse implementations.
//!
//! The orchestrator owns the transcript, commitment timing, and bridges.
//! This private interface has no transcript or RNG and uses static dispatch.
use alloc::borrow::Cow;

use ragu_backend::Backend;
use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::Registry,
};
use ragu_core::{Cycle, Result};
use ragu_primitives::vec::FixedVec;

use crate::{
    fuse::prover::claim_sources::NestedFuseProofSource,
    profile::ProfiledCycle,
    protocol::{
        nested, revdot,
        revdot::{Builder, fold::Parameters},
    },
};
/// Nested registry and child-proof view for the same fuse invocation.
pub(in crate::fuse::prover) struct NestedSideFuse<'m, 'rx, C: Cycle, R: Rank> {
    pub(in crate::fuse::prover) registry: &'m Registry<'m, C::ScalarField, R>,
    pub(in crate::fuse::prover) generators: &'m C::NestedGenerators,
    pub(in crate::fuse::prover) source: NestedFuseProofSource<'rx, C, R>,
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
        revdot::fold::fold_inner::<sparse::Polynomial<Self::Field, R>, _, Self::Parameters>(
            claims, mu,
        )
    }
}

use crate::fuse::prover::side::CurveSideFuse;

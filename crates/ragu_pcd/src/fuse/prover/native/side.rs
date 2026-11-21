//! Field-local phases of the native and nested fuse implementations.
//!
//! The orchestrator owns the transcript, commitment timing, and bridges.
//! This private interface has no transcript or RNG and uses static dispatch.

use ragu_backend::Backend;
use ragu_circuits::{polynomials::Rank, registry::Registry};
use ragu_core::{Cycle, Result};
use ragu_primitives::vec::FixedVec;

use crate::{
    fuse::prover::claim_sources::{FoldKey, NativeFuseProofSource, TrackedPoly},
    profile::ProfiledCycle,
    protocol::{
        native, revdot,
        revdot::{Builder, fold::Parameters},
    },
};
/// Native registry and child-proof view for one fuse invocation.
pub(in crate::fuse::prover) struct NativeSideFuse<'m, 'rx, C: Cycle, R: Rank> {
    pub(in crate::fuse::prover) registry: &'m Registry<'m, C::CircuitField, R>,
    pub(in crate::fuse::prover) generators: &'m C::HostGenerators,
    pub(in crate::fuse::prover) source: NativeFuseProofSource<'rx, C, R>,
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
        revdot::fold::fold_inner::<_, _, Self::Parameters>(claims, mu)
    }
}

use crate::fuse::prover::side::CurveSideFuse;

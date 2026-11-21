//! Nested ab prover phase.

use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::{Element, vec::FixedVec};

use crate::{
    Application,
    fuse::prover::proof_builder::ProofBuilder,
    profile::ProfiledCycle,
    protocol::{nested, revdot},
};

pub(in crate::fuse::prover) type NestedNumGroups<P> =
    <nested::RevdotParameters<P> as revdot::fold::Parameters>::NumGroups;

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// Applies the second layer of the nested fold, producing the nested
    /// accumulator polynomials.
    ///
    /// The nested $\mu'$ is derived from the native challenge
    /// (see [`nested::challenge`]), which the transcript squeezes only after
    /// the bridge carrying the layer-2 error terms is absorbed.
    pub(in crate::fuse::prover) fn compute_nested_ab<'dr, D>(
        &self,
        a: FixedVec<sparse::Polynomial<C::ScalarField, R>, NestedNumGroups<C::Profile>>,
        b: FixedVec<sparse::Polynomial<C::ScalarField, R>, NestedNumGroups<C::Profile>>,
        nested_fuser: &NestedSideFuse<'_, '_, C, R>,
        native_mu_prime: &Element<'dr, D>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let (a_poly, b_poly) = nested_fuser.accumulate(a, b, *native_mu_prime.value().take())?;

        builder.set_nested_a_poly(a_poly);
        builder.set_nested_b_poly(b_poly);

        Ok(())
    }
}

use crate::fuse::prover::side::{CurveSideFuse, NestedSideFuse};

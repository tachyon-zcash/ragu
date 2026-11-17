//! Nested ab prover phase.

use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::{Element, vec::FixedVec};

use crate::{
    Application,
    profile::ProfiledCycle,
    protocol::{fold_revdot, nested},
    prover::proof_builder::ProofBuilder,
};

pub(in crate::prover::fuse) type NestedNumGroups<P> =
    <nested::RevdotParameters<P> as fold_revdot::Parameters>::NumGroups;

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// Applies the second layer of the nested fold, producing the nested
    /// accumulator polynomials.
    ///
    /// The nested $\mu'$ is derived from the native challenge
    /// (see [`nested::challenge`]), which the transcript squeezes only after
    /// the bridge carrying the layer-2 error terms is absorbed.
    pub(in crate::prover::fuse) fn compute_nested_ab<'dr, D>(
        &self,
        a: FixedVec<sparse::Polynomial<C::ScalarField, R>, NestedNumGroups<C::Profile>>,
        b: FixedVec<sparse::Polynomial<C::ScalarField, R>, NestedNumGroups<C::Profile>>,
        native_mu_prime: &Element<'dr, D>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let nested_mu_prime = nested::challenge::<C>(*native_mu_prime.value().take())?;

        let a_poly = fold_revdot::fold_outer::<_, _, nested::RevdotParameters<C::Profile>>(
            a,
            nested_mu_prime,
        );
        let b_poly = fold_revdot::fold_outer::<_, _, nested::RevdotParameters<C::Profile>>(
            b,
            nested_mu_prime,
        );

        builder.set_nested_a_poly(a_poly);
        builder.set_nested_b_poly(b_poly);

        Ok(())
    }
}

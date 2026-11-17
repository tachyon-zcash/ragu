//! Bridge ab prover phase.

use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{Result, drivers::Driver};
use ragu_primitives::{Element, vec::FixedVec};

use crate::{
    Application,
    profile::ProfiledCycle,
    prover::{
        fuse::{
            claims::{FoldKey, TrackedPoly},
            nested::inner_error::NestedRegistryWy,
        },
        proof_builder::ProofBuilder,
    },
};

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    #[allow(clippy::too_many_arguments)]
    pub(in crate::prover::fuse) fn compute_ab<'dr, D, RNG: rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        native_a: FixedVec<
            TrackedPoly<'_, FoldKey, C::CircuitField, R>,
            NativeNumGroups<C::Profile>,
        >,
        native_b: FixedVec<sparse::Polynomial<C::CircuitField, R>, NativeNumGroups<C::Profile>>,
        nested_a: FixedVec<sparse::Polynomial<C::ScalarField, R>, NestedNumGroups<C::Profile>>,
        nested_b: FixedVec<sparse::Polynomial<C::ScalarField, R>, NestedNumGroups<C::Profile>>,
        nested_registry_wy: &NestedRegistryWy<C, R>,
        native_fuser: &NativeSideFuse<'_, '_, C, R>,
        nested_fuser: &NestedSideFuse<'_, '_, C, R>,
        mu_prime: &Element<'dr, D>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        self.compute_native_ab(native_a, native_b, native_fuser, mu_prime, builder)?;
        self.compute_nested_ab(nested_a, nested_b, nested_fuser, mu_prime, builder)?;
        self.commit_native_points_ab(
            rng,
            nested_registry_wy.commitment,
            builder.nested_a_commitment(),
            builder.nested_b_commitment(),
            builder,
        )?;
        Ok(())
    }
}

use crate::prover::fuse::{
    native::ab::NativeNumGroups,
    nested::ab::NestedNumGroups,
    side::{NativeSideFuse, NestedSideFuse},
};

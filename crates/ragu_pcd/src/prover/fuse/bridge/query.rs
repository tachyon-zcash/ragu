//! Bridge query prover phase.

use ragu_circuits::polynomials::Rank;
use ragu_core::{Result, drivers::Driver};
use ragu_primitives::Element;
use rand::CryptoRng;

use crate::{
    Application, Proof,
    profile::ProfiledCycle,
    prover::{
        fuse::{native::inner_error::RegistryWy, nested::inner_error::NestedRegistryWy},
        proof_builder::ProofBuilder,
    },
};

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    pub(in crate::prover::fuse) fn compute_query<'dr, D, RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        w: &Element<'dr, D>,
        x: &Element<'dr, D>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        registry_wy: &RegistryWy<C, R>,
        nested_registry_wy: &NestedRegistryWy<C, R>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<(
        crate::verifier::recursive::native::stages::query::Witness<C>,
        crate::verifier::recursive::nested::stages::query::Evaluations<C::ScalarField, C::Profile>,
    )>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let query_witness =
            self.compute_native_query(rng, w, x, y, z, registry_wy, left, right, builder)?;
        let nested_query =
            self.compute_nested_query(rng, w, x, y, z, nested_registry_wy, left, right, builder)?;
        Ok((query_witness, nested_query))
    }
}

//! Bridge p prover phase.

use ragu_circuits::polynomials::Rank;
use ragu_core::Result;
use ragu_primitives::EndoscalarChallenge;

use crate::{
    Application, Proof,
    profile::ProfiledCycle,
    protocol::nested::PointsWitness,
    prover::{
        fuse::{
            native::{f::NativeF, inner_error::RegistryWy, s_prime::NativeSPrime},
            nested::{f::NestedF, inner_error::NestedRegistryWy, s_prime::NestedSPrime},
        },
        proof_builder::ProofBuilder,
    },
};

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    #[allow(clippy::too_many_arguments)]
    pub(in crate::prover::fuse) fn compute_p<'dr, RNG: rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        pre_beta: &EndoscalarChallenge<'dr, NativeFuseEmulator<C>>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        s_prime: &NativeSPrime<C, R>,
        registry_wy: &RegistryWy<C, R>,
        f: &NativeF<C, R>,
        nested_s_prime: &NestedSPrime<C, R>,
        nested_registry_wy: &NestedRegistryWy<C, R>,
        nested_f: &NestedF<C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<(
        PointsWitness<C::HostCurve, C::Profile>,
        NativeInputs<C>,
        NativeWalk<C>,
    )> {
        // Extract endoscalar from pre_beta and compute effective beta. Going
        // through the validated `EndoscalarChallenge` makes the
        // `value < 2^CAPACITY` precondition a type invariant rather than an
        // unchecked argument to `extract_endoscalar`.
        let beta_endo = pre_beta.extract_native();

        let points = self.compute_native_p(
            rng,
            beta_endo,
            left,
            right,
            s_prime,
            registry_wy,
            f,
            builder,
        )?;
        let native_points = self.native_inputs(
            nested_f,
            nested_s_prime,
            nested_registry_wy,
            left,
            right,
            builder,
        );
        let native_walk = self.compute_nested_p(
            rng,
            beta_endo,
            left,
            right,
            nested_s_prime,
            nested_registry_wy,
            nested_f,
            &native_points,
            builder,
        )?;

        Ok((points, native_points, native_walk))
    }
}

use crate::prover::fuse::native::p::{NativeFuseEmulator, NativeInputs, NativeWalk};

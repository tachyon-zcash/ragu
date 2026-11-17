//! Bridge f prover phase.

use ragu_circuits::{polynomials::Rank, staging::StageExt};
use ragu_core::{Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::Element;
use rand::CryptoRng;
use udon::field::Field;

use crate::{
    Application, Proof,
    profile::ProfiledCycle,
    protocol::nested,
    prover::{
        fuse::{
            native::{inner_error::RegistryWy, s_prime::NativeSPrime},
            nested::{inner_error::NestedRegistryWy, s_prime::NestedSPrime},
        },
        proof_builder::ProofBuilder,
    },
};

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    pub(in crate::prover::fuse) fn compute_f<'dr, D, RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        w: &Element<'dr, D>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        x: &Element<'dr, D>,
        alpha: &Element<'dr, D>,
        s_prime: &NativeSPrime<C, R>,
        registry_wy: &RegistryWy<C, R>,
        nested_s_prime: &NestedSPrime<C, R>,
        nested_registry_wy: &NestedRegistryWy<C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
    ) -> Result<(NativeF<C, R>, NestedF<C, R>)>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let native = self.compute_native_f(
            w,
            y,
            z,
            x,
            alpha,
            s_prime,
            registry_wy,
            builder,
            left,
            right,
        )?;
        let nested = {
            let batch = self.nested_batch(builder, nested_s_prime, nested_registry_wy, left, right);
            let challenges = self.nested_challenges(w, x, y, z, left, right)?;
            let alpha = nested::challenge::<C>(*alpha.value().take())?;
            self.compute_nested_f(&batch, challenges, alpha)
        };
        self.commit_native_points_f(
            rng,
            builder.nested_registry_xy_commitment(),
            nested.commitment,
            builder,
        )?;
        self.compute_bridge_f(rng, &native, builder)?;
        Ok((native, nested))
    }

    /// Manually commits the bridge for $f$, rather than having the
    /// [`ProofBuilder`] retain the native copy that derives it, since the `f`
    /// polynomial is not retained after the fuse step and so does not appear in
    /// the proof.
    pub(in crate::prover::fuse) fn compute_bridge_f<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        native: &NativeF<C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        let bridge_rx = crate::verifier::recursive::nested::stages::f::Stage::<
            C::HostCurve,
            R,
            C::Profile,
        >::rx(
            C::ScalarField::random(|bytes| rng.fill_bytes(bytes)),
            &crate::verifier::recursive::nested::stages::f::Witness {
                native_f: native.commitment,
                native_points_f: builder.native_points_f_commitment(),
            },
        )?;
        let bridge_commitment =
            B::sparse_commit_to_affine(&bridge_rx, C::nested_generators(self.params));
        builder.set_bridge_f_rx(bridge_rx, bridge_commitment);
        Ok(())
    }
}

use crate::prover::fuse::{native::f::NativeF, nested::f::NestedF};

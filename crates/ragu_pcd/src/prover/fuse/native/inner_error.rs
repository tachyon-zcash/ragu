//! Native inner-error prover phase.
use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::RegistryAt,
    staging::StageExt,
};
use ragu_core::{Cycle, Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::Element;
use rand::CryptoRng;
use udon::field::Field;

use crate::{
    Application,
    profile::ProfiledCycle,
    protocol::{fold_revdot, native},
    prover::{
        fuse::claims::{NativeFuseBuilder, NativeFuseProofSource},
        proof_builder::ProofBuilder,
    },
};

/// Ephemeral $m(w, X, y)$ registry restriction, used only during the fuse step.
pub(in crate::prover::fuse) struct RegistryWy<C: Cycle, R: Rank> {
    pub(in crate::prover::fuse) poly: sparse::Polynomial<C::CircuitField, R>,
    pub(in crate::prover::fuse) commitment: C::HostCurve,
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    pub(in crate::prover::fuse) fn compute_native_inner_error<'dr, 'rx, D, RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        native_registry: &RegistryAt<'_, C::CircuitField, R>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        native_source: &NativeFuseProofSource<'rx, C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<(
        crate::verifier::recursive::native::stages::inner_error::Witness<
            C,
            native::RevdotParameters<C::Profile>,
        >,
        NativeFuseBuilder<'_, 'rx, C::CircuitField, R, B>,
        RegistryWy<C, R>,
    )>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let y = *y.value().take();
        let z = *z.value().take();

        let mut native_claims =
            NativeFuseBuilder::<C::CircuitField, R, B>::new(&self.native_registry, y, z);
        native::claims::build::<C::Profile, _, _>(native_source, &mut native_claims)?;

        let native_inner_error_witness =
            crate::verifier::recursive::native::stages::inner_error::Witness::<
                C,
                native::RevdotParameters<C::Profile>,
            > {
                error_terms: fold_revdot::inner_error_terms_with_backend::<
                    B,
                    _,
                    R,
                    native::RevdotParameters<C::Profile>,
                >(&native_claims.a, &native_claims.b),
            };
        let native_rx = crate::verifier::recursive::native::stages::inner_error::Stage::<
            C,
            R,
            HEADER_SIZE,
            native::RevdotParameters<C::Profile>,
        >::rx(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            &native_inner_error_witness,
        )?;

        builder.set_native_inner_error_rx(native_rx);

        let registry_wy_poly = B::registry_at_y(native_registry, y);
        let registry_wy_commitment =
            B::sparse_commit_to_affine(&registry_wy_poly, C::host_generators(self.params));
        let registry_wy = RegistryWy {
            poly: registry_wy_poly,
            commitment: registry_wy_commitment,
        };

        Ok((native_inner_error_witness, native_claims, registry_wy))
    }
}

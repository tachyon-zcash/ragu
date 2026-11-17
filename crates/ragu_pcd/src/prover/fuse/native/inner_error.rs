//! Native inner-error prover phase.
use ragu_circuits::{polynomials::Rank, registry::RegistryAt, staging::StageExt};
use ragu_core::{Cycle, Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::Element;
use rand::CryptoRng;
use udon::field::Field;

use crate::{
    Application,
    profile::ProfiledCycle,
    protocol::native,
    prover::{fuse::claims::NativeFuseBuilder, proof_builder::ProofBuilder},
};

/// Ephemeral $m(w, X, y)$ registry restriction, used only during the fuse step.
pub(in crate::prover::fuse) type RegistryWy<C, R> = RegistryRestriction<<C as Cycle>::HostCurve, R>;

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    pub(in crate::prover::fuse) fn compute_native_inner_error<'m, 'dr, 'rx, D, RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        native_registry: &RegistryAt<'_, C::CircuitField, R>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        native_fuser: &NativeSideFuse<'m, 'rx, C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<(
        crate::verifier::recursive::native::stages::inner_error::Witness<
            C,
            native::RevdotParameters<C::Profile>,
        >,
        NativeFuseBuilder<'m, 'rx, C::CircuitField, R, B>,
        RegistryWy<C, R>,
    )>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let y = *y.value().take();
        let z = *z.value().take();

        let native_claims = native_fuser.claims::<B>(y, z)?;

        let native_inner_error_witness =
            crate::verifier::recursive::native::stages::inner_error::Witness::<
                C,
                native::RevdotParameters<C::Profile>,
            > {
                error_terms: native_fuser.inner_errors::<B>(&native_claims),
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

        let registry_wy = native_fuser.registry_wy::<B>(native_registry, y);

        Ok((native_inner_error_witness, native_claims, registry_wy))
    }
}

use crate::prover::fuse::side::{CurveSideFuse, NativeSideFuse, RegistryRestriction};

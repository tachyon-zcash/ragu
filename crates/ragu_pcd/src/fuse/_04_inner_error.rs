//! Commit to the error (off-diagonal) terms of the first revdot folding
//! reductions.
//!
//! This sets the inner-error fields on the [`ProofBuilder`], which commits to
//! the `inner_error` stage.
//!
//! This phase of the fuse operation is also used to commit to the $m(w, X, y)$
//! restriction.

use ragu_arithmetic::{CryptoRngCore, Cycle, ff::Field};
use ragu_circuits::{polynomials::Rank, registry::RegistryAt, staging::StageExt};
use ragu_core::{Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::Element;

use super::{
    RegistryWy,
    claims::{FuseBuilder, FuseProofSource},
};
use crate::{
    Application,
    internal::{claims, fold_revdot, native, nested},
    proof::ProofBuilder,
};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    pub(super) fn inner_error_terms<'dr, 'rx, D, RNG: CryptoRngCore>(
        &self,
        rng: &mut RNG,
        native_registry: &RegistryAt<'_, C::CircuitField, R>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        source: &FuseProofSource<'rx, C, R>,
        builder: &mut ProofBuilder<'_, C, R>,
    ) -> Result<(
        native::stages::inner_error::Witness<C, native::RevdotParameters>,
        FuseBuilder<'_, 'rx, C::CircuitField, R>,
        RegistryWy<C, R>,
    )>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let (inner_error_witness, claims_builder, registry_wy) =
            self.compute_native_inner_error(rng, native_registry, y, z, source, builder)?;
        self.compute_bridge_inner_error(rng, &registry_wy, builder)?;
        Ok((inner_error_witness, claims_builder, registry_wy))
    }

    fn compute_bridge_inner_error<RNG: CryptoRngCore>(
        &self,
        rng: &mut RNG,
        registry_wy: &RegistryWy<C, R>,
        builder: &mut ProofBuilder<'_, C, R>,
    ) -> Result<()> {
        let bridge_rx = nested::stages::inner_error::Stage::<C::HostCurve, R>::rx(
            C::ScalarField::random(&mut *rng),
            &nested::stages::inner_error::Witness {
                native_inner_error: builder.native_inner_error_commitment(),
                registry_wy: registry_wy.commitment,
            },
        )?;
        let bridge_commitment = bridge_rx.commit_to_affine(C::nested_generators(self.params));
        builder.set_bridge_inner_error_rx(bridge_rx, bridge_commitment);
        Ok(())
    }

    fn compute_native_inner_error<'dr, 'rx, D, RNG: CryptoRngCore>(
        &self,
        rng: &mut RNG,
        native_registry: &RegistryAt<'_, C::CircuitField, R>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        source: &FuseProofSource<'rx, C, R>,
        builder: &mut ProofBuilder<'_, C, R>,
    ) -> Result<(
        native::stages::inner_error::Witness<C, native::RevdotParameters>,
        FuseBuilder<'_, 'rx, C::CircuitField, R>,
        RegistryWy<C, R>,
    )>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let y = *y.value().take();
        let z = *z.value().take();

        let mut claims_builder = claims::Builder::new(&self.native_registry, y, z);
        native::claims::build(source, &mut claims_builder)?;

        let inner_error_witness =
            native::stages::inner_error::Witness::<C, native::RevdotParameters> {
                error_terms: fold_revdot::inner_error_terms::<_, R, native::RevdotParameters>(
                    &claims_builder.a,
                    &claims_builder.b,
                ),
            };
        let native_rx =
            native::stages::inner_error::Stage::<C, R, HEADER_SIZE, native::RevdotParameters>::rx(
                C::CircuitField::random(&mut *rng),
                &inner_error_witness,
            )?;

        builder.set_native_inner_error_rx(native_rx);

        let registry_wy_poly = native_registry.y(y);
        let registry_wy_commitment =
            registry_wy_poly.commit_to_affine(C::host_generators(self.params));
        let registry_wy = RegistryWy {
            poly: registry_wy_poly,
            commitment: registry_wy_commitment,
        };

        Ok((inner_error_witness, claims_builder, registry_wy))
    }
}

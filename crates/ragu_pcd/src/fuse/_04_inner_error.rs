//! Commit to the error (off-diagonal) terms of the first revdot folding
//! reductions.
//!
//! This creates the [`proof::InnerError`] component of the proof, which commits to
//! the `inner_error` stage.
//!
//! This phase of the fuse operation is also used to commit to the $m(w, X, y)$
//! restriction.

use ff::Field;
use ragu_arithmetic::Cycle;
use ragu_circuits::{polynomials::Rank, registry::RegistryAt, staging::StageExt};
use ragu_core::{Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::Element;
use rand::CryptoRng;

use crate::{
    Application,
    internal::{claims, fold_revdot, native, nested},
    proof,
};

use super::claims::{FuseBuilder, FuseProofSource};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    pub(super) fn inner_error_terms<'dr, 'rx, D, RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        native_registry: &RegistryAt<'_, C::CircuitField, R>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        source: &FuseProofSource<'rx, C, R>,
        preamble: &proof::Preamble<C, R>,
    ) -> Result<(
        proof::InnerError<C, R>,
        native::stages::inner_error::Witness<C, native::RevdotParameters>,
        FuseBuilder<'_, 'rx, C::CircuitField, R>,
    )>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let (native_inner_error, inner_error_witness, builder) =
            self.compute_native_inner_error(rng, native_registry, y, z, source)?;

        let bridge = proof::Bridge::commit(
            self.params,
            nested::stages::inner_error::Stage::<C::HostCurve, R>::rx(
                C::ScalarField::random(&mut *rng),
                &nested::stages::inner_error::Witness {
                    native_inner_error: native_inner_error.rx_triple.commitment,
                    registry_wy: native_inner_error.registry_wy_commitment,
                    stashed_native_preamble: preamble.native.commitment,
                },
            )?,
        );

        Ok((
            proof::InnerError {
                native: native_inner_error,
                bridge,
            },
            inner_error_witness,
            builder,
        ))
    }

    fn compute_native_inner_error<'dr, 'rx, D, RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        native_registry: &RegistryAt<'_, C::CircuitField, R>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        source: &FuseProofSource<'rx, C, R>,
    ) -> Result<(
        proof::NativeInnerError<C, R>,
        native::stages::inner_error::Witness<C, native::RevdotParameters>,
        FuseBuilder<'_, 'rx, C::CircuitField, R>,
    )>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let y = *y.value().take();
        let z = *z.value().take();

        let mut builder = claims::Builder::new(&self.native_registry, y, z);
        native::claims::build(source, &mut builder)?;

        let inner_error_witness =
            native::stages::inner_error::Witness::<C, native::RevdotParameters> {
                error_terms: fold_revdot::inner_error_terms::<_, R, native::RevdotParameters>(
                    &builder.a, &builder.b,
                ),
            };
        let native_rx =
            native::stages::inner_error::Stage::<C, R, HEADER_SIZE, native::RevdotParameters>::rx(
                C::CircuitField::random(&mut *rng),
                &inner_error_witness,
            )?;

        let registry_wy_poly = native_registry.y(y);

        let host_gen = C::host_generators(self.params);
        let [registry_wy_commitment, native_commitment] = ragu_arithmetic::batch_to_affine([
            registry_wy_poly.commit(host_gen),
            native_rx.commit(host_gen),
        ]);

        Ok((
            proof::NativeInnerError {
                registry_wy_poly,
                registry_wy_commitment,
                rx_triple: proof::RxTriple {
                    rx: native_rx,
                    commitment: native_commitment,
                },
            },
            inner_error_witness,
            builder,
        ))
    }
}

//! Commit to the error (off-diagonal) terms of the first revdot folding
//! reductions.
//!
//! This creates the [`proof::ErrorM`] component of the proof, which commits to
//! the `error_m` stage.
//!
//! This phase of the fuse operation is also used to commit to the $m(w, X, y)$
//! restriction.

use ragu_arithmetic::Cycle;
use ragu_circuits::{
    polynomials::{Committable, Rank},
    registry::RegistryAt,
    staging::StageExt,
};
use ragu_core::{
    Result,
    drivers::Driver,
    maybe::{Always, Maybe},
};
use ragu_primitives::Element;
use rand::CryptoRng;

use crate::{
    Application, Proof,
    circuits::{native, nested},
    components::{
        claims,
        fold_revdot::{self, NativeParameters},
    },
    proof,
};

use super::FuseProofSource;

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    pub(super) fn compute_errors_m<'dr, 'rx, D, RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        registry_at_w: &RegistryAt<'_, C::CircuitField, R>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        left: &'rx Proof<C, R>,
        right: &'rx Proof<C, R>,
    ) -> Result<(
        proof::ErrorM<C, R>,
        native::stages::error_m::Witness<C, NativeParameters>,
        claims::Builder<'_, 'rx, C::CircuitField, R>,
    )>
    where
        D: Driver<'dr, F = C::CircuitField, MaybeKind = Always<()>>,
    {
        let y = *y.value().take();
        let z = *z.value().take();

        let registry_wy = registry_at_w
            .wy(y)
            .commit(C::host_generators(self.params), rng);

        let source = FuseProofSource { left, right };
        let mut builder = claims::Builder::new(&self.native_registry, y, z);
        claims::native::build(&source, &mut builder)?;

        let error_terms =
            fold_revdot::compute_errors_m::<_, R, NativeParameters>(&builder.a, &builder.b);

        let error_m_witness =
            native::stages::error_m::Witness::<C, NativeParameters> { error_terms };
        let native_rx = native::stages::error_m::Stage::<C, R, HEADER_SIZE, NativeParameters>::rx(
            &error_m_witness,
        )?
        .commit(C::host_generators(self.params), rng);

        let nested_error_m_witness = nested::stages::error_m::Witness {
            native_error_m: native_rx.commitment(),
            registry_wy: registry_wy.commitment(),
        };
        let nested_rx =
            nested::stages::error_m::Stage::<C::HostCurve, R>::rx(&nested_error_m_witness)?
                .commit(C::nested_generators(self.params), rng);

        Ok((
            proof::ErrorM {
                registry_wy,
                native_rx,
                nested_rx,
            },
            error_m_witness,
            builder,
        ))
    }
}

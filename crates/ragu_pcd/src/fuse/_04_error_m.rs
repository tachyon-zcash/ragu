//! Commit to the error (off-diagonal) terms of the first revdot folding
//! reductions.
//!
//! This creates the [`proof::ErrorM`] component of the proof, which commits to
//! the `error_m` stage.
//!
//! This phase of the fuse operation is also used to commit to the $m(w, X, y)$
//! restriction.

use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::{polynomials::Rank, staging::StageExt};
use ragu_core::{
    Result,
    drivers::Driver,
    maybe::{Always, Maybe},
};
use ragu_primitives::Element;
use rand::Rng;

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
    pub(super) fn compute_errors_m<'dr, 'rx, D, RNG: Rng>(
        &self,
        rng: &mut RNG,
        w: &Element<'dr, D>,
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
        let w = *w.value().take();
        let y = *y.value().take();
        let z = *z.value().take();

        let registry_wy_poly = self.native_registry.wy(w, y);
        let registry_wy_blind = C::CircuitField::random(&mut *rng);
        let registry_wy_commitment =
            registry_wy_poly.commit(C::host_generators(self.params), registry_wy_blind);

        let source = FuseProofSource { left, right };
        let mut builder =
            claims::Builder::new(&self.native_registry, self.num_application_steps, y, z);
        claims::native::build(&source, &mut builder)?;

        let error_terms =
            fold_revdot::compute_errors_m::<_, R, NativeParameters>(&builder.a, &builder.b);

        let error_m_witness =
            native::stages::error_m::Witness::<C, NativeParameters> { error_terms };
        let native_rx = native::stages::error_m::Stage::<C, R, HEADER_SIZE, NativeParameters>::rx(
            &error_m_witness,
        )?;
        let native_blind = C::CircuitField::random(&mut *rng);
        let native_commitment = native_rx.commit(C::host_generators(self.params), native_blind);

        let nested_error_m_witness = nested::stages::error_m::Witness {
            native_error_m: native_commitment,
            registry_wy: registry_wy_commitment,
        };
        let nested_rx =
            nested::stages::error_m::Stage::<C::HostCurve, R>::rx(&nested_error_m_witness)?;
        let nested_blind = C::ScalarField::random(&mut *rng);
        let nested_commitment = nested_rx.commit(C::nested_generators(self.params), nested_blind);

        Ok((
            proof::ErrorM {
                registry_wy_poly,
                registry_wy_blind,
                registry_wy_commitment,
                native_rx,
                native_blind,
                native_commitment,
                nested_rx,
                nested_blind,
                nested_commitment,
            },
            error_m_witness,
            builder,
        ))
    }
}

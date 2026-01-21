//! Commit to the error (off-diagonal) terms of the second revdot folding
//! reduction.
//!
//! This creates the [`proof::ErrorN`] component of the proof, which commits to
//! the `error_n` stage. The stage contains the error terms and is used to store
//! the $k(Y)$ evaluations for the child proofs, as well as the temporary sponge
//! state used to split the hashing operations across two circuits.

use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::{
    polynomials::{Rank, structured},
    staging::{Stage as StageTrait, StageExt},
};
use ragu_core::{
    Result,
    drivers::{Driver, emulator::Emulator},
    maybe::{Always, Maybe},
};
use ragu_primitives::{Element, vec::FixedVec};
use rand::Rng;

use crate::{
    Application,
    circuits::{
        native,
        native::stages::error_n::{ChildKyValues, KyValues},
        nested,
    },
    components::{
        claims,
        fold_revdot::{self, NativeParameters},
    },
    proof,
};

type NativeN = <NativeParameters as fold_revdot::Parameters>::N;

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    pub(super) fn compute_errors_n<'dr, D, RNG: Rng>(
        &self,
        rng: &mut RNG,
        preamble_witness: &native::stages::preamble::Witness<'_, C, R, HEADER_SIZE>,
        error_m_witness: &native::stages::error_m::Witness<C, NativeParameters>,
        claims: claims::Builder<'_, '_, C::CircuitField, R>,
        y: &Element<'dr, D>,
        mu: &Element<'dr, D>,
        nu: &Element<'dr, D>,
        sponge_state_elements: FixedVec<
            C::CircuitField,
            ragu_primitives::poseidon::PoseidonStateLen<C::CircuitField, C::CircuitPoseidon>,
        >,
    ) -> Result<(
        proof::ErrorN<C, R>,
        native::stages::error_n::Witness<C, NativeParameters>,
        FixedVec<structured::Polynomial<C::CircuitField, R>, NativeN>,
        FixedVec<structured::Polynomial<C::CircuitField, R>, NativeN>,
    )>
    where
        D: Driver<'dr, F = C::CircuitField, MaybeKind = Always<()>>,
    {
        let y = *y.value().take();
        let mu = *mu.value().take();
        let nu = *nu.value().take();
        let mu_inv = mu.invert().expect("mu must be non-zero");
        let munu = mu * nu;
        let a = fold_revdot::fold_polys_m::<_, R, NativeParameters>(&claims.a, mu_inv);
        let b = fold_revdot::fold_polys_m::<_, R, NativeParameters>(&claims.b, munu);
        drop(claims);

        let (ky, collapsed) = Emulator::emulate_wireless(
            (preamble_witness, &error_m_witness.error_terms, y, mu, nu),
            |dr, witness| {
                let (preamble_witness, error_terms_m, y, mu, nu) = witness.cast();

                let preamble = native::stages::preamble::Stage::<C, R, HEADER_SIZE>::default()
                    .witness(dr, preamble_witness.view().map(|w| *w))?;

                let y = Element::alloc(dr, y)?;
                let left_application_ky = preamble.left.application_ky(dr, &y)?;
                let right_application_ky = preamble.right.application_ky(dr, &y)?;
                let (left_unified_ky, left_unified_bridge_ky) =
                    preamble.left.unified_ky_values(dr, &y)?;
                let (right_unified_ky, right_unified_bridge_ky) =
                    preamble.right.unified_ky_values(dr, &y)?;
                let left_endoscale_ky = preamble.left.endoscale_ky(dr, &y)?;
                let right_endoscale_ky = preamble.right.endoscale_ky(dr, &y)?;

                let mu = Element::alloc(dr, mu)?;
                let nu = Element::alloc(dr, nu)?;

                // Build k(y) values in claim order.
                let ky = claims::native::TwoProofKySource {
                    left_raw_c: preamble.left.unified.c.clone(),
                    right_raw_c: preamble.right.unified.c.clone(),
                    left_app: left_application_ky.clone(),
                    right_app: right_application_ky.clone(),
                    left_bridge: left_unified_bridge_ky.clone(),
                    right_bridge: right_unified_bridge_ky.clone(),
                    left_unified: left_unified_ky.clone(),
                    right_unified: right_unified_ky.clone(),
                    left_endoscale: left_endoscale_ky.clone(),
                    right_endoscale: right_endoscale_ky.clone(),
                    zero: Element::zero(dr),
                };
                let mut ky = claims::native::ky_values(&ky);

                let fold_products = fold_revdot::FoldProducts::new(dr, &mu, &nu)?;

                let collapsed = FixedVec::try_from_fn(|i| {
                    let errors = FixedVec::try_from_fn(|j| {
                        Element::alloc(dr, error_terms_m.view().map(|et| et[i][j]))
                    })?;
                    let ky = FixedVec::from_fn(|_| ky.next().unwrap());

                    let v = fold_products.fold_products_m::<NativeParameters>(dr, &errors, &ky)?;
                    Ok(*v.value().take())
                })?;

                let ky = KyValues {
                    left: ChildKyValues {
                        application: *left_application_ky.value().take(),
                        unified: *left_unified_ky.value().take(),
                        unified_bridge: *left_unified_bridge_ky.value().take(),
                        endoscale: *left_endoscale_ky.value().take(),
                    },
                    right: ChildKyValues {
                        application: *right_application_ky.value().take(),
                        unified: *right_unified_ky.value().take(),
                        unified_bridge: *right_unified_bridge_ky.value().take(),
                        endoscale: *right_endoscale_ky.value().take(),
                    },
                };

                Ok((ky, collapsed))
            },
        )?;

        let error_terms = fold_revdot::compute_errors_n::<_, R, NativeParameters>(&a, &b);

        let error_n_witness = native::stages::error_n::Witness::<C, NativeParameters> {
            error_terms,
            collapsed,
            ky,
            sponge_state_elements,
        };
        let native_rx = native::stages::error_n::Stage::<C, R, HEADER_SIZE, NativeParameters>::rx(
            &error_n_witness,
        )?;
        let native_blind = C::CircuitField::random(&mut *rng);
        let native_commitment = native_rx.commit(C::host_generators(self.params), native_blind);

        let nested_error_n_witness = nested::stages::error_n::Witness {
            native_error_n: native_commitment,
        };
        let nested_rx =
            nested::stages::error_n::Stage::<C::HostCurve, R>::rx(&nested_error_n_witness)?;
        let nested_blind = C::ScalarField::random(&mut *rng);
        let nested_commitment = nested_rx.commit(C::nested_generators(self.params), nested_blind);

        Ok((
            proof::ErrorN {
                native_rx,
                native_blind,
                native_commitment,
                nested_rx,
                nested_blind,
                nested_commitment,
            },
            error_n_witness,
            a,
            b,
        ))
    }
}

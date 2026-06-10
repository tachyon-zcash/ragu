//! Commit to the error (off-diagonal) terms of the second revdot folding
//! reduction.
//!
//! This sets the outer-error fields on the [`ProofBuilder`], which commits to
//! the `outer_error` stage. The stage contains the error terms and is used to store
//! the $k(Y)$ evaluations for the child proofs, as well as the temporary sponge
//! state used to split the hashing operations across two circuits.

use ragu_arithmetic::{CryptoRngCore, Cycle, ff::Field};
use ragu_circuits::{
    polynomials::{Rank, sparse},
    staging::{Stage as StageTrait, StageExt},
};
use ragu_core::{
    Result,
    drivers::{Driver, emulator::Emulator},
    maybe::Maybe,
};
use ragu_primitives::{Element, vec::FixedVec};

use super::claims::{FoldKey, FuseBuilder, TrackedPoly};
use crate::{
    Application,
    internal::{
        fold_revdot, native,
        native::stages::outer_error::{ChildKyValues, KyValues},
    },
    proof::ProofBuilder,
};

type NativeNumGroups = <native::RevdotParameters as fold_revdot::Parameters>::NumGroups;

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    pub(super) fn outer_error_terms<'dr, 'rx, D, RNG: CryptoRngCore>(
        &self,
        rng: &mut RNG,
        preamble_witness: &native::stages::preamble::Witness<'_, C, R, HEADER_SIZE>,
        inner_error_witness: &native::stages::inner_error::Witness<C, native::RevdotParameters>,
        claims: FuseBuilder<'_, 'rx, C::CircuitField, R>,
        y: &Element<'dr, D>,
        mu: &Element<'dr, D>,
        nu: &Element<'dr, D>,
        sponge_state_elements: FixedVec<
            C::CircuitField,
            ragu_primitives::poseidon::PoseidonStateLen<C::CircuitField, C::CircuitPoseidon>,
        >,
        builder: &mut ProofBuilder<'_, C, R>,
    ) -> Result<(
        native::stages::outer_error::Witness<C, native::RevdotParameters>,
        FixedVec<TrackedPoly<'rx, FoldKey, C::CircuitField, R>, NativeNumGroups>,
        FixedVec<sparse::Polynomial<C::CircuitField, R>, NativeNumGroups>,
    )>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let y = *y.value().take();
        let mu = *mu.value().take();
        let nu = *nu.value().take();
        let mu_inv = mu.invert().expect("mu must be non-zero");
        let mu_nu = mu * nu;
        let a = fold_revdot::fold_inner::<_, _, native::RevdotParameters>(&claims.a, mu_inv);
        let b = fold_revdot::fold_inner::<_, _, native::RevdotParameters>(&claims.b, mu_nu);
        drop(claims);

        let (ky, collapsed) = Emulator::emulate_wireless(
            (
                preamble_witness,
                &inner_error_witness.error_terms,
                y,
                mu,
                nu,
            ),
            |dr, witness| {
                let (preamble_witness, inner_error_terms, y, mu, nu) = witness.cast();
                let allocator = &mut ();

                let preamble = native::stages::preamble::Stage::<C, R, HEADER_SIZE>::default()
                    .witness(dr, preamble_witness.as_ref().map(|w| *w))?;

                let y = Element::alloc(dr, allocator, y)?;
                let (left_unified_ky, left_unified_bridge_ky) =
                    preamble.left.unified_ky_values(dr, &y)?;
                let (right_unified_ky, right_unified_bridge_ky) =
                    preamble.right.unified_ky_values(dr, &y)?;

                let left_ky = native::stages::outer_error::ChildKyOutputs {
                    application: preamble.left.application_ky(dr, &y)?,
                    unified: left_unified_ky,
                    unified_bridge: left_unified_bridge_ky,
                };
                let right_ky = native::stages::outer_error::ChildKyOutputs {
                    application: preamble.right.application_ky(dr, &y)?,
                    unified: right_unified_ky,
                    unified_bridge: right_unified_bridge_ky,
                };

                let mu = Element::alloc(dr, allocator, mu)?;
                let nu = Element::alloc(dr, allocator, nu)?;

                // Build k(y) values in claim order.
                let ky_source = native::claims::TwoProofKySource::new(
                    dr,
                    preamble.left.unified.c.clone(),
                    preamble.right.unified.c.clone(),
                    &left_ky,
                    &right_ky,
                );
                let mut ky = native::claims::ky_values(&ky_source);

                let fold_products = fold_revdot::ClaimFolder::new(dr, &mu, &nu)?;

                let collapsed = FixedVec::try_from_fn(|i| {
                    let errors = FixedVec::try_from_fn(|j| {
                        Element::alloc(dr, allocator, inner_error_terms.as_ref().map(|et| et[i][j]))
                    })?;
                    let ky = FixedVec::from_fn(|_| ky.next().unwrap());

                    let v =
                        fold_products.fold_inner::<native::RevdotParameters>(dr, &errors, &ky)?;
                    Ok(*v.value().take())
                })?;

                let ky = KyValues {
                    left: ChildKyValues {
                        application: *left_ky.application.value().take(),
                        unified: *left_ky.unified.value().take(),
                        unified_bridge: *left_ky.unified_bridge.value().take(),
                    },
                    right: ChildKyValues {
                        application: *right_ky.application.value().take(),
                        unified: *right_ky.unified.value().take(),
                        unified_bridge: *right_ky.unified_bridge.value().take(),
                    },
                };

                Ok((ky, collapsed))
            },
        )?;

        let error_terms = fold_revdot::outer_error_terms::<_, R, native::RevdotParameters>(&a, &b);

        let outer_error_witness =
            native::stages::outer_error::Witness::<C, native::RevdotParameters> {
                error_terms,
                collapsed,
                ky,
                sponge_state_elements,
            };
        self.compute_native_outer_error(rng, &outer_error_witness, builder)?;

        Ok((outer_error_witness, a, b))
    }

    fn compute_native_outer_error<RNG: CryptoRngCore>(
        &self,
        rng: &mut RNG,
        outer_error_witness: &native::stages::outer_error::Witness<C, native::RevdotParameters>,
        builder: &mut ProofBuilder<'_, C, R>,
    ) -> Result<()> {
        let rx =
            native::stages::outer_error::Stage::<C, R, HEADER_SIZE, native::RevdotParameters>::rx(
                C::CircuitField::random(&mut *rng),
                outer_error_witness,
            )?;

        builder.set_native_outer_error_rx(rx);

        Ok(())
    }
}

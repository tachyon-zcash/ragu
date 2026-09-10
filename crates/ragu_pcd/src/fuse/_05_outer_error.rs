//! Commit to the error (off-diagonal) terms of the second revdot folding
//! reduction.
//!
//! This sets the outer-error fields on the [`ProofBuilder`], which commits to
//! the `outer_error` stage. The stage contains the error terms and is used to store
//! the $k(Y)$ evaluations for the child proofs, as well as the temporary sponge
//! state used to split the hashing operations across two circuits.
//!
//! The second layer of the nested fold is committed here as well: its error
//! terms and its layer-1 folded claim values ride inside the `outer_error`
//! bridge stage, so they are committed before $\mu'$ and $\nu'$ are squeezed.

use ragu_arithmetic::{Cycle, ff::Field, rand::CryptoRng};
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

use super::{
    NestedFuseEmulator,
    claims::{FoldKey, NativeFuseBuilder, NestedFuseBuilder, NestedFuseProofSource, TrackedPoly},
};
use crate::{
    Application,
    internal::{
        fold_revdot::{self, Parameters},
        native,
        native::stages::outer_error::{ChildKyValues, KyValues},
        nested,
    },
    proof::ProofBuilder,
};

type NativeNumGroups = <native::RevdotParameters as fold_revdot::Parameters>::NumGroups;
type NestedNumGroups = <nested::RevdotParameters as Parameters>::NumGroups;

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    pub(super) fn outer_error_terms<'dr, 'rx, D, RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        preamble_witness: &native::stages::preamble::Witness<'_, C, R, HEADER_SIZE>,
        native_inner_error_witness: &native::stages::inner_error::Witness<
            C,
            native::RevdotParameters,
        >,
        native_claims: NativeFuseBuilder<'_, 'rx, C::CircuitField, R, B>,
        nested_inner_error_witness: &nested::stages::inner_error::Witness<C::HostCurve>,
        nested_claims: NestedFuseBuilder<'_, 'rx, C::ScalarField, R, B>,
        nested_source: &NestedFuseProofSource<'rx, C, R>,
        nested_preamble: &nested::stages::preamble::Witness<C::HostCurve>,
        y: &Element<'dr, D>,
        mu: &Element<'dr, D>,
        nu: &Element<'dr, D>,
        sponge_state_elements: FixedVec<
            C::CircuitField,
            ragu_primitives::poseidon::PoseidonStateLen<C::CircuitField, C::CircuitPoseidon>,
        >,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<(
        native::stages::outer_error::Witness<C, native::RevdotParameters>,
        FixedVec<TrackedPoly<'rx, FoldKey, C::CircuitField, R>, NativeNumGroups>,
        FixedVec<sparse::Polynomial<C::CircuitField, R>, NativeNumGroups>,
        nested::stages::outer_error::Witness<C::HostCurve>,
        FixedVec<sparse::Polynomial<C::ScalarField, R>, NestedNumGroups>,
        FixedVec<sparse::Polynomial<C::ScalarField, R>, NestedNumGroups>,
    )>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let y = *y.value().take();
        let mu = *mu.value().take();
        let nu = *nu.value().take();
        let mu_inv = mu.invert().expect("mu must be non-zero");
        let mu_nu = mu * nu;
        let native_a =
            fold_revdot::fold_inner::<_, _, native::RevdotParameters>(&native_claims.a, mu_inv);
        let native_b =
            fold_revdot::fold_inner::<_, _, native::RevdotParameters>(&native_claims.b, mu_nu);
        drop(native_claims);

        let (ky, collapsed) = Emulator::emulate_wireless(
            (
                preamble_witness,
                &native_inner_error_witness.error_terms,
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

        let error_terms =
            fold_revdot::outer_error_terms_with_backend::<B, _, R, native::RevdotParameters>(
                &native_a, &native_b,
            );

        let native_outer_error_witness =
            native::stages::outer_error::Witness::<C, native::RevdotParameters> {
                error_terms,
                collapsed,
                ky,
                sponge_state_elements,
            };
        self.compute_native_outer_error(rng, &native_outer_error_witness, builder)?;

        // The bridge for this stage carries the nested fold's second layer, so
        // it is built once the native commitment it also bridges exists.
        let (nested_outer_error_witness, nested_a, nested_b) = self.compute_nested_outer_error(
            rng,
            nested_inner_error_witness,
            nested_claims,
            nested_source,
            nested_preamble,
            y,
            mu,
            nu,
            builder,
        )?;

        Ok((
            native_outer_error_witness,
            native_a,
            native_b,
            nested_outer_error_witness,
            nested_a,
            nested_b,
        ))
    }

    fn compute_native_outer_error<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        native_outer_error_witness: &native::stages::outer_error::Witness<
            C,
            native::RevdotParameters,
        >,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        let rx =
            native::stages::outer_error::Stage::<C, R, HEADER_SIZE, native::RevdotParameters>::rx(
                C::CircuitField::random(&mut *rng),
                native_outer_error_witness,
            )?;

        builder.set_native_outer_error_rx(rx);

        Ok(())
    }

    /// Applies the first layer of the nested fold and commits its second
    /// layer's data into the `outer_error` bridge stage.
    ///
    /// The nested $y$, $\mu$ and $\nu$ are derived from the native challenges
    /// (see [`nested::challenge`]), which the transcript squeezes only after
    /// the bridge carrying the layer-1 error terms is absorbed. The collapsed
    /// values are computed through [`fold_revdot::ClaimFolder`] exactly as a
    /// nested collapse circuit would, from the children's $k(y_n)$ values
    /// the bridge preamble's copies of their nested unified instances
    /// determine, so the witness this stage commits is the one such a
    /// circuit will later enforce.
    #[allow(clippy::too_many_arguments)]
    fn compute_nested_outer_error<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        nested_inner_error_witness: &nested::stages::inner_error::Witness<C::HostCurve>,
        nested_claims: NestedFuseBuilder<'_, '_, C::ScalarField, R, B>,
        nested_source: &NestedFuseProofSource<'_, C, R>,
        nested_preamble: &nested::stages::preamble::Witness<C::HostCurve>,
        native_y: C::CircuitField,
        native_mu: C::CircuitField,
        native_nu: C::CircuitField,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<(
        nested::stages::outer_error::Witness<C::HostCurve>,
        FixedVec<sparse::Polynomial<C::ScalarField, R>, NestedNumGroups>,
        FixedVec<sparse::Polynomial<C::ScalarField, R>, NestedNumGroups>,
    )> {
        let nested_y = nested::challenge::<C>(native_y)?;
        let nested_mu = nested::challenge::<C>(native_mu)?;
        let nested_nu = nested::challenge::<C>(native_nu)?;
        let nested_mu_inv = nested_mu.invert().expect("nested mu must be non-zero");
        let nested_mu_nu = nested_mu * nested_nu;

        let a = fold_revdot::fold_inner::<
            sparse::Polynomial<C::ScalarField, R>,
            _,
            nested::RevdotParameters,
        >(&nested_claims.a, nested_mu_inv);
        let b = fold_revdot::fold_inner::<
            sparse::Polynomial<C::ScalarField, R>,
            _,
            nested::RevdotParameters,
        >(&nested_claims.b, nested_mu_nu);
        drop(nested_claims);

        let collapsed = NestedFuseEmulator::<C>::emulate_wireless(
            (
                (
                    &nested_inner_error_witness.error_terms,
                    nested_y,
                    nested_mu,
                    nested_nu,
                ),
                (
                    nested_source.left.nested_c(),
                    nested_source.right.nested_c(),
                ),
                nested_preamble,
            ),
            |dr, witness| {
                let (challenges, cs, nested_preamble) = witness.cast();
                let (inner_error_terms, nested_y, nested_mu, nested_nu) = challenges.cast();
                let (left_c, right_c) = cs.cast();
                let allocator = &mut ();

                let preamble = nested::stages::preamble::Stage::<C::HostCurve, R>::default()
                    .witness(dr, nested_preamble.as_ref().map(|w| *w))?;

                let nested_y = Element::alloc(dr, allocator, nested_y)?;
                let nested_mu = Element::alloc(dr, allocator, nested_mu)?;
                let nested_nu = Element::alloc(dr, allocator, nested_nu)?;
                let left_c = Element::alloc(dr, allocator, left_c)?;
                let right_c = Element::alloc(dr, allocator, right_c)?;

                // The k(y) of each child's nested unified instance, from the
                // bridge preamble's copies: the value the export claim's
                // fold uses.
                let left_unified = preamble.left.nested_instance().ky(dr, &nested_y)?;
                let right_unified = preamble.right.nested_instance().ky(dr, &nested_y)?;

                // Build k(y) values in nested claim order.
                let ky_source = nested::claims::TwoProofKySource::new(
                    dr,
                    left_c,
                    right_c,
                    left_unified,
                    right_unified,
                );
                let mut ky = nested::claims::ky_values(&ky_source);

                let fold_products = fold_revdot::ClaimFolder::new(dr, &nested_mu, &nested_nu)?;

                FixedVec::try_from_fn(|i| {
                    let errors = FixedVec::try_from_fn(|j| {
                        Element::alloc(dr, allocator, inner_error_terms.as_ref().map(|et| et[i][j]))
                    })?;
                    let ky = FixedVec::from_fn(|_| ky.next().unwrap());

                    let v =
                        fold_products.fold_inner::<nested::RevdotParameters>(dr, &errors, &ky)?;
                    Ok(*v.value().take())
                })
            },
        )?;

        let error_terms =
            fold_revdot::outer_error_terms_with_backend::<B, _, R, nested::RevdotParameters>(
                &a, &b,
            );

        let bridge = nested::stages::outer_error::Witness {
            native_outer_error: builder.native_outer_error_commitment(),
            error_terms,
            collapsed,
        };
        let bridge_rx = nested::stages::outer_error::Stage::<C::HostCurve, R>::rx(
            C::ScalarField::random(&mut *rng),
            &bridge,
        )?;
        let bridge_commitment =
            B::sparse_commit_to_affine(&bridge_rx, C::nested_generators(self.params));
        builder.set_bridge_outer_error_rx(bridge_rx, bridge_commitment);

        Ok((bridge, a, b))
    }
}

//! Bridge outer-error prover phase.
use ragu_circuits::{
    polynomials::{Rank, sparse},
    staging::Stage as StageTrait,
};
use ragu_core::{
    Result,
    drivers::{Driver, emulator::Emulator},
    maybe::Maybe,
};
use ragu_primitives::{Element, vec::FixedVec};
use rand::CryptoRng;

use crate::{
    Application,
    profile::ProfiledCycle,
    protocol::{fold_revdot, ky, native},
    prover::{
        fuse::claims::{FoldKey, NativeFuseBuilder, NestedFuseBuilder, TrackedPoly},
        proof_builder::ProofBuilder,
    },
    verifier::recursive::native::stages::outer_error::{ChildKyValues, KyValues},
};

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    pub(in crate::prover::fuse) fn outer_error_terms<'dr, 'rx, D, RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        preamble_witness: &crate::verifier::recursive::native::stages::preamble::Witness<
            '_,
            C,
            R,
            HEADER_SIZE,
        >,
        native_inner_error_witness: &crate::verifier::recursive::native::stages::inner_error::Witness<
            C,
            native::RevdotParameters<C::Profile>,
        >,
        native_claims: NativeFuseBuilder<'_, 'rx, C::CircuitField, R, B>,
        nested_inner_error_witness: &crate::verifier::recursive::nested::stages::inner_error::Witness<C::HostCurve, C::Profile>,
        nested_claims: NestedFuseBuilder<'_, 'rx, C::ScalarField, R, B>,
        native_fuser: &NativeSideFuse<'_, 'rx, C, R>,
        nested_fuser: &NestedSideFuse<'_, 'rx, C, R>,
        nested_preamble: &crate::verifier::recursive::nested::stages::preamble::Witness<
            C::HostCurve,
            C::Profile,
        >,
        y: &Element<'dr, D>,
        mu: &Element<'dr, D>,
        sponge_state_elements: FixedVec<
            C::CircuitField,
            ragu_primitives::poseidon::PoseidonStateLen<C::CircuitField, C::CircuitPoseidon>,
        >,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<(
        crate::verifier::recursive::native::stages::outer_error::Witness<
            C,
            native::RevdotParameters<C::Profile>,
        >,
        FixedVec<TrackedPoly<'rx, FoldKey, C::CircuitField, R>, NativeNumGroups<C::Profile>>,
        FixedVec<sparse::Polynomial<C::CircuitField, R>, NativeNumGroups<C::Profile>>,
        crate::verifier::recursive::nested::stages::outer_error::Witness<C::HostCurve, C::Profile>,
        FixedVec<sparse::Polynomial<C::ScalarField, R>, NestedNumGroups<C::Profile>>,
        FixedVec<sparse::Polynomial<C::ScalarField, R>, NestedNumGroups<C::Profile>>,
    )>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let y = *y.value().take();
        let mu = *mu.value().take();
        let FoldedClaims {
            a: native_a,
            b: native_b,
            ..
        } = native_fuser.fold_claims::<B>(native_claims, mu)?;

        let (ky, collapsed) = Emulator::emulate_wireless(
            (
                preamble_witness,
                &native_inner_error_witness.error_terms,
                y,
                mu,
            ),
            |dr, witness| {
                let (preamble_witness, inner_error_terms, y, mu) = witness.cast();
                let allocator = &mut ();

                let preamble = crate::verifier::recursive::native::stages::preamble::Stage::<
                    C,
                    R,
                    HEADER_SIZE,
                >::default()
                .witness(dr, preamble_witness.as_ref().map(|w| *w))?;

                let y = Element::alloc(dr, allocator, y)?;
                let (left_unified_ky, left_unified_bridge_ky) =
                    preamble.left.unified_ky_values(dr, &y)?;
                let (right_unified_ky, right_unified_bridge_ky) =
                    preamble.right.unified_ky_values(dr, &y)?;

                let left_ky =
                    crate::verifier::recursive::native::stages::outer_error::ChildKyOutputs {
                        application: preamble.left.application_ky(dr, &y)?,
                        unified: left_unified_ky,
                        unified_bridge: left_unified_bridge_ky,
                        compute_v_bridge: preamble.left.compute_v_bridge_ky(dr, &y)?,
                    };
                let right_ky =
                    crate::verifier::recursive::native::stages::outer_error::ChildKyOutputs {
                        application: preamble.right.application_ky(dr, &y)?,
                        unified: right_unified_ky,
                        unified_bridge: right_unified_bridge_ky,
                        compute_v_bridge: preamble.right.compute_v_bridge_ky(dr, &y)?,
                    };

                let mu = Element::alloc(dr, allocator, mu)?;

                // Build k(y) values in claim order.
                let left_statement = preamble.left.statement_ky::<C::Profile>(dr, &y)?;
                let right_statement = preamble.right.statement_ky::<C::Profile>(dr, &y)?;
                // The binding circuit's, over the children's nested
                // extension stages its binding names: in the circuit the
                // parent walks them, here they are read off the proofs.
                let bound = |proof: &crate::Proof<C, R>| {
                    ky::native_bound::<C::Profile, _>(|index| proof.nested_rx_commitment(index))
                };
                let left_bound = preamble_witness.as_ref().map(|w| bound(w.left.proof));
                let right_bound = preamble_witness.as_ref().map(|w| bound(w.right.proof));
                let count = left_bound.as_ref().map(|b| b.len()).take();
                let left_binding =
                    ky::binding_ky_alloc(dr, &y, count, left_bound.as_ref().map(|b| b.as_slice()))?;
                let right_binding = ky::binding_ky_alloc(
                    dr,
                    &y,
                    count,
                    right_bound.as_ref().map(|b| b.as_slice()),
                )?;
                let ky_source = native::claims::TwoProofKySource::new(
                    dr,
                    preamble.left.unified.c.clone(),
                    preamble.right.unified.c.clone(),
                    &left_ky,
                    &right_ky,
                    left_statement,
                    right_statement,
                    left_binding,
                    right_binding,
                );
                let mut ky = native::claims::ky_values::<C::Profile, _>(&ky_source);

                let fold_products = fold_revdot::ClaimFolder::new(&mu);

                let collapsed = FixedVec::try_from_fn(|i| {
                    let errors = FixedVec::try_from_fn(|j| {
                        Element::alloc(dr, allocator, inner_error_terms.as_ref().map(|et| et[i][j]))
                    })?;
                    let ky = FixedVec::from_fn(|_| ky.next().unwrap());

                    let v = fold_products
                        .fold_inner::<native::RevdotParameters<C::Profile>>(dr, &errors, &ky)?;
                    Ok(*v.value().take())
                })?;

                let ky = KyValues {
                    left: ChildKyValues {
                        application: *left_ky.application.value().take(),
                        unified: *left_ky.unified.value().take(),
                        unified_bridge: *left_ky.unified_bridge.value().take(),
                        compute_v_bridge: *left_ky.compute_v_bridge.value().take(),
                    },
                    right: ChildKyValues {
                        application: *right_ky.application.value().take(),
                        unified: *right_ky.unified.value().take(),
                        unified_bridge: *right_ky.unified_bridge.value().take(),
                        compute_v_bridge: *right_ky.compute_v_bridge.value().take(),
                    },
                };

                Ok((ky, collapsed))
            },
        )?;

        let error_terms = native_fuser.outer_errors::<B>(&native_a, &native_b);

        let native_outer_error_witness =
            crate::verifier::recursive::native::stages::outer_error::Witness::<
                C,
                native::RevdotParameters<C::Profile>,
            > {
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
            nested_fuser,
            nested_preamble,
            y,
            mu,
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
}

use crate::prover::fuse::{
    nested::outer_error::{NativeNumGroups, NestedNumGroups},
    side::{CurveSideFuse, FoldedClaims, NativeSideFuse, NestedSideFuse},
};

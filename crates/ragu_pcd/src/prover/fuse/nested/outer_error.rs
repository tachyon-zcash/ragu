//! Nested outer-error prover phase.
use ragu_circuits::{
    polynomials::{Rank, sparse},
    staging::{Stage as StageTrait, StageExt},
};
use ragu_core::{
    Cycle, Result,
    drivers::emulator::{Emulator, Wireless},
    maybe::{Always, Maybe},
};
use ragu_primitives::{Element, vec::FixedVec};
use rand::CryptoRng;
use udon::field::Field;

use crate::{
    Application,
    profile::{Profile, ProfiledCycle},
    protocol::{fold_revdot, fold_revdot::Parameters, ky, native, nested},
    prover::{
        fuse::claims::{NestedFuseBuilder, NestedFuseProofSource},
        proof_builder::ProofBuilder,
    },
};

pub(in crate::prover::fuse) type NativeNumGroups<P> =
    <native::RevdotParameters<P> as fold_revdot::Parameters>::NumGroups;

pub(in crate::prover::fuse) type NestedNumGroups<P> =
    <nested::RevdotParameters<P> as Parameters>::NumGroups;

/// The wireless emulator the fuse step's scalar-field computations run in.
pub(in crate::prover::fuse) type NestedFuseEmulator<C> =
    Emulator<Wireless<Always<()>, <C as Cycle>::ScalarField>>;

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// Applies the first layer of the nested fold and commits its second
    /// layer's data into the `outer_error` bridge stage.
    ///
    /// The nested $y$ and $\mu$ are derived from the native challenges
    /// (see [`nested::challenge`]). The transcript squeezes $y$ after the
    /// `s_prime` bridge, and $\mu$ only after the bridge carrying
    /// the layer-1 error terms is absorbed. The collapsed values are computed
    /// through [`fold_revdot::ClaimFolder`] exactly as the nested collapse
    /// circuit does, from the children's $k(y_n)$ values
    /// the bridge preamble's copies of their nested unified instances
    /// determine, so the witness this stage commits is the one that circuit
    /// enforces.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::prover::fuse) fn compute_nested_outer_error<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        nested_inner_error_witness: &crate::verifier::recursive::nested::stages::inner_error::Witness<C::HostCurve, C::Profile>,
        nested_claims: NestedFuseBuilder<'_, '_, C::ScalarField, R, B>,
        nested_source: &NestedFuseProofSource<'_, C, R>,
        nested_preamble: &crate::verifier::recursive::nested::stages::preamble::Witness<
            C::HostCurve,
            C::Profile,
        >,
        native_y: C::CircuitField,
        native_mu: C::CircuitField,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<(
        crate::verifier::recursive::nested::stages::outer_error::Witness<C::HostCurve, C::Profile>,
        FixedVec<sparse::Polynomial<C::ScalarField, R>, NestedNumGroups<C::Profile>>,
        FixedVec<sparse::Polynomial<C::ScalarField, R>, NestedNumGroups<C::Profile>>,
    )> {
        let nested_y = nested::challenge::<C>(native_y)?;
        let nested_mu = nested::challenge::<C>(native_mu)?;

        let a = fold_revdot::fold_inner::<
            sparse::Polynomial<C::ScalarField, R>,
            _,
            nested::RevdotParameters<C::Profile>,
        >(&nested_claims.a, nested_mu);
        let b = fold_revdot::fold_inner::<
            sparse::Polynomial<C::ScalarField, R>,
            _,
            nested::RevdotParameters<C::Profile>,
        >(&nested_claims.b, nested_mu);
        drop(nested_claims);

        let collapsed = NestedFuseEmulator::<C>::emulate_wireless(
            (
                (&nested_inner_error_witness.error_terms, nested_y, nested_mu),
                (
                    nested_source.left.nested_c(),
                    nested_source.right.nested_c(),
                ),
                nested_preamble,
            ),
            |dr, witness| {
                let (challenges, cs, nested_preamble) = witness.cast();
                let (inner_error_terms, nested_y, nested_mu) = challenges.cast();
                let (left_c, right_c) = cs.cast();
                let allocator = &mut ();

                let preamble = crate::verifier::recursive::nested::stages::preamble::Stage::<
                    C::HostCurve,
                    R,
                    C::Profile,
                >::default()
                .witness(dr, nested_preamble.as_ref().map(|w| *w))?;

                let nested_y = Element::alloc(dr, allocator, nested_y)?;
                let nested_mu = Element::alloc(dr, allocator, nested_mu)?;
                let left_c = Element::alloc(dr, allocator, left_c)?;
                let right_c = Element::alloc(dr, allocator, right_c)?;

                // The k(y) of each child's nested unified instance, from the
                // bridge preamble's copies: the value the export claim's
                // fold uses.
                let left_unified = preamble.left.nested_instance().ky(dr, &nested_y)?;
                let right_unified = preamble.right.nested_instance().ky(dr, &nested_y)?;

                // The binding circuit's k(y), over the children's native
                // extension stages the bridge preamble holds.
                let binding = C::Profile::nested_extension().binding;
                let left_binding = ky::binding_ky(
                    dr,
                    &nested_y,
                    &ky::bound(binding.as_ref(), |j| {
                        preamble.left.extension_stages[j as usize].clone()
                    }),
                )?;
                let right_binding = ky::binding_ky(
                    dr,
                    &nested_y,
                    &ky::bound(binding.as_ref(), |j| {
                        preamble.right.extension_stages[j as usize].clone()
                    }),
                )?;

                // Build k(y) values in nested claim order.
                let ky_source = nested::claims::TwoProofKySource::new(
                    dr,
                    left_c,
                    right_c,
                    left_unified,
                    right_unified,
                    left_binding,
                    right_binding,
                );
                let mut ky = nested::claims::ky_values::<C::Profile, _>(&ky_source);

                let fold_products = fold_revdot::ClaimFolder::new(&nested_mu);

                FixedVec::try_from_fn(|i| {
                    let errors = FixedVec::try_from_fn(|j| {
                        Element::alloc(dr, allocator, inner_error_terms.as_ref().map(|et| et[i][j]))
                    })?;
                    let ky = FixedVec::from_fn(|_| ky.next().unwrap());

                    let v = fold_products
                        .fold_inner::<nested::RevdotParameters<C::Profile>>(dr, &errors, &ky)?;
                    Ok(*v.value().take())
                })
            },
        )?;

        let error_terms = fold_revdot::outer_error_terms_with_backend::<
            B,
            _,
            R,
            nested::RevdotParameters<C::Profile>,
        >(&a, &b);

        let bridge = crate::verifier::recursive::nested::stages::outer_error::Witness {
            native_outer_error: builder.native_outer_error_commitment(),
            error_terms,
            collapsed,
        };
        let bridge_rx = crate::verifier::recursive::nested::stages::outer_error::Stage::<
            C::HostCurve,
            R,
            C::Profile,
        >::rx(
            C::ScalarField::random(|bytes| rng.fill_bytes(bytes)),
            &bridge,
        )?;
        let bridge_commitment =
            B::sparse_commit_to_affine(&bridge_rx, C::nested_generators(self.params));
        builder.set_bridge_outer_error_rx(bridge_rx, bridge_commitment);

        Ok((bridge, a, b))
    }
}

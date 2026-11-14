//! Commit to the quotient error terms of the first revdot folding layer.
//!
//! This sets the inner-error fields on the [`ProofBuilder`], which commits to
//! the `inner_error` stage.
//!
//! The children's nested claims are folded here as well: their layer-1 error
//! terms ride inside the `inner_error` bridge stage, so they are committed
//! before the first-layer folding challenge is squeezed.
//!
//! This phase of the fuse operation is also used to commit to the $m(w, X, y)$
//! restriction; its nested counterpart's commitment enters the native
//! points stage committed before $x$ (see `_06_ab`).

use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::RegistryAt,
    staging::StageExt,
};
use ragu_core::{Cycle, Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::{Element, vec::FixedVec};
use rand::CryptoRng;
use udon::field::Field;

use super::{
    claims::{
        HollowProcessor, NativeFuseBuilder, NativeFuseProofSource, NestedFuseBuilder,
        NestedFuseProofSource,
    },
    device::Devices,
};
use crate::{
    Application,
    internal::{
        fold_revdot::{self, NumErrorTerms, Parameters},
        native, nested,
    },
    multicore::par_join,
    profile::ProfiledCycle,
    proof::ProofBuilder,
    timing::span,
};

/// Ephemeral $m(w, X, y)$ registry restriction, used only during the fuse step.
pub(super) struct RegistryWy<C: Cycle, R: Rank> {
    pub(super) poly: sparse::Polynomial<C::CircuitField, R>,
    pub(super) commitment: C::HostCurve,
}

/// Ephemeral $m_n(w_n, X, y_n)$ nested registry restriction, used only
/// during the fuse step.
pub(super) struct NestedRegistryWy<C: Cycle, R: Rank> {
    pub(super) poly: sparse::Polynomial<C::ScalarField, R>,
    pub(super) commitment: C::NestedCurve,
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    pub(super) fn inner_error_terms<'dr, 'rx, D, RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        native_registry: &RegistryAt<'_, C::CircuitField, R>,
        nested_registry: &RegistryAt<'_, C::ScalarField, R>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        native_source: &NativeFuseProofSource<'rx, C, R>,
        nested_source: &NestedFuseProofSource<'rx, C, R>,
        devices: &mut Devices<'rx, C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<(
        native::stages::inner_error::Witness<C, native::RevdotParameters<C::Profile>>,
        NativeFuseBuilder<'_, 'rx, C::CircuitField, R, B>,
        RegistryWy<C, R>,
        nested::stages::inner_error::Witness<C::HostCurve, C::Profile>,
        NestedFuseBuilder<'_, 'rx, C::ScalarField, R, B>,
        NestedRegistryWy<C, R>,
    )>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let y = *y.value().take();
        let z = *z.value().take();
        let (native_full, nested_full) = (&self.native_registry, &self.nested_registry);
        // The claims take the devices with them; `_06_ab` hands them back.
        let native_recorded = devices
            .native_claims
            .take()
            .and_then(|recorder| Some((devices.native.take()?, recorder)));
        let nested_recorded = devices
            .nested_claims
            .take()
            .and_then(|recorder| Some((devices.nested.take()?, recorder)));

        let (host_generators, nested_generators) = (
            C::host_generators(self.params),
            C::nested_generators(self.params),
        );

        // Each side assembles its children's claims, computes the layer-1
        // error terms of their fold and restricts its registry to $y$.
        // Neither reads the other or the builder, so they run together. The
        // nested side works at the nested counterparts of the challenges
        // (see [`nested::challenge`]); recursive soundness additionally
        // requires binding the children's commitments before $y$ and $z$,
        // binding the lifted challenges, and checking the fold in-circuit.
        let (native, nested) = par_join!(
            || -> Result<_> {
                let mut claims =
                    NativeFuseBuilder::<C::CircuitField, R, B>::deferred(native_full, y, z);
                // With a device, the claims' polynomials are formed and
                // multiplied there, while the host restricts the registry.
                if let Some((device, recorder)) = native_recorded {
                    span("ie.native.hollow", || {
                        native::claims::build::<C::Profile, _, _>(
                            native_source,
                            &mut HollowProcessor {
                                claims: &mut claims,
                            },
                        )
                    })?;
                    let (mut held, wy) = span("ie.native.device", || {
                        recorder.finish::<B>(device, native_full, native_registry, y, z)
                    });
                    // The restriction is committed to while the error terms
                    // are computed: neither reads the other.
                    let (error_terms, commitment) = par_join!(
                        || span("ie.native.terms", || {
                            held.inner_error_terms::<B, native::RevdotParameters<C::Profile>>()
                        }),
                        || span("ie.native.commit", || {
                            B::sparse_commit_to_affine(&wy, host_generators)
                        }),
                    );
                    claims.device = Some(held);
                    return Ok((claims, error_terms, wy, Some(commitment)));
                }
                span("ie.native.claims", || {
                    native::claims::build::<C::Profile, _, _>(native_source, &mut claims)
                })?;
                span("ie.native.finish", || claims.finish());
                let error_terms = span("ie.native.errors", || {
                    fold_revdot::inner_error_terms_with_backend::<
                        B,
                        _,
                        R,
                        native::RevdotParameters<C::Profile>,
                    >(&claims.a, &claims.b)
                });
                let wy = span("ie.native.registry_y", || {
                    B::registry_at_y(native_registry, y)
                });
                Ok((claims, error_terms, wy, None))
            },
            || -> Result<_> {
                let nested_y = nested::challenge::<C>(y)?;
                let nested_z = nested::challenge::<C>(z)?;
                let mut claims = NestedFuseBuilder::<C::ScalarField, R, B>::deferred(
                    nested_full,
                    nested_y,
                    nested_z,
                );
                if let Some((device, recorder)) = nested_recorded {
                    let (mut held, wy) = span("ie.nested.device", || {
                        recorder.finish::<B>(
                            device,
                            nested_full,
                            nested_registry,
                            nested_y,
                            nested_z,
                        )
                    });
                    let (error_terms, commitment) = par_join!(
                        || span("ie.nested.terms", || {
                            held.inner_error_terms::<B, nested::RevdotParameters<C::Profile>>()
                        }),
                        || span("ie.nested.commit", || {
                            B::sparse_commit_to_affine(&wy, nested_generators)
                        }),
                    );
                    claims.device = Some(held);
                    return Ok((claims, error_terms, wy, Some(commitment)));
                }
                span("ie.nested.claims", || {
                    nested::claims::build::<C::Profile, _, _>(nested_source, &mut claims)
                })?;
                span("ie.nested.finish", || claims.finish());
                let error_terms = span("ie.nested.errors", || {
                    fold_revdot::inner_error_terms_with_backend::<
                        B,
                        _,
                        R,
                        nested::RevdotParameters<C::Profile>,
                    >(&claims.a, &claims.b)
                });
                let wy = span("ie.nested.registry_y", || {
                    B::registry_at_y(nested_registry, nested_y)
                });
                Ok((claims, error_terms, wy, None))
            },
        );
        let (native_claims, native_error_terms, registry_wy_poly, commitment) = native?;
        let (nested_claims, nested_inner_error_terms, nested_registry_wy_poly, nested_commitment) =
            nested?;

        let native_inner_error_witness =
            native::stages::inner_error::Witness::<C, native::RevdotParameters<C::Profile>> {
                error_terms: native_error_terms,
            };
        let blind = C::CircuitField::random(|bytes| rng.fill_bytes(bytes));
        let native_rx = span("ie.rx", || {
            native::stages::inner_error::Stage::<
                C,
                R,
                HEADER_SIZE,
                native::RevdotParameters<C::Profile>,
            >::rx(blind, &native_inner_error_witness)
        })?;
        builder.set_native_inner_error_rx(native_rx);

        // The two sides' commitments are independent, and on different
        // curves. A side with a device has committed already.
        let (commitment, nested_commitment) = span("ie.commit", || {
            par_join!(
                || commitment.unwrap_or_else(|| B::sparse_commit_to_affine(
                    &registry_wy_poly,
                    host_generators
                )),
                || nested_commitment.unwrap_or_else(|| B::sparse_commit_to_affine(
                    &nested_registry_wy_poly,
                    nested_generators
                )),
            )
        });
        let registry_wy = RegistryWy {
            commitment,
            poly: registry_wy_poly,
        };
        let nested_registry_wy = NestedRegistryWy {
            commitment: nested_commitment,
            poly: nested_registry_wy_poly,
        };

        let nested_inner_error_witness = span("ie.bridge", || {
            self.compute_bridge_inner_error(rng, &registry_wy, nested_inner_error_terms, builder)
        })?;
        Ok((
            native_inner_error_witness,
            native_claims,
            registry_wy,
            nested_inner_error_witness,
            nested_claims,
            nested_registry_wy,
        ))
    }

    /// Commits the nested fold's inner error terms alongside the native
    /// inner-error and registry commitments in the bridge stage.
    fn compute_bridge_inner_error<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        registry_wy: &RegistryWy<C, R>,
        error_terms: FixedVec<
            FixedVec<
                C::ScalarField,
                NumErrorTerms<<nested::RevdotParameters<C::Profile> as Parameters>::GroupSize>,
            >,
            <nested::RevdotParameters<C::Profile> as Parameters>::NumGroups,
        >,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<nested::stages::inner_error::Witness<C::HostCurve, C::Profile>> {
        let nested_inner_error_witness = nested::stages::inner_error::Witness {
            native_inner_error: builder.native_inner_error_commitment(),
            registry_wy: registry_wy.commitment,
            error_terms,
        };
        let bridge_rx = nested::stages::inner_error::Stage::<C::HostCurve, R, C::Profile>::rx(
            C::ScalarField::random(|bytes| rng.fill_bytes(bytes)),
            &nested_inner_error_witness,
        )?;
        let bridge_commitment =
            B::sparse_commit_to_affine(&bridge_rx, C::nested_generators(self.params));
        builder.set_bridge_inner_error_rx(bridge_rx, bridge_commitment);

        Ok(nested_inner_error_witness)
    }
}

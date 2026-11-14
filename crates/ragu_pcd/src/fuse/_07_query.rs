//! Commit to the polynomial query claims at various points ($x$, $xz$, $w$, and
//! $\omega^i$ for various internal circuits).
//!
//! This sets the native `query` stage containing the claimed evaluations at
//! various points that are then relied on in the revdot claims infrastructure.
//! (See the `compute_v` circuit.)
//!
//! This phase of the fuse operation is also used to commit to the $m(W, x, y)$
//! restriction.
//!
//! The nested counterparts are computed here as well: the nested query values
//! at $x_n z_n$, $x_n$ and $w_n$ ride inside the `query` bridge stage, and
//! the $m_n(W, x_n, y_n)$ restriction is stored on the proof; its
//! nested-curve commitment enters the native points stage committed before
//! $u$ (see `_08_f`).

use ragu_circuits::{polynomials::Rank, staging::StageExt};
use ragu_core::{Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::{Element, vec::FixedVec};
use rand::CryptoRng;
use udon::{fft::bit_reverse, field::Field};

use super::{
    _04_inner_error::{NestedRegistryWy, RegistryWy},
    device::{Devices, evaluations, registry_wxy_over_domain},
};
use crate::{
    Application, Proof,
    internal::{native, nested},
    multicore::par_join,
    profile::ProfiledCycle,
    proof::ProofBuilder,
    timing::span,
};

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    pub(super) fn compute_query<'dr, D, RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        w: &Element<'dr, D>,
        x: &Element<'dr, D>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        registry_wy: &RegistryWy<C, R>,
        nested_registry_wy: &NestedRegistryWy<C, R>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        devices: &mut Devices<'_, C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<(
        native::stages::query::Witness<C>,
        nested::stages::query::Evaluations<C::ScalarField, C::Profile>,
    )>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        // Everything up to the stages' blindings reads only the challenges
        // and polynomials that are already fixed: each registry over its
        // domain, on its side's device where that holds the registry's wiring
        // matrices, then its interpolation and the openings. The two sides
        // run together. The nested side works at the nested counterparts of
        // the challenges, whose derivation is reported where the nested
        // query is assembled below.
        let native_w = *w.value().take();
        let native_x = *x.value().take();
        let native_y = *y.value().take();
        let native_z = *z.value().take();
        let (native_full, nested_full) = (&self.native_registry, &self.nested_registry);
        let (mut native_device, mut nested_device) =
            (devices.native.as_deref_mut(), devices.nested.as_deref_mut());
        let (native_held, nested_held) = (&devices.native_held, &devices.nested_held);
        let (host_generators, nested_generators) = (
            C::host_generators(self.params),
            C::nested_generators(self.params),
        );
        let (native, nested) = span("q.evaluations", || {
            par_join!(
                || {
                    let (w, x, y) = (native_w, native_x, native_y);
                    let xz = x * native_z;
                    let registry_xy_evals = span("q.native.domain", || {
                        native_device
                            .as_deref_mut()
                            .and_then(|device| registry_wxy_over_domain(device, native_full, x, y))
                            .unwrap_or_else(|| B::registry_wxy_over_domain(native_full, x, y))
                    });
                    let log2_n = native_full.log2_domain();

                    let fixed_registry =
                        native::InternalCircuitValues::<_, C::Profile>::from_fn(|id| {
                            let i = usize::from(id.circuit_index::<C::Profile>()) as u32;
                            registry_xy_evals[bit_reverse(i as usize, log2_n)]
                        });
                    let registry_xy_poly = span("q.native.interpolate", || {
                        B::registry_interpolate_xy(native_full, registry_xy_evals)
                    });

                    // Evaluate the registry polynomial at w and the children's
                    // openings: on the device from the polynomials it holds,
                    // or on the host, concurrently.
                    let mut native_commitment = None;
                    let (registry_wxy, left_witness, right_witness) = match native_device {
                        Some(device) => {
                            let child = |proof| {
                                native::stages::query::ChildEvaluationsWitness::openings(
                                    proof,
                                    w,
                                    x,
                                    xz,
                                    &registry_xy_poly,
                                    &registry_wy.poly,
                                )
                            };
                            let mut openings = alloc::vec![(&registry_xy_poly, w)];
                            openings.extend(child(left));
                            openings.extend(child(right));
                            // The restriction is committed to while it
                            // and the children are opened.
                            let (values, commitment) =
                                par_join!(|| evaluations(device, native_held, &openings), || {
                                    B::sparse_commit_to_affine(&registry_xy_poly, host_generators)
                                },);
                            native_commitment = Some(commitment);
                            let mut values = values.into_iter();
                            (
                                values.next().expect("one value per opening"),
                                native::stages::query::ChildEvaluationsWitness::from_values(
                                    &mut values,
                                ),
                                native::stages::query::ChildEvaluationsWitness::from_values(
                                    &mut values,
                                ),
                            )
                        }
                        None => {
                            par_join!(
                                || B::sparse_eval(&registry_xy_poly, w),
                                || native::stages::query::ChildEvaluationsWitness::from_proof::<
                                    C,
                                    R,
                                    B,
                                >(
                                    left, w, x, xz, &registry_xy_poly, &registry_wy.poly,
                                ),
                                || native::stages::query::ChildEvaluationsWitness::from_proof::<
                                    C,
                                    R,
                                    B,
                                >(
                                    right, w, x, xz, &registry_xy_poly, &registry_wy.poly,
                                ),
                            )
                        }
                    };
                    (
                        fixed_registry,
                        registry_xy_poly,
                        registry_wxy,
                        left_witness,
                        right_witness,
                        native_commitment,
                    )
                },
                || -> Result<_> {
                    let w = nested::challenge::<C>(native_w)?;
                    let x = nested::challenge::<C>(native_x)?;
                    let y = nested::challenge::<C>(native_y)?;
                    let xz = x * nested::challenge::<C>(native_z)?;

                    let registry_xy_evals = span("q.nested.domain", || {
                        nested_device
                            .as_deref_mut()
                            .and_then(|device| registry_wxy_over_domain(device, nested_full, x, y))
                            .unwrap_or_else(|| B::registry_wxy_over_domain(nested_full, x, y))
                    });
                    let log2_n = nested_full.log2_domain();

                    let all = nested::InternalCircuitIndex::all::<C::Profile>();
                    let fixed_registry = FixedVec::from_fn(|i| {
                        let id = all[i];
                        let j = usize::from(id.circuit_index::<C::Profile>()) as u32;
                        registry_xy_evals[bit_reverse(j as usize, log2_n)]
                    });
                    let registry_xy_poly = span("q.nested.interpolate", || {
                        B::registry_interpolate_xy(nested_full, registry_xy_evals)
                    });

                    let mut nested_commitment = None;
                    let (registry_wxy, left_witness, right_witness) = match nested_device {
                        Some(device) => {
                            let child = |proof| {
                                nested::stages::query::ChildEvaluationsWitness::openings(
                                    proof,
                                    w,
                                    x,
                                    xz,
                                    &nested_registry_wy.poly,
                                )
                            };
                            let mut openings = alloc::vec![(&registry_xy_poly, w)];
                            openings.extend(child(left)?);
                            openings.extend(child(right)?);
                            let (values, commitment) =
                                par_join!(|| evaluations(device, nested_held, &openings), || {
                                    B::sparse_commit_to_affine(&registry_xy_poly, nested_generators)
                                },);
                            nested_commitment = Some(commitment);
                            let mut values = values.into_iter();
                            (
                                values.next().expect("one value per opening"),
                                nested::stages::query::ChildEvaluationsWitness::from_values(
                                    &mut values,
                                ),
                                nested::stages::query::ChildEvaluationsWitness::from_values(
                                    &mut values,
                                ),
                            )
                        }
                        None => {
                            let (registry_wxy, left_witness, right_witness) = par_join!(
                                || B::sparse_eval(&registry_xy_poly, w),
                                || nested::stages::query::ChildEvaluationsWitness::from_proof::<
                                    C,
                                    R,
                                    B,
                                >(
                                    left, w, x, xz, &nested_registry_wy.poly
                                ),
                                || nested::stages::query::ChildEvaluationsWitness::from_proof::<
                                    C,
                                    R,
                                    B,
                                >(
                                    right, w, x, xz, &nested_registry_wy.poly
                                ),
                            );
                            (registry_wxy, left_witness?, right_witness?)
                        }
                    };
                    Ok((
                        nested::stages::query::Evaluations {
                            fixed_registry,
                            registry_wxy,
                            left: left_witness,
                            right: right_witness,
                        },
                        registry_xy_poly,
                        nested_commitment,
                    ))
                },
            )
        });

        // The native query stage.
        let (
            fixed_registry,
            registry_xy_poly,
            registry_wxy,
            left_witness,
            right_witness,
            native_commitment,
        ) = native;
        let query_witness = native::stages::query::Witness {
            fixed_registry,
            registry_wxy,
            left: left_witness,
            right: right_witness,
            online: *builder.online_openings(),
        };
        let rx = native::stages::query::Stage::<C, R, HEADER_SIZE>::rx(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            &query_witness,
        )?;
        builder.set_native_query_rx(rx);
        builder.set_native_registry_xy_poly(registry_xy_poly);

        // The nested query values and the $m_n(W, x_n, y_n)$ restriction,
        // and the `query` bridge stage carrying the values, which is built
        // once the native commitments it also carries exist.
        let (nested_query, nested_registry_xy_poly, nested_commitment) = nested?;
        builder.set_nested_registry_xy_poly(nested_registry_xy_poly);
        builder.set_registry_xy_commitments(native_commitment, nested_commitment);

        // The bridge below reads the two native commitments just set, and
        // the nested restriction's is read before $u$: those a device side
        // has not committed to already go together, one backend call per
        // curve.
        builder.precommit_together()?;

        let bridge_rx = nested::stages::query::Stage::<C::HostCurve, R, C::Profile>::rx(
            C::ScalarField::random(|bytes| rng.fill_bytes(bytes)),
            &nested::stages::query::Witness {
                native_query: builder.native_query_commitment(),
                registry_xy: builder.native_registry_xy_commitment(),
                nested: nested_query.clone(),
            },
        )?;
        let bridge_commitment =
            B::sparse_commit_to_affine(&bridge_rx, C::nested_generators(self.params));
        builder.set_bridge_query_rx(bridge_rx, bridge_commitment);

        Ok((query_witness, nested_query))
    }
}

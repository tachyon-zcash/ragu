//! Commit to the polynomial query claims at various points (typically $x$,
//! $xz$, $w$).
//!
//! This creates the [`proof::Query`] component of the proof, which contains
//! claimed evaluations (corresponding to each polynomial query) usually at
//! points like $x$, $xz$, and $w$.
//!
//! This phase of the fuse operation is also used to commit to the $m(W, x, y)$
//! restriction.

use ff::Field;
use ragu_arithmetic::Cycle;
use ragu_circuits::{polynomials::Rank, staging::StageExt};
use ragu_core::{Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::Element;
use rand::CryptoRng;

use crate::{
    Application, Proof,
    internal::{native, nested},
    proof,
};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    pub(super) fn compute_query<'dr, D, RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        w: &Element<'dr, D>,
        x: &Element<'dr, D>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        inner_error: &proof::InnerError<C, R>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
    ) -> Result<(proof::Query<C, R>, native::stages::query::Witness<C>)>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let (native_query, query_witness) =
            self.compute_native_query(rng, w, x, y, z, inner_error, left, right)?;

        let bridge = proof::Bridge::commit(
            self.params,
            rng,
            nested::stages::query::Stage::<C::HostCurve, R>::rx(&nested::stages::query::Witness {
                native_query: native_query.rx_triple.commitment,
                registry_xy: native_query.registry_xy_commitment,
            })?,
        );

        Ok((
            proof::Query {
                native: native_query,
                bridge,
            },
            query_witness,
        ))
    }

    fn compute_native_query<'dr, D, RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        w: &Element<'dr, D>,
        x: &Element<'dr, D>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        inner_error: &proof::InnerError<C, R>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
    ) -> Result<(proof::NativeQuery<C, R>, native::stages::query::Witness<C>)>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let w = *w.value().take();
        let x = *x.value().take();
        let y = *y.value().take();
        let xz = x * *z.value().take();

        let registry_xy_poly = self.native_registry.xy(x, y);
        let registry_xy_blind = C::CircuitField::random(&mut *rng);

        // Evaluate the registry polynomial at all internal-circuit points and
        // at w concurrently with the left/right child witness construction.
        let ((fixed_registry, registry_wxy), (left_witness, right_witness)) = maybe_rayon::join(
            || {
                (
                    // TODO: these evaluations could be batched by the registry more efficiently in theory.
                    native::InternalCircuitValues::from_fn(|id| {
                        registry_xy_poly.eval(id.circuit_index().omega_j())
                    }),
                    registry_xy_poly.eval(w),
                )
            },
            || {
                maybe_rayon::join(
                    || {
                        native::stages::query::ChildEvaluationsWitness::from_proof(
                            left,
                            w,
                            x,
                            xz,
                            &registry_xy_poly,
                            &inner_error.native.registry_wy_poly,
                        )
                    },
                    || {
                        native::stages::query::ChildEvaluationsWitness::from_proof(
                            right,
                            w,
                            x,
                            xz,
                            &registry_xy_poly,
                            &inner_error.native.registry_wy_poly,
                        )
                    },
                )
            },
        );
        let query_witness = native::stages::query::Witness {
            fixed_registry,
            registry_wxy,
            left: left_witness,
            right: right_witness,
        };

        let rx = native::stages::query::Stage::<C, R, HEADER_SIZE>::rx(&query_witness)?;
        let blind = C::CircuitField::random(&mut *rng);
        let host_gen = C::host_generators(self.params);
        let [registry_xy_commitment, commitment] = ragu_arithmetic::batch_to_affine([
            registry_xy_poly.commit(host_gen, registry_xy_blind),
            rx.commit(host_gen, blind),
        ]);

        Ok((
            proof::NativeQuery {
                registry_xy_poly,
                registry_xy_blind,
                registry_xy_commitment,
                rx_triple: proof::RxTriple {
                    rx,
                    blind,
                    commitment,
                },
            },
            query_witness,
        ))
    }
}

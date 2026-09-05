//! Commit to the polynomial query claims at various points ($x$, $xz$, $w$, and
//! $\omega^i$ for various internal circuits).
//!
//! This sets the native `query` stage containing the claimed evaluations at
//! various points that are then relied on in the revdot claims infrastructure.
//! (See the `compute_v` circuit.)
//!
//! This phase of the fuse operation is also used to commit to the $m(W, x, y)$
//! restriction.

use ragu_arithmetic::{Cycle, bitreverse, ff::Field, par_join, rand::CryptoRng};
use ragu_circuits::{polynomials::Rank, staging::StageExt};
use ragu_core::{Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::Element;

use super::RegistryWy;
use crate::{Application, Proof, internal::native, proof::ProofBuilder};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
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
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<native::stages::query::Witness<C>>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let w = *w.value().take();
        let x = *x.value().take();
        let y = *y.value().take();
        let xz = x * *z.value().take();

        let registry_xy_evals = B::registry_wxy_over_domain(&self.native_registry, x, y);
        let log2_n = self.native_registry.log2_domain();

        let fixed_registry = native::InternalCircuitValues::from_fn(|id| {
            let i = usize::from(id.circuit_index()) as u32;
            registry_xy_evals[bitreverse(i, log2_n) as usize]
        });
        let registry_xy_poly = B::registry_interpolate_xy(&self.native_registry, registry_xy_evals);

        // Evaluate the registry polynomial at w concurrently with the
        // left/right child witness construction.
        let (registry_wxy, left_witness, right_witness) = par_join!(
            || B::sparse_eval(&registry_xy_poly, w),
            || native::stages::query::ChildEvaluationsWitness::from_proof::<C, R, B>(
                left,
                w,
                x,
                xz,
                &registry_xy_poly,
                &registry_wy.poly,
            ),
            || native::stages::query::ChildEvaluationsWitness::from_proof::<C, R, B>(
                right,
                w,
                x,
                xz,
                &registry_xy_poly,
                &registry_wy.poly,
            ),
        );

        let query_witness = native::stages::query::Witness {
            fixed_registry,
            registry_wxy,
            left: left_witness,
            right: right_witness,
        };

        let rx = native::stages::query::Stage::<C, R, HEADER_SIZE>::rx(
            C::CircuitField::random(&mut *rng),
            &query_witness,
        )?;

        builder.set_native_query_rx(rx);
        builder.set_native_registry_xy_poly(registry_xy_poly);

        Ok(query_witness)
    }
}

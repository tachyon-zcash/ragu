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
use ragu_core::{Cycle, Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::{
    Element,
    vec::{FixedVec, Len},
};
use rand::CryptoRng;
use udon::{fft::bit_reverse, field::Field};

use super::{NestedRegistryWy, RegistryWy};
use crate::{
    Application, Proof,
    internal::{native, nested},
    multicore::par_join,
    proof::ProofBuilder,
};

impl<
    C: Cycle,
    R: Rank,
    const HEADER_SIZE: usize,
    J: crate::framework_hooks::HookConfig,
    B: crate::SelectableBackend,
> Application<'_, C, R, HEADER_SIZE, J, B>
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
        builder: &mut ProofBuilder<'_, C, R, J, B>,
    ) -> Result<(
        native::stages::query::Witness<C>,
        nested::stages::query::Evaluations<C::ScalarField, J::PolyWitnesses>,
    )>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let query_witness =
            self.compute_native_query(rng, w, x, y, z, registry_wy, left, right, builder)?;
        let nested_query =
            self.compute_nested_query(rng, w, x, y, z, nested_registry_wy, left, right, builder)?;
        Ok((query_witness, nested_query))
    }

    fn compute_native_query<'dr, D, RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        w: &Element<'dr, D>,
        x: &Element<'dr, D>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        registry_wy: &RegistryWy<C, R>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        builder: &mut ProofBuilder<'_, C, R, J, B>,
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

        let polys = J::PolyWitnesses::len();
        let fixed_registry = native::InternalCircuitValues::from_fn(polys, |id| {
            let i = usize::from(id.circuit_index(polys)) as u32;
            registry_xy_evals[bit_reverse(i as usize, log2_n)]
        });
        let registry_xy_poly = B::registry_interpolate_xy(&self.native_registry, registry_xy_evals);

        // Evaluate the registry polynomial at w concurrently with the
        // left/right child witness construction.
        let (registry_wxy, left_witness, right_witness) = par_join!(
            || B::sparse_eval(&registry_xy_poly, w),
            || native::stages::query::ChildEvaluationsWitness::from_proof::<C, R, B>(
                polys,
                left,
                w,
                x,
                xz,
                &registry_xy_poly,
                &registry_wy.poly,
            ),
            || native::stages::query::ChildEvaluationsWitness::from_proof::<C, R, B>(
                polys,
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

        let rx = native::stages::query::Stage::<C, R, HEADER_SIZE, J>::rx(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            &query_witness,
        )?;

        builder.set_native_query_rx(rx);
        builder.set_native_registry_xy_poly(registry_xy_poly);

        Ok(query_witness)
    }

    /// Computes the nested query values and the $m_n(W, x_n, y_n)$
    /// restriction, and commits the `query` bridge stage carrying the values.
    ///
    /// Runs after the native query so the native commitments the bridge also
    /// carries already exist.
    fn compute_nested_query<'dr, D, RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        w: &Element<'dr, D>,
        x: &Element<'dr, D>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        nested_registry_wy: &NestedRegistryWy<C, R>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        builder: &mut ProofBuilder<'_, C, R, J, B>,
    ) -> Result<nested::stages::query::Evaluations<C::ScalarField, J::PolyWitnesses>>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let w = nested::challenge::<C>(*w.value().take())?;
        let x = nested::challenge::<C>(*x.value().take())?;
        let y = nested::challenge::<C>(*y.value().take())?;
        let xz = x * nested::challenge::<C>(*z.value().take())?;

        let registry_xy_evals = B::registry_wxy_over_domain(&self.nested_registry, x, y);
        let log2_n = self.nested_registry.log2_domain();

        let polys = J::PolyWitnesses::len();
        let ids: alloc::vec::Vec<_> = nested::InternalCircuitIndex::all(polys).collect();
        let fixed_registry = FixedVec::from_fn(|i| {
            let id = ids[i];
            let j = usize::from(id.circuit_index(polys)) as u32;
            registry_xy_evals[bit_reverse(j as usize, log2_n)]
        });
        let registry_xy_poly = B::registry_interpolate_xy(&self.nested_registry, registry_xy_evals);

        let (registry_wxy, left_witness, right_witness) = par_join!(
            || B::sparse_eval(&registry_xy_poly, w),
            || nested::stages::query::ChildEvaluationsWitness::from_proof::<C, R, B>(
                left,
                w,
                x,
                xz,
                &nested_registry_wy.poly,
            ),
            || nested::stages::query::ChildEvaluationsWitness::from_proof::<C, R, B>(
                right,
                w,
                x,
                xz,
                &nested_registry_wy.poly,
            ),
        );

        let nested_query = nested::stages::query::Evaluations {
            fixed_registry,
            registry_wxy,
            left: left_witness?,
            right: right_witness?,
        };

        builder.set_nested_registry_xy_poly(registry_xy_poly);

        let bridge_rx = nested::stages::query::Stage::<C::HostCurve, R, J::PolyWitnesses>::rx(
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

        Ok(nested_query)
    }
}

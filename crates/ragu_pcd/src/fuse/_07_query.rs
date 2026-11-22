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

use alloc::vec::Vec;

use ragu_circuits::{Blind, polynomials::Rank, staging::StageExt};
use ragu_core::{Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::{Element, vec::FixedVec};
use rand::CryptoRng;
use udon::fft::bit_reverse;

use super::{
    _01_application::NativeApplication,
    _04_inner_error::{NestedRegistryWy, RegistryWy},
    randomizer::{NativeRandomizer, NestedRandomizer, Randomizers},
};
use crate::{
    Application, Proof,
    internal::{
        native,
        nested::{self, online as online_fq},
    },
    multicore::par_join,
    profile::ProfiledCycle,
    proof::ProofBuilder,
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
        application: &NativeApplication<C, R>,
        randomizers: &Randomizers<C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<(
        native::stages::query::Witness<C>,
        nested::stages::query::Evaluations<C::ScalarField, C::Profile>,
    )>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let query_witness = self.compute_native_query(
            rng,
            w,
            x,
            y,
            z,
            registry_wy,
            left,
            right,
            application,
            &randomizers.native,
            builder,
        )?;
        let nested_query = self.compute_nested_query(
            rng,
            w,
            x,
            y,
            z,
            nested_registry_wy,
            left,
            right,
            &randomizers.nested,
            builder,
        )?;
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
        application: &NativeApplication<C, R>,
        randomizer: &NativeRandomizer<C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<native::stages::query::Witness<C>>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let w = *w.value().take();
        let x = *x.value().take();
        let y = *y.value().take();
        let xz = x * *z.value().take();
        // The fold randomizers, opened as a child's a and b are.
        let randomizer_a_at_xz = B::sparse_eval(&randomizer.a, xz);
        let randomizer_b_at_x = B::sparse_eval(&randomizer.b, x);

        let registry_xy_evals = B::registry_wxy_over_domain(&self.native_registry, x, y);
        let log2_n = self.native_registry.log2_domain();

        let fixed_registry = native::InternalCircuitValues::<_, C::Profile>::from_fn(|id| {
            let i = usize::from(id.circuit_index::<C::Profile>()) as u32;
            registry_xy_evals[bit_reverse(i as usize, log2_n)]
        });
        let registry_xy_poly = B::registry_interpolate_xy(&self.native_registry, registry_xy_evals);

        // Evaluate the registry polynomial at w and at the step's own circuit
        // id, and the step's own application trace and stage at xz,
        // concurrently with the left/right child witness construction.
        let (
            (registry_wxy, registry_xy_at_circuit_id, application_at_xz, application_stage_at_xz),
            left_witness,
            right_witness,
        ) = par_join!(
            || (
                B::sparse_eval(&registry_xy_poly, w),
                B::sparse_eval(&registry_xy_poly, application.circuit_id.omega_j()),
                B::sparse_eval(&application.rx, xz),
                B::sparse_eval(&application.stage.rx, xz),
            ),
            || native::stages::query::ChildEvaluationsWitness::from_proof::<C, R, B>(
                left,
                w,
                x,
                xz,
                &registry_wy.poly,
            ),
            || native::stages::query::ChildEvaluationsWitness::from_proof::<C, R, B>(
                right,
                w,
                x,
                xz,
                &registry_wy.poly,
            ),
        );

        let query_witness = native::stages::query::Witness {
            online_auxiliaries: builder.nested_online_auxiliary_coordinates(),
            online_stage: builder.nested_online_stage_coordinates(1),
            fixed_registry,
            registry_wxy,
            registry_xy_at_circuit_id,
            application_at_xz,
            application_stage_at_xz,
            randomizer_a_at_xz,
            randomizer_b_at_x,
            left: left_witness,
            right: right_witness,
        };

        let rx = native::stages::query::Stage::<C, R, HEADER_SIZE>::rx(
            Blind::random(rng),
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
        randomizer: &NestedRandomizer<C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<nested::stages::query::Evaluations<C::ScalarField, C::Profile>>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let w = nested::challenge::<C>(*w.value().take())?;
        let x = nested::challenge::<C>(*x.value().take())?;
        let y = nested::challenge::<C>(*y.value().take())?;
        let xz = x * nested::challenge::<C>(*z.value().take())?;

        let registry_xy_evals = B::registry_wxy_over_domain(&self.nested_registry, x, y);
        let log2_n = self.nested_registry.log2_domain();

        let all = nested::InternalCircuitIndex::all::<C::Profile>();
        let fixed_registry = FixedVec::from_fn(|i| {
            let id = all[i];
            let j = usize::from(id.circuit_index::<C::Profile>()) as u32;
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

        // The value of each online Fq polynomial at its opening point.
        let online_fq_point = online_fq::point(w);
        let online_fq = FixedVec::try_from(
            online_fq::openings(builder.online_fq_polynomials().len())
                .map(|opening| {
                    let poly = &builder.online_fq_polynomials()[opening.polynomial];
                    let value = B::sparse_eval(poly, online_fq_point);
                    // Test hook: this runs on the thread that calls `fuse`,
                    // outside its parallel jobs, as the hook's thread-local
                    // requires.
                    #[cfg(test)]
                    let value = crate::online_fq_oracles_tests::mutate_query_value(value);
                    value
                })
                .collect::<Vec<_>>(),
        )?;
        // The openings the step exports, for a profile whose nested
        // binding names any: the point the nested `compute_v` opens at,
        // the challenge stage's lift of w, then the value the query stage
        // holds.
        builder.set_online_fq_openings(
            online_fq::bound_openings::<C::Profile>()
                .iter()
                .flat_map(|&slot| [w, online_fq[slot as usize]])
                .collect(),
        );
        let nested_query = nested::stages::query::Evaluations {
            fixed_registry,
            registry_wxy,
            randomizer_a_at_xz: B::sparse_eval(&randomizer.a, xz),
            randomizer_b_at_x: B::sparse_eval(&randomizer.b, x),
            left: left_witness?,
            right: right_witness?,
            online_fq,
        };

        builder.set_nested_registry_xy_poly(registry_xy_poly);

        let bridge_rx = nested::stages::query::Stage::<C::HostCurve, R, C::Profile>::rx(
            Blind::random(rng),
            &nested::stages::query::Witness {
                online_points: builder.native_online_phase::<3>(),
                online_stage: ragu_primitives::vec::FixedVec::from_fn(|_| {
                    builder.native_online_stage_commitment(1)
                }),
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

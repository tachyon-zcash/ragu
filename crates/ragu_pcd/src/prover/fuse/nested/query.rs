//! Nested query prover phase.
use alloc::vec::Vec;

use ragu_circuits::{polynomials::Rank, staging::StageExt};
use ragu_core::{Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::{Element, vec::FixedVec};
use rand::CryptoRng;
use udon::{fft::bit_reverse, field::Field};

use crate::{
    Application, Proof,
    profile::ProfiledCycle,
    protocol::{nested, nested::online as online_fq},
    prover::{
        fuse::nested::inner_error::NestedRegistryWy, multicore::par_join,
        proof_builder::ProofBuilder,
    },
};

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// Computes the nested query values and the $m_n(W, x_n, y_n)$
    /// restriction, and commits the `query` bridge stage carrying the values.
    ///
    /// Runs after the native query so the native commitments the bridge also
    /// carries already exist.
    pub(in crate::prover::fuse) fn compute_nested_query<'dr, D, RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        w: &Element<'dr, D>,
        x: &Element<'dr, D>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        nested_registry_wy: &NestedRegistryWy<C, R>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<
        crate::verifier::recursive::nested::stages::query::Evaluations<C::ScalarField, C::Profile>,
    >
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
            || {
                crate::verifier::recursive::nested::stages::query::ChildEvaluationsWitness::from_proof::<C, R, B>(
                left,
                w,
                x,
                xz,
                &nested_registry_wy.poly,
            )
            },
            || {
                crate::verifier::recursive::nested::stages::query::ChildEvaluationsWitness::from_proof::<C, R, B>(
                right,
                w,
                x,
                xz,
                &nested_registry_wy.poly,
            )
            },
        );

        // The value of each online Fq polynomial at its opening point.
        let online_fq_point = online_fq::point(w);
        let online_fq = FixedVec::try_from(
            builder
                .online_fq_polynomials()
                .iter()
                .map(|poly| {
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
        let nested_query = crate::verifier::recursive::nested::stages::query::Evaluations {
            fixed_registry,
            registry_wxy,
            left: left_witness?,
            right: right_witness?,
            online_fq,
        };

        builder.set_nested_registry_xy_poly(registry_xy_poly);

        let bridge_rx = crate::verifier::recursive::nested::stages::query::Stage::<
            C::HostCurve,
            R,
            C::Profile,
        >::rx(
            C::ScalarField::random(|bytes| rng.fill_bytes(bytes)),
            &crate::verifier::recursive::nested::stages::query::Witness {
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

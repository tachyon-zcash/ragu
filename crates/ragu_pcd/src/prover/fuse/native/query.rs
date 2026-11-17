//! Native query prover phase.

use ragu_circuits::{polynomials::Rank, staging::StageExt};
use ragu_core::{Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::Element;
use rand::CryptoRng;
use udon::{fft::bit_reverse, field::Field};

use crate::{
    Application, Proof,
    profile::ProfiledCycle,
    protocol::native,
    prover::{
        fuse::native::inner_error::RegistryWy, multicore::par_join, proof_builder::ProofBuilder,
    },
};

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    pub(in crate::prover::fuse) fn compute_native_query<'dr, D, RNG: CryptoRng>(
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
    ) -> Result<crate::verifier::recursive::native::stages::query::Witness<C>>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let w = *w.value().take();
        let x = *x.value().take();
        let y = *y.value().take();
        let xz = x * *z.value().take();

        let registry_xy_evals = B::registry_wxy_over_domain(&self.native_registry, x, y);
        let log2_n = self.native_registry.log2_domain();

        let fixed_registry = native::InternalCircuitValues::<_, C::Profile>::from_fn(|id| {
            let i = usize::from(id.circuit_index::<C::Profile>()) as u32;
            registry_xy_evals[bit_reverse(i as usize, log2_n)]
        });
        let registry_xy_poly = B::registry_interpolate_xy(&self.native_registry, registry_xy_evals);

        // Evaluate the registry polynomial at w concurrently with the
        // left/right child witness construction.
        let (registry_wxy, left_witness, right_witness) = par_join!(
            || B::sparse_eval(&registry_xy_poly, w),
            || {
                crate::verifier::recursive::native::stages::query::ChildEvaluationsWitness::from_proof::<C, R, B>(
                left,
                w,
                x,
                xz,
                &registry_xy_poly,
                &registry_wy.poly,
            )
            },
            || {
                crate::verifier::recursive::native::stages::query::ChildEvaluationsWitness::from_proof::<C, R, B>(
                right,
                w,
                x,
                xz,
                &registry_xy_poly,
                &registry_wy.poly,
            )
            },
        );

        let query_witness = crate::verifier::recursive::native::stages::query::Witness {
            fixed_registry,
            registry_wxy,
            left: left_witness,
            right: right_witness,
            online: *builder.online_openings(),
        };

        let rx = crate::verifier::recursive::native::stages::query::Stage::<C, R, HEADER_SIZE>::rx(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            &query_witness,
        )?;

        builder.set_native_query_rx(rx);
        builder.set_native_registry_xy_poly(registry_xy_poly);

        Ok(query_witness)
    }
}

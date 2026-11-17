//! Nested circuits prover phase.

use ragu_circuits::{CircuitExt, polynomials::Rank, staging::MultiStage};
use ragu_core::{Error, Result};
use ragu_primitives::Uendo;
use rand::CryptoRng;

use crate::{
    Application,
    header::NUM_ONLINE_FP_POLYS,
    profile::{Profile, ProfiledCycle},
    protocol::nested,
    prover::proof_builder::ProofBuilder,
};

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// Traces this step's nested internal instance circuits, assembles their
    /// Rx polynomials, and stores them in the proof builder.
    ///
    /// Traces the collapse and compute-v circuits with the saved nested
    /// stage witnesses. Their shared instance accumulates coverage, which
    /// must be complete after both circuits. The endoscaling traces
    /// are produced earlier by [`Self::compute_p`].
    pub(in crate::prover::fuse) fn compute_nested_internal_circuits<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        nested_endoscalar: Uendo,
        nested_points: &nested::PointsWitness<C::HostCurve, C::Profile>,
        nested_preamble_witness: &crate::verifier::recursive::nested::stages::preamble::Witness<
            C::HostCurve,
            C::Profile,
        >,
        nested_s_prime_witness: &crate::verifier::recursive::nested::stages::s_prime::Witness<
            C::HostCurve,
        >,
        nested_inner_error_witness: &crate::verifier::recursive::nested::stages::inner_error::Witness<C::HostCurve, C::Profile>,
        nested_outer_error_witness: &crate::verifier::recursive::nested::stages::outer_error::Witness<C::HostCurve, C::Profile>,
        nested_ab_witness: &crate::verifier::recursive::nested::stages::ab::Witness<C::HostCurve>,
        nested_query_witness: &crate::verifier::recursive::nested::stages::query::Witness<
            C::HostCurve,
            C::Profile,
        >,
        nested_f_witness: &crate::verifier::recursive::nested::stages::f::Witness<C::HostCurve>,
        nested_eval_witness: &crate::verifier::recursive::nested::stages::eval::Witness<
            C::HostCurve,
            C::Profile,
        >,
        nested_challenges_witness: &crate::verifier::recursive::nested::stages::challenges::Witness<
            C::ScalarField,
        >,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        let instance = nested::unified::Instance {
            c: builder.nested_c(),
            v: builder.nested_v()?,
            x: nested::challenge::<C>(builder.x())?,
            y: nested::challenge::<C>(builder.y())?,
            u: nested::challenge::<C>(builder.u())?,
            exported: [
                builder.native_preamble_commitment(),
                builder.native_inner_error_commitment(),
                builder.native_outer_error_commitment(),
                builder.native_query_commitment(),
                builder.native_eval_commitment(),
                builder.native_a_commitment(),
                builder.native_b_commitment(),
                builder.native_registry_xy_commitment(),
                builder.native_p_commitment(),
                builder.native_points_binding_commitment(),
                builder.native_points_preamble_commitment(),
                builder.native_points_registry_wx_commitment(),
                builder.native_points_ab_commitment(),
                builder.native_points_f_commitment(),
                builder.online_commitments()[0],
                builder.online_commitments()[1],
                builder.native_application_stage_commitment(),
            ],
            coverage: Default::default(),
        };
        let witness = |instance| crate::verifier::recursive::nested::circuits::common::Witness {
            instance,
            endoscalar: nested_endoscalar,
            bridge_hash: builder.online_commitments()[NUM_ONLINE_FP_POLYS - 1],
            points: nested_points,
            preamble: nested_preamble_witness,
            s_prime: nested_s_prime_witness,
            inner_error: nested_inner_error_witness,
            outer_error: nested_outer_error_witness,
            ab: nested_ab_witness,
            query: nested_query_witness,
            f: nested_f_witness,
            eval: nested_eval_witness,
            challenges: nested_challenges_witness,
        };

        let (collapse_trace, instance) = MultiStage::new(
            crate::verifier::recursive::nested::circuits::collapse::Circuit::<
                C::HostCurve,
                R,
                C::Profile,
            >::new(),
        )
        .trace(witness(instance))?
        .into_parts();
        let collapse_rx = self.nested_registry.assemble(
            &collapse_trace,
            nested::InternalCircuitIndex::Collapse.circuit_index::<C::Profile>(),
            &mut *rng,
        )?;

        let (compute_v_trace, instance) = MultiStage::new(
            crate::verifier::recursive::nested::circuits::compute_v::Circuit::<
                C::HostCurve,
                R,
                C::Profile,
            >::new(),
        )
        .trace(witness(instance))?
        .into_parts();
        let compute_v_rx = self.nested_registry.assemble(
            &compute_v_trace,
            nested::InternalCircuitIndex::ComputeV.circuit_index::<C::Profile>(),
            &mut *rng,
        )?;

        // As for the native instance: every slot covered exactly once.
        instance.assert_complete();

        builder.set_nested_collapse_rx(collapse_rx);
        builder.set_nested_compute_v_rx(compute_v_rx);

        let extension = C::Profile::nested_extension();
        let rxs = C::Profile::nested_extension_rxs::<C::Base, R, HEADER_SIZE, B, RNG>(
            &self.context,
            &self.nested_registry,
            rng,
        )?;
        if rxs.circuits.len() != extension.circuits.len() || rxs.stages.len() != extension.stages {
            return Err(Error::Initialization(
                "the profile's prover did not fill its nested extension".into(),
            ));
        }
        builder.set_nested_extension_circuit_rxs(rxs.circuits);
        builder.set_nested_extension_stage_rxs(rxs.stages);

        Ok(())
    }
}

//! Trace the internal circuits.
//!
//! This traces the native and nested internal circuits over the stage
//! witnesses the earlier phases saved, assembles their rx polynomials, and
//! sets them on the [`ProofBuilder`] together with the profile's extension.

use alloc::vec::Vec;

use ragu_circuits::{CircuitExt, polynomials::Rank, staging::MultiStage};
use ragu_core::{Error, Result};
use ragu_primitives::Uendo;
use rand::CryptoRng;

use super::_10_p::{NativeInputs, NativeWalk};
use crate::{
    Application,
    internal::{native, native::total_circuit_counts, nested},
    profile::{Decompressed, Profile, ProfiledCycle},
    proof::ProofBuilder,
};

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// Traces this step's native internal circuits, assembles their Rx
    /// polynomials, and stores them in the proof builder.
    ///
    /// Builds the shared native instance from the accumulated proof data and
    /// supplies the saved stage witnesses to the circuits for the transcript,
    /// folding, batch evaluation, and nested challenge and commitment binding.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn compute_native_internal_circuits<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        preamble_witness: &native::stages::preamble::Witness<'_, C, R, HEADER_SIZE>,
        native_outer_error_witness: &native::stages::outer_error::Witness<
            C,
            native::RevdotParameters<C::Profile>,
        >,
        native_inner_error_witness: &native::stages::inner_error::Witness<
            C,
            native::RevdotParameters<C::Profile>,
        >,
        query_witness: &native::stages::query::Witness<C>,
        eval_witness: &native::stages::eval::Witness<C>,
        native_points: &NativeInputs<C>,
        native_walk: &NativeWalk<C>,
        source: Option<&Decompressed<C::Base>>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        let unified = native::unified::Instance {
            bridge_preamble_commitment: builder.bridge_preamble_commitment(),
            w: builder.w(),
            bridge_s_prime_commitment: builder.bridge_s_prime_commitment(),
            y: builder.y(),
            z: builder.z(),
            bridge_inner_error_commitment: builder.bridge_inner_error_commitment(),
            mu: builder.mu(),
            bridge_outer_error_commitment: builder.bridge_outer_error_commitment(),
            mu_prime: builder.mu_prime(),
            c: builder.native_c(),
            bridge_ab_commitment: builder.bridge_ab_commitment()?,
            x: builder.x(),
            bridge_query_commitment: builder.bridge_query_commitment(),
            alpha: builder.alpha(),
            bridge_f_commitment: builder.bridge_f_commitment(),
            u: builder.u(),
            bridge_eval_commitment: builder.bridge_eval_commitment(),
            pre_beta: builder.pre_beta(),
            v: builder.v(),
            nested_challenges_partial: builder.nested_challenges_partial(),
            nested_p_commitment: builder.nested_p_commitment(),
            nested_a_commitment: builder.nested_a_commitment(),
            nested_b_commitment: builder.nested_b_commitment(),
            nested_registry_xy_commitment: builder.nested_registry_xy_commitment(),
            coverage: Default::default(),
        };

        let (hashes_1_trace, unified) = native::circuits::hashes_1::Circuit::<
            C,
            R,
            HEADER_SIZE,
            native::RevdotParameters<C::Profile>,
        >::new(
            self.params,
            total_circuit_counts::<C::Profile>(self.num_application_steps).1,
        )
        .trace(native::circuits::hashes_1::Witness {
            unified,
            preamble_witness,
            outer_error_witness: native_outer_error_witness,
        })?
        .into_parts();
        let hashes_1_rx = self.native_registry.assemble(
            &hashes_1_trace,
            native::InternalCircuitIndex::Hashes1Circuit.circuit_index::<C::Profile>(),
            &mut *rng,
        )?;

        let (hashes_2_trace, unified) = native::circuits::hashes_2::Circuit::<
            C,
            R,
            HEADER_SIZE,
            native::RevdotParameters<C::Profile>,
        >::new(self.params)
        .trace(native::circuits::hashes_2::Witness {
            unified,
            outer_error_witness: native_outer_error_witness,
        })?
        .into_parts();
        let hashes_2_rx = self.native_registry.assemble(
            &hashes_2_trace,
            native::InternalCircuitIndex::Hashes2Circuit.circuit_index::<C::Profile>(),
            &mut *rng,
        )?;

        let (collapse_trace, unified) = native::circuits::collapse::Circuit::<
            C,
            R,
            HEADER_SIZE,
            native::RevdotParameters<C::Profile>,
        >::new()
        .trace(native::circuits::collapse::Witness {
            binding: &native_points.binding,
            preamble_witness,
            unified,
            outer_error_witness: native_outer_error_witness,
            inner_error_witness: native_inner_error_witness,
        })?
        .into_parts();
        let collapse_rx = self.native_registry.assemble(
            &collapse_trace,
            native::InternalCircuitIndex::CollapseCircuit.circuit_index::<C::Profile>(),
            &mut *rng,
        )?;

        let (compute_v_trace, unified) =
            native::circuits::compute_v::Circuit::<C, R, HEADER_SIZE>::new()
                .trace(native::circuits::compute_v::Witness {
                    unified,
                    preamble_witness,
                    query_witness,
                    eval_witness,
                })?
                .into_parts();
        let compute_v_rx = self.native_registry.assemble(
            &compute_v_trace,
            native::InternalCircuitIndex::ComputeVCircuit.circuit_index::<C::Profile>(),
            &mut *rng,
        )?;

        // Native circuits binding the nested challenge stage's claimed commitment.
        let mut unified = unified;
        let mut bind_challenges_rxs = Vec::with_capacity(native::NUM_BINDERS);
        for k in 0..native::NUM_BINDERS {
            let (trace, updated) =
                crate::with_binder!(k, C, R, HEADER_SIZE, self.params, |circuit| {
                    circuit
                        .trace(native::circuits::bind_challenges::Witness {
                            unified,
                            preamble_witness,
                            query_witness,
                            eval_witness,
                        })?
                        .into_parts()
                });
            unified = updated;
            bind_challenges_rxs.push(
                self.native_registry.assemble(
                    &trace,
                    native::InternalCircuitIndex::BindChallengesCircuit(k as u32)
                        .circuit_index::<C::Profile>(),
                    &mut *rng,
                )?,
            );
        }

        builder.set_native_hashes_1_rx(hashes_1_rx);
        builder.set_native_hashes_2_rx(hashes_2_rx);
        builder.set_native_collapse_rx(collapse_rx);

        // Native circuit binding the children's nested beta commitments.
        let (bind_beta_trace, unified) =
            native::circuits::bind_beta::Circuit::<C, R, HEADER_SIZE>::new(self.params)
                .trace(native::circuits::bind_beta::Witness {
                    unified,
                    binding: &native_points.binding,
                    preamble_witness,
                })?
                .into_parts();
        let bind_beta_rx = self.native_registry.assemble(
            &bind_beta_trace,
            native::InternalCircuitIndex::BindBetaCircuit.circuit_index::<C::Profile>(),
            &mut *rng,
        )?;

        // The native walk's inputs: the bits the endoscaling steps walked
        // with are pre_beta's, and the points lie on the curve.
        let (bind_endoscalar_trace, unified) =
            native::circuits::bind_endoscalar::Circuit::<C, R>::new()
                .trace(native::circuits::bind_endoscalar::Witness {
                    unified,
                    inputs: native_points,
                    walk: native_walk,
                })?
                .into_parts();
        let bind_endoscalar_rx = self.native_registry.assemble(
            &bind_endoscalar_trace,
            native::InternalCircuitIndex::BindEndoscalarCircuit.circuit_index::<C::Profile>(),
            &mut *rng,
        )?;

        // Cross-circuit coverage validation (prover-time development assertion,
        // not a verifier check): all internal recursion circuits together must
        // cover every slot exactly once. Overlap is caught eagerly by finish();
        // missing slots are caught here.
        unified.assert_complete();

        builder.set_native_compute_v_rx(compute_v_rx);
        builder.set_native_bind_challenges_rxs(bind_challenges_rxs);
        builder.set_native_bind_beta_rx(bind_beta_rx);
        builder.set_native_bind_endoscalar_rx(bind_endoscalar_rx);

        // The profile's extension: its prover fills every circuit's and
        // stage's polynomial over the context the application holds.
        let extension = C::Profile::native_extension();
        let rxs = C::Profile::native_extension_rxs::<C::Base, R, HEADER_SIZE, B, RNG>(
            &self.context,
            source,
            &self.native_registry,
            rng,
        )?;
        if rxs.circuits.len() != extension.circuits.len() || rxs.stages.len() != extension.stages {
            return Err(Error::Initialization(
                "the profile's prover did not fill its native extension".into(),
            ));
        }
        builder.set_native_extension_circuit_rxs(rxs.circuits);
        builder.set_native_extension_stage_rxs(rxs.stages);

        Ok(())
    }

    /// Traces this step's nested internal instance circuits, assembles their
    /// Rx polynomials, and stores them in the proof builder.
    ///
    /// Traces the collapse and compute-v circuits with the saved nested
    /// stage witnesses. Their shared instance accumulates coverage, which
    /// must be complete after both circuits. The endoscaling traces
    /// are produced earlier by [`Self::compute_p`].
    pub(super) fn compute_nested_internal_circuits<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        nested_endoscalar: Uendo,
        nested_points: &nested::PointsWitness<C::HostCurve, C::Profile>,
        nested_preamble_witness: &nested::stages::preamble::Witness<C::HostCurve, C::Profile>,
        nested_s_prime_witness: &nested::stages::s_prime::Witness<C::HostCurve>,
        nested_inner_error_witness: &nested::stages::inner_error::Witness<C::HostCurve, C::Profile>,
        nested_outer_error_witness: &nested::stages::outer_error::Witness<C::HostCurve, C::Profile>,
        nested_ab_witness: &nested::stages::ab::Witness<C::HostCurve>,
        nested_query_witness: &nested::stages::query::Witness<C::HostCurve, C::Profile>,
        nested_f_witness: &nested::stages::f::Witness<C::HostCurve>,
        nested_eval_witness: &nested::stages::eval::Witness<C::HostCurve, C::Profile>,
        nested_challenges_witness: &nested::stages::challenges::Witness<C::ScalarField>,
        source: Option<&Decompressed<C::Base>>,
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
                builder.native_points_children_commitment(),
                builder.native_points_registry_wx_commitment(),
                builder.native_points_ab_commitment(),
                builder.native_points_f_commitment(),
            ],
            coverage: Default::default(),
        };
        let witness = |instance| nested::circuits::common::Witness {
            instance,
            endoscalar: nested_endoscalar,
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

        let (collapse_trace, instance) = MultiStage::new(nested::circuits::collapse::Circuit::<
            C::HostCurve,
            R,
            C::Profile,
        >::new())
        .trace(witness(instance))?
        .into_parts();
        let collapse_rx = self.nested_registry.assemble(
            &collapse_trace,
            nested::InternalCircuitIndex::Collapse.circuit_index::<C::Profile>(),
            &mut *rng,
        )?;

        let (compute_v_trace, instance) = MultiStage::new(nested::circuits::compute_v::Circuit::<
            C::HostCurve,
            R,
            C::Profile,
        >::new())
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
            source,
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

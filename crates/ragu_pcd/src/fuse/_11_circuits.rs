use alloc::vec::Vec;

use ragu_arithmetic::{Cycle, rand::CryptoRng};
use ragu_circuits::{CircuitExt, polynomials::Rank, staging::MultiStage};
use ragu_core::Result;
use ragu_primitives::extract_endoscalar;

use super::NestedChallengeWitnesses;
use crate::{
    Application,
    internal::{
        endoscalar::PointsWitness,
        native,
        native::total_circuit_counts,
        nested::{self, NUM_ENDOSCALING_POINTS},
    },
    proof::ProofBuilder,
};

/// The witnesses of every nested stage a fuse step committed, for tracing
/// the nested circuits that load them.
pub(super) struct NestedWitnesses<'a, C: Cycle> {
    pub(super) endoscalar: u128,
    pub(super) points: &'a PointsWitness<C::HostCurve, NUM_ENDOSCALING_POINTS>,
    pub(super) preamble: nested::stages::preamble::Witness<C::HostCurve>,
    pub(super) s_prime: nested::stages::s_prime::Witness<C::HostCurve>,
    pub(super) inner_error: nested::stages::inner_error::Witness<C::HostCurve>,
    pub(super) outer_error: nested::stages::outer_error::Witness<C::HostCurve>,
    pub(super) ab: nested::stages::ab::Witness<C::HostCurve>,
    pub(super) query: nested::stages::query::Witness<C::HostCurve>,
    pub(super) f: nested::stages::f::Witness<C::HostCurve>,
    pub(super) eval: nested::stages::eval::Witness<C::HostCurve>,
    pub(super) challenges: NestedChallengeWitnesses<C::ScalarField>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    #[allow(clippy::too_many_arguments)]
    pub(super) fn compute_internal_circuits<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        preamble_witness: &native::stages::preamble::Witness<'_, C, R, HEADER_SIZE>,
        native_outer_error_witness: &native::stages::outer_error::Witness<
            C,
            native::RevdotParameters,
        >,
        native_inner_error_witness: &native::stages::inner_error::Witness<
            C,
            native::RevdotParameters,
        >,
        query_witness: &native::stages::query::Witness<C>,
        eval_witness: &native::stages::eval::Witness<C>,
        native_points: &super::NativeInputs<C>,
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
            nu: builder.nu(),
            bridge_outer_error_commitment: builder.bridge_outer_error_commitment(),
            mu_prime: builder.mu_prime(),
            nu_prime: builder.nu_prime(),
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
            coverage: Default::default(),
        };

        let (hashes_1_trace, unified) = native::circuits::hashes_1::Circuit::<
            C,
            R,
            HEADER_SIZE,
            native::RevdotParameters,
        >::new(
            self.params,
            total_circuit_counts(self.num_application_steps).1,
        )
        .trace(native::circuits::hashes_1::Witness {
            unified,
            preamble_witness,
            outer_error_witness: native_outer_error_witness,
        })?
        .into_parts();
        let hashes_1_rx = self.native_registry.assemble(
            &hashes_1_trace,
            native::InternalCircuitIndex::Hashes1Circuit.circuit_index(),
            &mut *rng,
        )?;

        let (hashes_2_trace, unified) = native::circuits::hashes_2::Circuit::<
            C,
            R,
            HEADER_SIZE,
            native::RevdotParameters,
        >::new(self.params)
        .trace(native::circuits::hashes_2::Witness {
            unified,
            outer_error_witness: native_outer_error_witness,
        })?
        .into_parts();
        let hashes_2_rx = self.native_registry.assemble(
            &hashes_2_trace,
            native::InternalCircuitIndex::Hashes2Circuit.circuit_index(),
            &mut *rng,
        )?;

        let (inner_collapse_trace, unified) = native::circuits::inner_collapse::Circuit::<
            C,
            R,
            HEADER_SIZE,
            native::RevdotParameters,
        >::new()
        .trace(native::circuits::inner_collapse::Witness {
            preamble_witness,
            unified,
            outer_error_witness: native_outer_error_witness,
            inner_error_witness: native_inner_error_witness,
        })?
        .into_parts();
        let inner_collapse_rx = self.native_registry.assemble(
            &inner_collapse_trace,
            native::InternalCircuitIndex::InnerCollapseCircuit.circuit_index(),
            &mut *rng,
        )?;

        let (outer_collapse_trace, unified) = native::circuits::outer_collapse::Circuit::<
            C,
            R,
            HEADER_SIZE,
            native::RevdotParameters,
        >::new()
        .trace(native::circuits::outer_collapse::Witness {
            unified,
            preamble_witness,
            outer_error_witness: native_outer_error_witness,
        })?
        .into_parts();
        let outer_collapse_rx = self.native_registry.assemble(
            &outer_collapse_trace,
            native::InternalCircuitIndex::OuterCollapseCircuit.circuit_index(),
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
            native::InternalCircuitIndex::ComputeVCircuit.circuit_index(),
            &mut *rng,
        )?;

        // The nested challenge binding circuits.
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
            bind_challenges_rxs.push(self.native_registry.assemble(
                &trace,
                native::InternalCircuitIndex::BindChallengesCircuit(k as u32).circuit_index(),
                &mut *rng,
            )?);
        }

        builder.set_native_hashes_1_rx(hashes_1_rx);
        builder.set_native_hashes_2_rx(hashes_2_rx);
        builder.set_native_inner_collapse_rx(inner_collapse_rx);
        builder.set_native_outer_collapse_rx(outer_collapse_rx);
        // The children's nested beta binding circuit.
        let (bind_beta_trace, unified) = native::circuits::bind_beta::Circuit::<
            C,
            R,
            HEADER_SIZE,
            native::RevdotParameters,
        >::new(self.params)
        .trace(native::circuits::bind_beta::Witness {
            unified,
            preamble_witness,
            outer_error_witness: native_outer_error_witness,
        })?
        .into_parts();
        let bind_beta_rx = self.native_registry.assemble(
            &bind_beta_trace,
            native::InternalCircuitIndex::BindBetaCircuit.circuit_index(),
            &mut *rng,
        )?;

        // The native walk's inputs: the bits the endoscaling steps walked
        // with are pre_beta's, and the points lie on the curve.
        let (bind_endoscalar_trace, unified) =
            native::circuits::bind_endoscalar::Circuit::<C, R>::new()
                .trace(native::circuits::bind_endoscalar::Witness {
                    unified,
                    endoscalar: extract_endoscalar(builder.pre_beta())?,
                    inputs: native_points,
                })?
                .into_parts();
        let bind_endoscalar_rx = self.native_registry.assemble(
            &bind_endoscalar_trace,
            native::InternalCircuitIndex::BindEndoscalarCircuit.circuit_index(),
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

        Ok(())
    }

    /// This step's nested unified instance, read off the finished builder,
    /// with fresh coverage.
    pub(super) fn nested_instance(
        builder: &ProofBuilder<'_, C, R, B>,
    ) -> Result<nested::unified::Instance<C::HostCurve>> {
        Ok(nested::unified::Instance {
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
                builder.native_points_inputs_commitment(),
            ],
            coverage: Default::default(),
        })
    }

    /// Traces the nested circuits that verify this step on the nested side:
    /// the export circuit, which pins the nested unified instance to the
    /// stages, the collapse circuit, which verifies the nested fold, and the
    /// compute-v circuit, which recomputes the nested batch evaluation. The
    /// instance threads through them accumulating coverage, which must be
    /// complete once all three are traced.
    pub(super) fn compute_nested_circuits<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        witnesses: &NestedWitnesses<'_, C>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        let instance = Self::nested_instance(builder)?;
        let witness = |instance| nested::circuits::common::Witness {
            instance,
            endoscalar: witnesses.endoscalar,
            points: witnesses.points,
            preamble: &witnesses.preamble,
            s_prime: &witnesses.s_prime,
            inner_error: &witnesses.inner_error,
            outer_error: &witnesses.outer_error,
            ab: &witnesses.ab,
            query: &witnesses.query,
            f: &witnesses.f,
            eval: &witnesses.eval,
            challenges: &witnesses.challenges.challenges,
            beta: witnesses.challenges.beta,
        };

        let (export_trace, instance) =
            MultiStage::new(nested::circuits::export::Circuit::<C::HostCurve, R>::new())
                .trace(witness(instance))?
                .into_parts();
        let export_rx = self.nested_registry.assemble(
            &export_trace,
            nested::InternalCircuitIndex::Export.circuit_index(),
            &mut *rng,
        )?;

        let (collapse_trace, instance) =
            MultiStage::new(nested::circuits::collapse::Circuit::<C::HostCurve, R>::new())
                .trace(witness(instance))?
                .into_parts();
        let collapse_rx = self.nested_registry.assemble(
            &collapse_trace,
            nested::InternalCircuitIndex::Collapse.circuit_index(),
            &mut *rng,
        )?;

        let (compute_v_trace, instance) =
            MultiStage::new(nested::circuits::compute_v::Circuit::<C::HostCurve, R>::new())
                .trace(witness(instance))?
                .into_parts();
        let compute_v_rx = self.nested_registry.assemble(
            &compute_v_trace,
            nested::InternalCircuitIndex::ComputeV.circuit_index(),
            &mut *rng,
        )?;

        // As for the native instance: every slot covered exactly once.
        instance.assert_complete();

        builder.set_nested_export_rx(export_rx);
        builder.set_nested_collapse_rx(collapse_rx);
        builder.set_nested_compute_v_rx(compute_v_rx);

        Ok(())
    }
}

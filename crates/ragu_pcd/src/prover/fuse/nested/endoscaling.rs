//! Prover nested endoscaling construction.
use alloc::vec::Vec;

use ragu_circuits::{
    CircuitExt,
    polynomials::Rank,
    staging::{MultiStage, StageExt},
};
use ragu_core::Result;
use ragu_primitives::{Uendo, vec::Len};

use crate::{
    profile::ProfiledCycle,
    protocol::{
        nested,
        nested::{
            EndoscalingStep, EndoscalingStepWitness, NumPoints, NumSteps, PointsStage,
            PointsWitness,
        },
    },
    prover::proof_builder::ProofBuilder,
    verifier::recursive::gadgets::endoscalar::EndoscalarStage,
};

impl<'params, C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    crate::Application<'params, C, R, HEADER_SIZE, B>
{
    /// Runs endoscaling over the host-curve commitments that feed
    /// `PointsStage`, in the order `compute_p` (`_10_p.rs`)
    /// accumulates them. Writes `nested_endoscalar_rx`,
    /// `nested_points_rx`, and `nested_endoscaling_step_rxs` onto
    /// `builder`, and returns the accumulated `p` commitment (last
    /// `PointsStage` interstitial) together with the points witness the
    /// nested circuits load.
    ///
    /// Shared by `compute_p` (in `fuse/_10_p.rs`) and by
    /// [`dummy_proof`](Self::dummy_proof), so the nested
    /// endoscaling setup lives in one place.
    pub(crate) fn compute_endoscaling<RNG: rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        beta_endo: Uendo,
        points: &[C::HostCurve],
        endoscalar_alpha: C::ScalarField,
        points_alpha: C::ScalarField,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<(C::HostCurve, PointsWitness<C::HostCurve, C::Profile>)> {
        assert_eq!(points.len(), NumPoints::<C::Profile>::len());

        let witness = PointsWitness::<C::HostCurve, C::Profile>::new(beta_endo, points);

        let endoscalar_rx =
            <EndoscalarStage as StageExt<C::ScalarField, R>>::rx(endoscalar_alpha, beta_endo)?;
        let points_rx = <PointsStage<C::HostCurve, C::Profile> as StageExt<C::ScalarField, R>>::rx(
            points_alpha,
            &witness,
        )?;

        let num_steps = NumSteps::<C::Profile>::len();
        let mut step_rxs = Vec::with_capacity(num_steps);
        for step in 0..num_steps {
            let step_circuit = EndoscalingStep::<C::HostCurve, R, C::Profile>::new(step);
            let staged = MultiStage::new(step_circuit);
            let step_trace = staged
                .trace(EndoscalingStepWitness {
                    endoscalar: beta_endo,
                    points: &witness,
                })?
                .into_output();
            let step_rx = self.nested_registry.assemble(
                &step_trace,
                nested::InternalCircuitIndex::EndoscalingStep(step as u32)
                    .circuit_index::<C::Profile>(),
                rng,
            )?;
            step_rxs.push(step_rx);
        }

        builder.set_nested_endoscaling_step_rxs(step_rxs);
        builder.set_nested_endoscalar_rx(endoscalar_rx);
        builder.set_nested_points_rx(points_rx);

        let p_commitment = *witness
            .interstitials
            .last()
            .expect("every walk has at least one interstitial");
        Ok((p_commitment, witness))
    }
}

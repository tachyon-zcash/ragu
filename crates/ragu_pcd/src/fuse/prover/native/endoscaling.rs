//! Prover native endoscaling construction.
use alloc::vec::Vec;

use ragu_circuits::{CircuitExt, polynomials::Rank, staging::StageExt};
use ragu_core::Result;
use ragu_primitives::{Uendo, vec::Len};
use udon::field::Field;

use crate::{
    fuse::prover::proof_builder::ProofBuilder,
    profile::ProfiledCycle,
    protocol::{
        native,
        native::stages::{points as native_points, points::Inputs},
    },
};

impl<'params, C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    crate::Application<'params, C, R, HEADER_SIZE, B>
{
    /// Runs the native endoscaling over the committed inputs: walks them
    /// under `beta_endo`, commits the walk stage, traces the steps, and
    /// writes all of it onto `builder`. Returns $P_n$ (the last
    /// interstitial) with the walk stage's witness.
    ///
    /// Shared by `compute_p` (in `fuse/prover/bridge/p.rs`) and
    /// [`dummy_proof`](Self::dummy_proof), like
    /// [`compute_endoscaling`](Self::compute_endoscaling) on the nested side.
    pub(crate) fn compute_native_endoscaling<RNG: rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        beta_endo: Uendo,
        inputs: &Inputs<C::NestedCurve, C::Profile>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<(
        C::NestedCurve,
        native_points::WalkWitness<C::NestedCurve, C::Profile>,
    )> {
        use native_points::{WalkStage, WalkWitness};

        let walk = WalkWitness::new(
            beta_endo,
            crate::protocol::gadgets::endoscalar::PointsWitness::<
                C::NestedCurve,
                native::NumPoints<C::Profile>,
                native::Endoscalings<C::Profile>,
            >::new(beta_endo, &inputs.walk()),
        );

        let walk_rx = <WalkStage<C::NestedCurve, C::Profile> as StageExt<C::CircuitField, R>>::rx(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            &walk,
        )?;

        let mut step_rxs = Vec::with_capacity(native::NumSteps::<C::Profile>::len());
        for step in 0..native::NumSteps::<C::Profile>::len() {
            let trace = crate::fuse::circuits::native::endoscaling_step::Circuit::<C, R>::new(step)
                .trace(crate::fuse::circuits::native::endoscaling_step::Witness {
                    inputs,
                    walk: &walk,
                })?
                .into_output();
            step_rxs.push(
                self.native_registry.assemble(
                    &trace,
                    native::InternalCircuitIndex::EndoscalingStep(step as u32)
                        .circuit_index::<C::Profile>(),
                    &mut *rng,
                )?,
            );
        }

        builder.set_native_points_walk_rx(walk_rx);
        builder.set_native_endoscaling_step_rxs(step_rxs);

        let p_commitment = walk.p();
        Ok((p_commitment, walk))
    }
}

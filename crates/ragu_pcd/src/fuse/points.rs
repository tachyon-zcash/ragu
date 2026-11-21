//! The native points stages and the endoscaling walk over the host-curve
//! commitments the nested batch folds, shared by `compute_p` (`_10_p.rs`) and
//! the dummy proof.

use alloc::vec::Vec;

use ragu_circuits::{
    CircuitExt,
    polynomials::Rank,
    staging::{MultiStage, StageExt},
};
use ragu_core::Result;
use ragu_primitives::{
    Uendo,
    vec::{FixedVec, Len},
};
use udon::field::Field;

use crate::{
    Proof,
    profile::{Profile, ProfiledCycle},
    proof::ProofBuilder,
    recursion::{
        endoscalar::EndoscalarStage,
        native::{
            self,
            stages::points::{self as native_points, Inputs},
        },
        nested::{
            self, EndoscalingStep, EndoscalingStepWitness, NumPoints, NumSteps, PointsStage,
            PointsWitness,
        },
    },
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

    /// Commits the native points binding and preamble stages over the
    /// children's nested commitments and the step's own online Fq
    /// commitments, before $w$ is squeezed; the preamble bridge carries
    /// their commitments.
    pub(crate) fn commit_native_points_preamble<RNG: rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        source: Option<&crate::profile::Source<'params, C, R, B>>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        // The profile's prover supplies its online Fq polynomials: a
        // placeholder in every slot by default.
        let polynomials =
            C::Profile::online_fq_polynomials::<C::Base, R, B>(&self.context, source)?;
        if polynomials.len() != C::Profile::ONLINE_FQ_POLYS {
            return Err(ragu_core::Error::Initialization(
                "the profile's prover did not supply its online Fq polynomials".into(),
            ));
        }
        builder.set_online_fq_polynomials(polynomials);

        // The step's own online Fq commitments, which the preamble stage
        // holds.
        let mut online_fq = builder.online_fq_commitments().to_vec();
        online_fq.extend_from_slice(&builder.nested_online_phase::<0>());
        let online_fq = &online_fq;

        // Test hook: this runs on the thread that calls `fuse`, outside its
        // parallel jobs, as the hook's thread-local requires.
        #[cfg(test)]
        let online_fq = &crate::online_fq_oracles_tests::mutate_stage_commitments(online_fq);

        let (binding, preamble) = native_points::preamble_witnesses::<_, C::Profile>(
            &nested::pcs::child_commitments(left).collect::<Vec<_>>(),
            &nested::pcs::child_commitments(right).collect::<Vec<_>>(),
            [&left.online_fq_commitments, &right.online_fq_commitments],
            online_fq,
            FixedVec::from_fn(|_| builder.nested_online_stage_commitment(0)),
        );
        builder.set_native_points_binding_rx(<native_points::BindingStage<
            C::NestedCurve,
            C::Profile,
        > as StageExt<C::CircuitField, R>>::rx(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            &binding,
        )?);
        builder.set_native_points_preamble_rx(<native_points::PreambleStage<
            C::NestedCurve,
            C::Profile,
        > as StageExt<C::CircuitField, R>>::rx(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            &preamble,
        )?);
        Ok(())
    }

    /// Commits the native points stage holding the nested `registry_wx`
    /// commitments, before $y$ is squeezed; the `s_prime` bridge carries its
    /// commitment.
    pub(crate) fn commit_native_points_registry_wx<RNG: rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        registry_wx0: C::NestedCurve,
        registry_wx1: C::NestedCurve,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        let witness = native_points::RegistryWxWitness {
            online_points: builder.nested_online_phase::<1>(),
            registry_wx0,
            registry_wx1,
        };
        builder.set_native_points_registry_wx_rx(<native_points::RegistryWxStage<
            C::NestedCurve,
            C::Profile,
        > as StageExt<C::CircuitField, R>>::rx(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            &witness,
        )?);
        Ok(())
    }

    /// Commits the native points stage holding the nested `registry_wy`
    /// commitment, $A_n$ and $B_n$, before $x$ is squeezed; the `ab` bridge
    /// carries its commitment.
    pub(crate) fn commit_native_points_ab<RNG: rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        registry_wy: C::NestedCurve,
        a: C::NestedCurve,
        b: C::NestedCurve,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        let witness = native_points::AbWitness {
            registry_wy,
            a,
            b,
            online_points: builder.nested_online_phase::<2>(),
        };
        builder.set_native_points_ab_rx(<native_points::AbStage<C::NestedCurve, C::Profile> as StageExt<
            C::CircuitField,
            R,
        >>::rx(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            &witness,
        )?);
        Ok(())
    }

    /// Commits the native points stage holding the nested `registry_xy`
    /// commitment and $F_n$, before $u$ is squeezed; the `f` bridge carries
    /// its commitment.
    pub(crate) fn commit_native_points_f<RNG: rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        registry_xy: C::NestedCurve,
        f: C::NestedCurve,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        let witness = native_points::FWitness {
            registry_xy,
            f,
            online_points: builder.nested_online_phase::<3>(),
        };
        builder.set_native_points_f_rx(<native_points::FStage<C::NestedCurve, C::Profile> as StageExt<
            C::CircuitField,
            R,
        >>::rx(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            &witness,
        )?);
        Ok(())
    }

    /// Commits every native points input stage at once, for a proof whose
    /// walk needs no transcript schedule: the dummy proof.
    pub(super) fn commit_native_points_stages<RNG: rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        inputs: &Inputs<C::NestedCurve, C::Profile>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        builder.set_native_points_binding_rx(<native_points::BindingStage<
            C::NestedCurve,
            C::Profile,
        > as StageExt<C::CircuitField, R>>::rx(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            &inputs.binding,
        )?);
        builder.set_native_points_preamble_rx(<native_points::PreambleStage<
            C::NestedCurve,
            C::Profile,
        > as StageExt<C::CircuitField, R>>::rx(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            &inputs.preamble,
        )?);
        self.commit_native_points_registry_wx(
            rng,
            inputs.registry_wx.registry_wx0,
            inputs.registry_wx.registry_wx1,
            builder,
        )?;
        self.commit_native_points_ab(
            rng,
            inputs.ab.registry_wy,
            inputs.ab.a,
            inputs.ab.b,
            builder,
        )?;
        self.commit_native_points_f(rng, inputs.f.registry_xy, inputs.f.f, builder)
    }

    /// Runs the native endoscaling over the committed inputs: walks them
    /// under `beta_endo`, commits the walk stage, traces the steps, and
    /// writes all of it onto `builder`. Returns $P_n$ (the last
    /// interstitial) with the walk stage's witness.
    ///
    /// Shared by `compute_p` (in `fuse/_10_p.rs`) and
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
            crate::recursion::endoscalar::PointsWitness::<
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
            let trace = native::circuits::endoscaling_step::Circuit::<C, R>::new(step)
                .trace(native::circuits::endoscaling_step::Witness {
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

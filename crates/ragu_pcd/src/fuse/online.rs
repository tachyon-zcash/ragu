//! Calls profile preparation hooks at the private batch's commitment deadlines.
//!
//! Every call is made for every profile: the hooks' defaults supply nothing
//! for a side without a batch, and the batch's state takes it from there.

use ragu_circuits::polynomials::Rank;
use ragu_core::Result;
use rand::CryptoRng;

use crate::{
    Application, Proof,
    internal::nested,
    profile::{
        Profile, ProfiledCycle,
        online::{Phase, prepared::PreparationChallenges, prover::State},
    },
    proof::ProofBuilder,
};

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// Begins both sides' private batches from the profile's inputs, supplies
    /// their polynomials fixed before $w$ and commits the two input stages.
    pub(super) fn prepare_private_inputs<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        children: [&Proof<C, R>; 2],
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        let native = State::begin(
            C::Profile::native_online_inputs::<C::Base, R, B>(&self.context)?,
            || Ok(children.map(|child| [child.x(), child.y()])),
            self.native_source.as_ref(),
        )?;
        let nested = State::begin(
            C::Profile::nested_online_inputs::<C::Base, R, B>(&self.context)?,
            || {
                let [left, right] = children;
                Ok([
                    [
                        nested::challenge::<C>(left.x())?,
                        nested::challenge::<C>(left.y())?,
                    ],
                    [
                        nested::challenge::<C>(right.x())?,
                        nested::challenge::<C>(right.y())?,
                    ],
                ])
            },
            self.nested_source.as_ref(),
        )?;
        builder.set_native_private(native);
        builder.set_nested_private(nested);
        self.prepare_private_phase_inner(
            Phase::BeforeW,
            PreparationChallenges::default(),
            builder,
            Some(children),
        )?;
        // Both fields' private polynomials exist before either input stage is
        // committed, so consumers get the actual opposite-field commitments.
        let native_foreign = builder.nested_private().coordinates();
        let nested_foreign = builder.native_private().coordinates();
        builder.native_private_mut().commit_inputs::<B, _, _>(
            native_foreign,
            C::host_generators(self.params),
            rng,
        )?;
        builder.nested_private_mut().commit_inputs::<B, _, _>(
            nested_foreign,
            C::nested_generators(self.params),
            rng,
        )?;
        Ok(())
    }

    /// Supplies both sides' polynomials fixed at `phase`, a deadline after
    /// $w$, under the challenges drawn before it.
    pub(super) fn prepare_private_phase(
        &self,
        phase: Phase,
        challenges: PreparationChallenges<C::CircuitField>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        self.prepare_private_phase_inner(phase, challenges, builder, None)
    }

    fn prepare_private_phase_inner(
        &self,
        phase: Phase,
        challenges: PreparationChallenges<C::CircuitField>,
        builder: &mut ProofBuilder<'_, C, R, B>,
        children: Option<[&Proof<C, R>; 2]>,
    ) -> Result<()> {
        let supplied = C::Profile::native_online_polynomials::<C::Base, R, B>(
            &self.context,
            phase,
            builder.native_private().early_values(),
            challenges,
        )?;
        builder.native_private_mut().prepare::<B, _>(
            phase,
            supplied,
            challenges,
            self.native_source.as_ref(),
            children.map(|children| children.map(|child| &child.native_source_out[..])),
            C::host_generators(self.params),
        )?;

        let challenges = nested_challenges::<C>(challenges)?;
        let supplied = C::Profile::nested_online_polynomials::<C::Base, R, B>(
            &self.context,
            phase,
            builder.nested_private().early_values(),
            challenges,
        )?;
        builder.nested_private_mut().prepare::<B, _>(
            phase,
            supplied,
            challenges,
            self.nested_source.as_ref(),
            children.map(|children| children.map(|child| &child.nested_source_out[..])),
            C::nested_generators(self.params),
        )?;
        Ok(())
    }

    /// Takes the profile's witness query points and commits both sides' query
    /// stages, after $x$ and before $\alpha$.
    pub(super) fn prepare_private_queries<RNG: CryptoRng>(
        &self,
        challenges: PreparationChallenges<C::CircuitField>,
        rng: &mut RNG,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        let points = C::Profile::native_online_points::<C::Base, R, B>(
            &self.context,
            builder.native_private().early_values(),
            challenges,
        )?;
        builder.native_private_mut().commit_query::<B, _, _>(
            points,
            challenges,
            C::host_generators(self.params),
            rng,
        )?;

        let challenges = nested_challenges::<C>(challenges)?;
        let points = C::Profile::nested_online_points::<C::Base, R, B>(
            &self.context,
            builder.nested_private().early_values(),
            challenges,
        )?;
        builder.nested_private_mut().commit_query::<B, _, _>(
            points,
            challenges,
            C::nested_generators(self.params),
            rng,
        )?;
        Ok(())
    }

    /// Commits both sides' evaluation stages at `u`, before `pre_beta`.
    pub(super) fn prepare_private_evaluations<RNG: CryptoRng>(
        &self,
        u: C::CircuitField,
        rng: &mut RNG,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        builder.native_private_mut().commit_eval::<B, _, _>(
            u,
            C::host_generators(self.params),
            rng,
        )?;
        builder.nested_private_mut().commit_eval::<B, _, _>(
            nested::challenge::<C>(u)?,
            C::nested_generators(self.params),
            rng,
        )?;
        Ok(())
    }
}

fn nested_challenges<C: ProfiledCycle>(
    challenges: PreparationChallenges<C::CircuitField>,
) -> Result<PreparationChallenges<C::ScalarField>> {
    Ok(PreparationChallenges {
        w: challenges.w.map(nested::challenge::<C>).transpose()?,
        y: challenges.y.map(nested::challenge::<C>).transpose()?,
        x: challenges.x.map(nested::challenge::<C>).transpose()?,
    })
}

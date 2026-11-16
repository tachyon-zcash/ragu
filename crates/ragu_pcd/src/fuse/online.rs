//! Calls profile preparation hooks at the private batch's commitment deadlines.

use alloc::vec::Vec;

use ragu_circuits::polynomials::Rank;
use ragu_core::Result;
use rand::CryptoRng;
use udon::{curve::Affine, field::Field};

use crate::{
    Application,
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
    pub(crate) fn prepare_private_inputs<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        if !C::Profile::NATIVE_ONLINE.is_empty() {
            builder.native_private = Some(
                State::new(C::Profile::native_online_inputs::<C::Base, R, B>(
                    &self.context,
                )?)?
                .with_source_tag(self.native_source.as_ref().map(|source| source.tag()))?,
            );
        }
        if !C::Profile::NESTED_ONLINE.is_empty() {
            builder.nested_private = Some(
                State::new(C::Profile::nested_online_inputs::<C::Base, R, B>(
                    &self.context,
                )?)?
                .with_source_tag(self.nested_source.as_ref().map(|source| source.tag()))?,
            );
        }
        self.prepare_private_phase(Phase::BeforeW, PreparationChallenges::default(), builder)?;
        // Both fields' private polynomials exist before either input stage is
        // committed, so consumers get the actual opposite-field commitments.
        let native_foreign = coordinates(
            builder
                .nested_private
                .as_ref()
                .map(|state| state.commitments())
                .unwrap_or(&[]),
        );
        let nested_foreign = coordinates(
            builder
                .native_private
                .as_ref()
                .map(|state| state.commitments())
                .unwrap_or(&[]),
        );
        if let Some(state) = &mut builder.native_private {
            state.commit_inputs::<B, _, _>(native_foreign, C::host_generators(self.params), rng)?;
        }
        if let Some(state) = &mut builder.nested_private {
            state.commit_inputs::<B, _, _>(
                nested_foreign,
                C::nested_generators(self.params),
                rng,
            )?;
        }
        Ok(())
    }

    pub(crate) fn prepare_private_phase(
        &self,
        phase: Phase,
        challenges: PreparationChallenges<C::CircuitField>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        if let Some(state) = &mut builder.native_private {
            let polynomials = C::Profile::native_online_polynomials::<C::Base, R, B>(
                &self.context,
                phase,
                state.early_values(),
                challenges,
            )?;
            state.supply::<B, _>(phase, polynomials, C::host_generators(self.params))?;
        }
        if let Some(state) = &mut builder.nested_private {
            let polynomials = C::Profile::nested_online_polynomials::<C::Base, R, B>(
                &self.context,
                phase,
                state.early_values(),
                nested_challenges::<C>(challenges)?,
            )?;
            state.supply::<B, _>(phase, polynomials, C::nested_generators(self.params))?;
        }
        Ok(())
    }

    pub(crate) fn prepare_private_queries<RNG: CryptoRng>(
        &self,
        challenges: PreparationChallenges<C::CircuitField>,
        rng: &mut RNG,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        if let Some(state) = &mut builder.native_private {
            let points = C::Profile::native_online_points::<C::Base, R, B>(
                &self.context,
                state.early_values(),
                challenges,
            )?;
            state.commit_query::<B, _, _>(
                points,
                challenges,
                C::host_generators(self.params),
                rng,
            )?;
        }
        if let Some(state) = &mut builder.nested_private {
            let challenges = nested_challenges::<C>(challenges)?;
            let points = C::Profile::nested_online_points::<C::Base, R, B>(
                &self.context,
                state.early_values(),
                challenges,
            )?;
            state.commit_query::<B, _, _>(
                points,
                challenges,
                C::nested_generators(self.params),
                rng,
            )?;
        }
        Ok(())
    }

    pub(crate) fn prepare_private_evaluations<RNG: CryptoRng>(
        &self,
        u: C::CircuitField,
        rng: &mut RNG,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        if let Some(state) = &mut builder.native_private {
            state.commit_eval::<B, _, _>(u, C::host_generators(self.params), rng)?;
        }
        if let Some(state) = &mut builder.nested_private {
            state.commit_eval::<B, _, _>(
                nested::challenge::<C>(u)?,
                C::nested_generators(self.params),
                rng,
            )?;
        }
        Ok(())
    }
}

fn coordinates<C: Affine>(points: &[C]) -> Vec<C::Base> {
    points
        .iter()
        .flat_map(|point| {
            let (x, y) = point
                .coordinates()
                .unwrap_or((C::Base::ZERO, C::Base::ZERO));
            [x, y]
        })
        .collect()
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

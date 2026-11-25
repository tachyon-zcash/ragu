//! The profile's online batch over the scalar field,
//! [`Profile::NESTED_ONLINE`]: online polynomials of the step's own,
//! prepared as the native side's are (see
//! [`online`](crate::internal::native::online)) at the nested lifts of the
//! fuse's challenges.
//!
//! The step commits each polynomial natively, in the native points stage
//! of its deadline, and the native walk folds each commitment into $P_n$
//! after the nested batch's other commitments.

use ragu_circuits::polynomials::Rank;
use ragu_core::Result;
use rand::CryptoRng;

use super::challenge;
use crate::{
    Application, Proof, SelectableBackend,
    profile::{
        Profile, ProfiledCycle, Source,
        online::{Phase, PreparationChallenges, prover::State},
    },
    proof::ProofBuilder,
};

impl<'params, C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: SelectableBackend>
    Application<'params, C, R, HEADER_SIZE, B>
{
    /// Begins the step's nested online batch from the profile's inputs,
    /// with the lifts of the children's $x$ and $y$ in the slots a mesh
    /// inherits them at, and supplies its polynomials fixed before $w$.
    pub(crate) fn begin_nested_online(
        &self,
        children: [&Proof<C, R>; 2],
        source: Option<&Source<'params, C, R, B>>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        builder.set_nested_online(State::begin(
            C::Profile::nested_online_inputs::<C::Base, R, B>(&self.context, source)?,
            || {
                let [left, right] = children;
                Ok([
                    [challenge::<C>(left.x())?, challenge::<C>(left.y())?],
                    [challenge::<C>(right.x())?, challenge::<C>(right.y())?],
                ])
            },
            self.nested_source().as_ref(),
        )?);
        self.supply_nested_online(
            Phase::BeforeW,
            PreparationChallenges::default(),
            Some(children),
            source,
            builder,
        )
    }

    /// Supplies the nested polynomials fixed at `phase`, a deadline after
    /// $w$, under the lifts of the challenges drawn before it.
    pub(crate) fn prepare_nested_online(
        &self,
        phase: Phase,
        challenges: PreparationChallenges<C::CircuitField>,
        source: Option<&Source<'params, C, R, B>>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        self.supply_nested_online(phase, challenges, None, source, builder)
    }

    /// Supplies the polynomials the profile and the mesh fix at `phase`,
    /// before $w$ with the polynomials `children` hand up.
    fn supply_nested_online(
        &self,
        phase: Phase,
        challenges: PreparationChallenges<C::CircuitField>,
        children: Option<[&Proof<C, R>; 2]>,
        source: Option<&Source<'params, C, R, B>>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        let challenges = lifts::<C>(challenges)?;
        let supplied = C::Profile::nested_online_polynomials::<C::Base, R, B>(
            &self.context,
            source,
            phase,
            builder.nested_online().early_values(),
            challenges,
        )?;
        builder.nested_online_mut().prepare::<B, _>(
            phase,
            supplied,
            challenges,
            self.nested_source().as_ref(),
            children.map(|children| children.map(|child| &child.nested_source_out[..])),
            C::nested_generators(self.params),
        )
    }

    /// Commits the nested input stage, which holds the native batch's
    /// commitments fixed before $w$.
    pub(crate) fn commit_nested_online_inputs<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        let foreign = builder.native_online().coordinates()?;
        builder.nested_online_mut().commit_inputs::<B, _, _>(
            foreign,
            C::nested_generators(self.params),
            rng,
        )
    }

    /// Takes the profile's witness query points and commits the nested query
    /// stage, after $x$ and before $\alpha$.
    pub(crate) fn commit_nested_online_query<RNG: CryptoRng>(
        &self,
        challenges: PreparationChallenges<C::CircuitField>,
        rng: &mut RNG,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        let challenges = lifts::<C>(challenges)?;
        let points = C::Profile::nested_online_points::<C::Base, R, B>(
            &self.context,
            builder.nested_online().early_values(),
            challenges,
        )?;
        builder.nested_online_mut().commit_query::<B, _, _>(
            points,
            challenges,
            C::nested_generators(self.params),
            rng,
        )
    }

    /// Commits the nested evaluation stage at the lift of `u`, before
    /// `pre_beta`.
    pub(crate) fn commit_nested_online_eval<RNG: CryptoRng>(
        &self,
        u: C::CircuitField,
        rng: &mut RNG,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        builder.nested_online_mut().commit_eval::<B, _, _>(
            challenge::<C>(u)?,
            C::nested_generators(self.params),
            rng,
        )
    }
}

/// The nested lifts of the preparation challenges drawn so far.
fn lifts<C: ProfiledCycle>(
    challenges: PreparationChallenges<C::CircuitField>,
) -> Result<PreparationChallenges<C::ScalarField>> {
    Ok(PreparationChallenges {
        w: challenges.w.map(challenge::<C>).transpose()?,
        y: challenges.y.map(challenge::<C>).transpose()?,
        x: challenges.x.map(challenge::<C>).transpose()?,
    })
}

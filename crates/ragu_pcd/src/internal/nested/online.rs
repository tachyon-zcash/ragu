//! The online polynomials over the scalar field: the step's own, which the
//! nested `compute_v` circuit opens.
//!
//! A profile sets how many each step commits, with
//! [`Profile::ONLINE_FQ_POLYS`]. The step commits each one natively, in the
//! native points stage that holds the children's nested commitments, before
//! $w$ is drawn. The native walk folds each commitment into $P_n$ after the
//! nested batch's other commitments. The nested `query` stage holds the
//! opened value $y_q$, the nested `eval` stage holds the value at $u_n$, and
//! the nested `compute_v` circuit reads them and folds the opening into the
//! step's own nested batch. The step does not export the polynomial, so a
//! parent never opens it.
//!
//! The opening point is $\zeta_q$, the challenge stage's lift of $w$, so no
//! stage holds a point. Every nested circuit that loads the `query` and
//! challenge stages reads the same $y_q$ and $\zeta_q$.
//!
//! The profile's private batch, [`Profile::NESTED_ONLINE`], adds online
//! polynomials of the step's own on this field, prepared as the native
//! side's are (see [`online`](crate::internal::native::online)) at the
//! nested lifts of the fuse's challenges.

use core::marker::PhantomData;

use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::Result;
use ragu_primitives::vec::Len;
use rand::CryptoRng;
use udon::field::Field;

use super::challenge;
use crate::{
    Application, Proof, SelectableBackend,
    profile::{
        Profile, ProfiledCycle,
        online::{Phase, prepared::PreparationChallenges, prover::State},
    },
    proof::ProofBuilder,
};

/// The maximum number of online polynomials over the scalar field that a
/// step commits.
///
/// Such a polynomial belongs to the step that commits it. The step commits
/// it before its challenge is drawn, and the step's nested batch opens it.
/// The step does not export it, so a parent never opens it. Only a profile
/// that asks for the slot has it; see [`Profile::ONLINE_FQ_POLYS`]. A
/// profile that needs more pre-w polynomials over the scalar field declares
/// them in [`Profile::NESTED_ONLINE`] instead.
pub const NUM_ONLINE_FQ_POLYS: usize = 1;

/// Compatibility descriptors for pre-w slots opened at the lifted w.
/// Their stage placement is retained for existing profiles; their opening
/// algebra is shared with the general private batch.
pub(crate) fn openings(count: usize) -> impl Iterator<Item = crate::profile::online::Opening> {
    (0..count).map(|i| crate::profile::online::Opening {
        polynomial: i,
        point: crate::profile::online::Point::Challenge(crate::profile::online::Challenge::W),
        value: i,
    })
}

/// Length type for a step's own online polynomials over the scalar field
/// in profile `P`.
pub struct FqPolysLen<P: Profile>(PhantomData<P>);

impl<P: Profile> Len for FqPolysLen<P> {
    fn len() -> usize {
        P::ONLINE_FQ_POLYS
    }
}

/// The walked commitments: legacy slots followed by distinct private polynomials.
pub struct FqPointsLen<P: Profile>(PhantomData<P>);
impl<P: Profile> Len for FqPointsLen<P> {
    fn len() -> usize {
        P::ONLINE_FQ_POLYS + P::NESTED_ONLINE.polynomials.len()
    }
}

/// Legacy and private points fixed before w; later auxiliaries live in later stages.
pub struct FqEarlyPointsLen<P: Profile>(PhantomData<P>);
impl<P: Profile> Len for FqEarlyPointsLen<P> {
    fn len() -> usize {
        P::ONLINE_FQ_POLYS + <crate::profile::online::stages::PhaseLen<P,crate::profile::online::stages::Nested,0> as Len>::len()
    }
}

/// The point at which a step opens its online Fq polynomials, given the
/// lift of $w$ into the scalar field: $\zeta_q$ itself.
///
/// No stage holds the point: the nested `compute_v` takes it from the
/// challenge stage. The prover's openings and quotients take it from here,
/// so this is the one place the prover chooses it.
///
/// New consumers with other opening points use [`Profile::NESTED_ONLINE`].
pub fn point<F: Field>(w: F) -> F {
    // Test hook: this runs on the thread that calls `fuse`, outside its
    // parallel jobs, as the hook's thread-local requires.
    #[cfg(test)]
    let w = crate::online_fq_oracles_tests::mutate_query_point(w);
    w
}

/// The polynomial that a step commits in each of its online Fq slots.
///
/// It is not zero, so its commitment is not the identity, which the native
/// walk cannot take. It is not constant, so its value at $\zeta_q$ depends
/// on $\zeta_q$.
///
/// This witness is retained for compatibility profiles. New consumers supply
/// their own polynomials through the private-batch preparation hooks.
pub fn placeholder<F: Field, R: Rank>() -> sparse::Polynomial<F, R> {
    sparse::Polynomial::from_coeffs(alloc::vec![F::from(1), F::from(2), F::from(3)])
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// Begins the step's nested private batch from the profile's inputs,
    /// with the lifts of the children's $x$ and $y$ in the slots a mesh
    /// inherits them at, and supplies its polynomials fixed before $w$.
    pub(crate) fn begin_nested_online(
        &self,
        children: [&Proof<C, R>; 2],
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        builder.set_nested_online(State::begin(
            C::Profile::nested_online_inputs::<C::Base, R, B>(&self.context)?,
            || {
                let [left, right] = children;
                Ok([
                    [challenge::<C>(left.x())?, challenge::<C>(left.y())?],
                    [challenge::<C>(right.x())?, challenge::<C>(right.y())?],
                ])
            },
            self.nested_source.as_ref(),
        )?);
        self.supply_nested_online(
            Phase::BeforeW,
            PreparationChallenges::default(),
            Some(children),
            builder,
        )
    }

    /// Supplies the nested polynomials fixed at `phase`, a deadline after
    /// $w$, under the lifts of the challenges drawn before it.
    pub(crate) fn prepare_nested_online(
        &self,
        phase: Phase,
        challenges: PreparationChallenges<C::CircuitField>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        self.supply_nested_online(phase, challenges, None, builder)
    }

    /// Supplies the polynomials the profile and the mesh fix at `phase`,
    /// before $w$ with the polynomials `children` hand up.
    fn supply_nested_online(
        &self,
        phase: Phase,
        challenges: PreparationChallenges<C::CircuitField>,
        children: Option<[&Proof<C, R>; 2]>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        let challenges = lifts::<C>(challenges)?;
        let supplied = C::Profile::nested_online_polynomials::<C::Base, R, B>(
            &self.context,
            phase,
            builder.nested_online().early_values(),
            challenges,
        )?;
        builder.nested_online_mut().prepare::<B, _>(
            phase,
            supplied,
            challenges,
            self.nested_source.as_ref(),
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
        let foreign = builder.native_online().coordinates();
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

#[cfg(test)]
mod tests {
    use ragu_circuits::polynomials::TestRank;
    use ragu_core::pasta::Fq;

    use super::*;

    #[test]
    fn the_placeholder_is_not_constant() {
        let poly = placeholder::<Fq, TestRank>();
        // 1 + 2 * 5 + 3 * 25
        assert_eq!(poly.eval(Fq::from(5)), Fq::from(86));
        assert_ne!(poly.eval(Fq::from(5)), poly.eval(Fq::from(0)));
    }
}

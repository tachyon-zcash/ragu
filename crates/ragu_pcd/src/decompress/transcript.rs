//! The compression's transcript as a gadget: the schedule of
//! [`verify_compressed`](crate::Application::verify_compressed) over an
//! allocated instance and allocated messages, squeezing the challenges
//! the native verifier squeezes.
//!
//! The native transcript is a Poseidon sponge over the circuit field. It
//! absorbs the host curve's scalars directly and the nested curve's points
//! by their coordinates; what lives in the other field, the host curve's
//! points and the nested curve's scalars, it commits by the run before
//! each challenge and absorbs as the commitment, a nested-curve point (see
//! [`CycleTranscript`](crate::ipa::CycleTranscript)). In the circuit over
//! the circuit field the same sponge runs over allocated elements and
//! points, each run's commitment an allocated point: what the commitment
//! covers is bound elsewhere, by the proof's consumer holding the point to
//! the run's stage on the other side (see [`stages`](super::stages)). Each
//! challenge is read as the
//! compression reads it: the squeezed element constrained into the
//! endoscalar range, its endoscalar, which scales points, and the
//! endoscalar's lift into the circuit field, which the field checks over
//! this field use. The nested curve's field checks use the same
//! endoscalar's lift into the scalar field, which the circuit over that
//! field must receive bound to these bits.

use alloc::vec::Vec;

use ragu_core::{PoseidonPermutation, Result, drivers::Driver};
use ragu_primitives::{Element, Endoscalar, EndoscalarChallenge, GadgetExt, Point, io::Buffer};
use udon::curve::EndomorphismAffine as Affine;

use crate::{
    compress::{Sampled, revdot::fold::Weights},
    internal::transcript::Transcript,
    ipa::IPA_TAG,
};

/// What the transcript absorbs: an element by value, a point by its
/// coordinates.
pub(crate) trait Absorb<'dr, D: Driver<'dr>> {
    fn absorb<P: PoseidonPermutation<D::F>>(
        &self,
        dr: &mut D,
        transcript: &mut Transcript<'dr, D, P>,
    ) -> Result<()>;
}

impl<'dr, D: Driver<'dr>> Absorb<'dr, D> for Element<'dr, D> {
    fn absorb<P: PoseidonPermutation<D::F>>(
        &self,
        dr: &mut D,
        transcript: &mut Transcript<'dr, D, P>,
    ) -> Result<()> {
        transcript.write(dr, self)
    }
}

impl<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> Absorb<'dr, D> for Point<'dr, D, C> {
    fn absorb<P: PoseidonPermutation<D::F>>(
        &self,
        dr: &mut D,
        transcript: &mut Transcript<'dr, D, P>,
    ) -> Result<()> {
        GadgetExt::write(self, dr, transcript)
    }
}

/// A child's values as the preamble stage holds them, allocated.
pub(crate) struct Child<'dr, D: Driver<'dr>> {
    pub x: Element<'dr, D>,
    pub y: Element<'dr, D>,
    pub id: Element<'dr, D>,
}

/// The instance as the transcript absorbs it, with the fields of
/// [`Instance`](crate::compress::instance::Instance) that lie in the
/// circuit field, as elements, and on the nested curve, as points. Its
/// scalar-field values, the host commitments and the nested curve's
/// instance values, are the instance's two runs
/// ([`Run::Commitments`](super::stages::Run::Commitments) and
/// [`Run::Scalars`](super::stages::Run::Scalars)).
pub(crate) struct Instance<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> {
    /// $\omega^j$ of the circuit id.
    pub circuit_id: Element<'dr, D>,
    pub left_header: Vec<Element<'dr, D>>,
    pub right_header: Vec<Element<'dr, D>>,

    /// The nested commitments, in
    /// [`nested_components`](crate::compress::revdot::nested_components)
    /// order.
    pub nested: Vec<Point<'dr, D, C>>,
    pub nested_registry_xy: Point<'dr, D, C>,
    pub nested_p: Point<'dr, D, C>,
    pub nested_challenges_partial: Point<'dr, D, C>,

    pub c: Element<'dr, D>,
    pub v: Element<'dr, D>,

    pub left: Child<'dr, D>,
    pub right: Child<'dr, D>,
    pub a_at_u: Element<'dr, D>,
    pub b_at_u: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> Instance<'dr, D, C> {
    /// Absorbs the instance in the native verifier's order: the circuit id
    /// and the headers, the host commitments' run, the host curve's
    /// scalars, the nested commitments, then the run of the scalar
    /// field's instance values.
    fn absorb<P: PoseidonPermutation<D::F>>(
        &self,
        dr: &mut D,
        transcript: &mut Transcript<'dr, D, P>,
        runs: &mut Runs<'_, 'dr, D, C>,
    ) -> Result<()> {
        self.circuit_id.absorb(dr, transcript)?;
        for element in self.left_header.iter().chain(&self.right_header) {
            element.absorb(dr, transcript)?;
        }
        runs.absorb(dr, transcript)?; // the host commitments
        let (l, r) = (&self.left, &self.right);
        for element in [
            &self.c,
            &self.v,
            &l.x,
            &l.y,
            &l.id,
            &r.x,
            &r.y,
            &r.id,
            &self.a_at_u,
            &self.b_at_u,
        ] {
            element.absorb(dr, transcript)?;
        }
        for point in self.nested.iter().chain([
            &self.nested_registry_xy,
            &self.nested_p,
            &self.nested_challenges_partial,
        ]) {
            point.absorb(dr, transcript)?;
        }
        runs.absorb(dr, transcript)?; // the scalar field's instance values
        Ok(())
    }
}

/// A challenge as the compression uses it: the endoscalar read from the
/// squeezed element, which scales points, and its lift, the scalar the
/// field checks over this field use.
pub(crate) struct Challenge<'dr, D: Driver<'dr>> {
    pub endoscalar: Endoscalar<'dr, D>,
    pub lift: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr>> Challenge<'dr, D> {
    /// Squeezes a challenge, constraining the element into the endoscalar
    /// range as the native transcript requires of it.
    fn squeeze<P: PoseidonPermutation<D::F>>(
        dr: &mut D,
        transcript: &mut Transcript<'dr, D, P>,
    ) -> Result<Self> {
        let element = transcript.challenge(dr)?;
        let endoscalar =
            Endoscalar::extract(EndoscalarChallenge::from_element(dr, &mut (), element)?);
        let lift = endoscalar.lift(dr)?;
        Ok(Challenge { endoscalar, lift })
    }
}

/// A challenge of the fuse's transcript as the compressed verifier
/// replays it: the squeezed element, which the native side uses as it is,
/// and its endoscalar, whose lift the nested side uses and whose bits
/// scale the challenge stage's generator.
pub(crate) struct RawChallenge<'dr, D: Driver<'dr>> {
    pub raw: Element<'dr, D>,
    pub endoscalar: Endoscalar<'dr, D>,
}

impl<'dr, D: Driver<'dr>> RawChallenge<'dr, D> {
    /// Squeezes a challenge, constraining it into the endoscalar range as
    /// the fuse's circuits do.
    pub(crate) fn squeeze<P: PoseidonPermutation<D::F>>(
        dr: &mut D,
        transcript: &mut Transcript<'dr, D, P>,
    ) -> Result<Self> {
        let raw = transcript.challenge(dr)?;
        let endoscalar =
            Endoscalar::extract(EndoscalarChallenge::from_element(dr, &mut (), raw.clone())?);
        Ok(RawChallenge { raw, endoscalar })
    }
}

/// The host curve's messages as the transcript absorbs them: its scalars,
/// which lie in the circuit field, as elements. Its points are in the
/// runs.
pub(crate) struct NativeMessages<'dr, D: Driver<'dr>> {
    pub inner_epsilon: Element<'dr, D>,
    pub outer_epsilon: Element<'dr, D>,
    pub openings: Vec<Element<'dr, D>>,
    pub p_at_inverse_r: Element<'dr, D>,
    pub q_at_r: Element<'dr, D>,
    pub evaluations: Vec<Element<'dr, D>>,
    pub c: Element<'dr, D>,
}

/// The nested curve's messages as the transcript absorbs them: its points.
/// Its scalars are in the runs.
pub(crate) struct NestedMessages<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> {
    pub inner: Point<'dr, D, C>,
    pub outer: Point<'dr, D, C>,
    pub p: Point<'dr, D, C>,
    pub q: Point<'dr, D, C>,
    pub f: Point<'dr, D, C>,
    pub s_commitment: Point<'dr, D, C>,
    pub rounds: Vec<(Point<'dr, D, C>, Point<'dr, D, C>)>,
}

/// The challenges the transcript squeezes for one curve, in the order
/// the native verifier squeezes them.
pub(crate) struct Challenges<'dr, D: Driver<'dr>> {
    pub sampled: Sampled<Challenge<'dr, D>>,
    pub weights: Weights<Challenge<'dr, D>>,
    pub rho: Challenge<'dr, D>,
    pub r: Challenge<'dr, D>,
    pub alpha: Challenge<'dr, D>,
    pub u: Challenge<'dr, D>,
    pub beta: Challenge<'dr, D>,
    pub xi: Challenge<'dr, D>,
    pub z: Challenge<'dr, D>,
    pub rounds: Vec<Challenge<'dr, D>>,
}

/// The runs' commitments in [`Run`](super::stages::Run) order, absorbed
/// one per run as the native transcript absorbs them: witness points,
/// which the chunk circuits' consumer holds to the run stages.
pub(crate) struct Runs<'a, 'dr, D: Driver<'dr>, C: Affine<Base = D::F>> {
    points: core::slice::Iter<'a, Point<'dr, D, C>>,
}

impl<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> Runs<'_, 'dr, D, C> {
    /// Absorbs the next run's commitment.
    fn absorb<P: PoseidonPermutation<D::F>>(
        &mut self,
        dr: &mut D,
        transcript: &mut Transcript<'dr, D, P>,
    ) -> Result<()> {
        self.points
            .next()
            .expect("a commitment per run")
            .absorb(dr, transcript)
    }
}

/// Replays the compression's transcript over the allocated statement,
/// both curves' messages and `runs`, the commitments of the scalar field's
/// runs in [`Run`](super::stages::Run) order, returning each curve's
/// challenges: the statement is absorbed, both curves' challenges are
/// sampled, then the host curve's messages run, then the nested curve's.
///
/// # Panics
///
/// Panics unless `runs` holds one commitment per run.
pub(crate) fn replay<'dr, D, P, C>(
    dr: &mut D,
    params: &'dr P,
    instance: &Instance<'dr, D, C>,
    output_header: &[Element<'dr, D>],
    native: &NativeMessages<'dr, D>,
    nested: &NestedMessages<'dr, D, C>,
    runs: &[Point<'dr, D, C>],
) -> Result<(Challenges<'dr, D>, Challenges<'dr, D>)>
where
    D: Driver<'dr>,
    P: PoseidonPermutation<D::F>,
    C: Affine<Base = D::F>,
{
    let mut runs = Runs {
        points: runs.iter(),
    };
    let mut transcript = Transcript::new(dr, params, IPA_TAG)?;
    instance.absorb(dr, &mut transcript, &mut runs)?;
    for element in output_header {
        element.absorb(dr, &mut transcript)?;
    }
    let native_sampled = sample(dr, &mut transcript)?;
    let nested_sampled = sample(dr, &mut transcript)?;
    let native = native_side(
        dr,
        &mut transcript,
        native_sampled,
        native,
        nested.rounds.len(),
        &mut runs,
    )?;
    let nested = nested_side(dr, &mut transcript, nested_sampled, nested, &mut runs)?;
    assert!(runs.points.next().is_none(), "every run is absorbed");
    Ok((native, nested))
}

/// The challenges sampled for one curve once the statement is absorbed.
fn sample<'dr, D: Driver<'dr>, P: PoseidonPermutation<D::F>>(
    dr: &mut D,
    transcript: &mut Transcript<'dr, D, P>,
) -> Result<Sampled<Challenge<'dr, D>>> {
    Ok(Sampled {
        w: Challenge::squeeze(dr, transcript)?,
        y: Challenge::squeeze(dr, transcript)?,
        z: Challenge::squeeze(dr, transcript)?,
        sigma: Challenge::squeeze(dr, transcript)?,
    })
}

/// The host curve's reduction, batch and IPA of `rounds` rounds on the
/// transcript: its points come as runs, one before each challenge a point
/// precedes.
fn native_side<'dr, D, P, C>(
    dr: &mut D,
    transcript: &mut Transcript<'dr, D, P>,
    sampled: Sampled<Challenge<'dr, D>>,
    messages: &NativeMessages<'dr, D>,
    rounds: usize,
    runs: &mut Runs<'_, 'dr, D, C>,
) -> Result<Challenges<'dr, D>>
where
    D: Driver<'dr>,
    P: PoseidonPermutation<D::F>,
    C: Affine<Base = D::F>,
{
    let squeeze = Challenge::squeeze;

    runs.absorb(dr, transcript)?; // the inner error commitment
    let mu = squeeze(dr, transcript)?;
    let nu = squeeze(dr, transcript)?;
    runs.absorb(dr, transcript)?; // the outer error commitment
    let mu_prime = squeeze(dr, transcript)?;
    let nu_prime = squeeze(dr, transcript)?;
    messages.inner_epsilon.absorb(dr, transcript)?;
    messages.outer_epsilon.absorb(dr, transcript)?;
    let rho = squeeze(dr, transcript)?;
    runs.absorb(dr, transcript)?; // p and q
    let r = squeeze(dr, transcript)?;
    for opened in &messages.openings {
        opened.absorb(dr, transcript)?;
    }
    messages.p_at_inverse_r.absorb(dr, transcript)?;
    messages.q_at_r.absorb(dr, transcript)?;

    let alpha = squeeze(dr, transcript)?;
    runs.absorb(dr, transcript)?; // f
    let u = squeeze(dr, transcript)?;
    for evaluation in &messages.evaluations {
        evaluation.absorb(dr, transcript)?;
    }
    let beta = squeeze(dr, transcript)?;

    runs.absorb(dr, transcript)?; // the masking commitment
    let xi = squeeze(dr, transcript)?;
    let z = squeeze(dr, transcript)?;
    let rounds = (0..rounds)
        .map(|_| {
            runs.absorb(dr, transcript)?; // the round's L and R
            squeeze(dr, transcript)
        })
        .collect::<Result<Vec<_>>>()?;
    messages.c.absorb(dr, transcript)?;

    Ok(Challenges {
        sampled,
        weights: Weights {
            mu,
            nu,
            mu_prime,
            nu_prime,
        },
        rho,
        r,
        alpha,
        u,
        beta,
        xi,
        z,
        rounds,
    })
}

/// The nested curve's reduction, batch and IPA on the transcript: its
/// scalars come as runs, one before each challenge scalars precede; its
/// IPA's $c$ precedes none.
fn nested_side<'dr, D, P, C>(
    dr: &mut D,
    transcript: &mut Transcript<'dr, D, P>,
    sampled: Sampled<Challenge<'dr, D>>,
    messages: &NestedMessages<'dr, D, C>,
    runs: &mut Runs<'_, 'dr, D, C>,
) -> Result<Challenges<'dr, D>>
where
    D: Driver<'dr>,
    P: PoseidonPermutation<D::F>,
    C: Affine<Base = D::F>,
{
    let squeeze = Challenge::squeeze;

    messages.inner.absorb(dr, transcript)?;
    let mu = squeeze(dr, transcript)?;
    let nu = squeeze(dr, transcript)?;
    messages.outer.absorb(dr, transcript)?;
    let mu_prime = squeeze(dr, transcript)?;
    let nu_prime = squeeze(dr, transcript)?;
    runs.absorb(dr, transcript)?; // the two epsilons
    let rho = squeeze(dr, transcript)?;
    messages.p.absorb(dr, transcript)?;
    messages.q.absorb(dr, transcript)?;
    let r = squeeze(dr, transcript)?;
    runs.absorb(dr, transcript)?; // the openings, p(1/r) and q(r)

    let alpha = squeeze(dr, transcript)?;
    messages.f.absorb(dr, transcript)?;
    let u = squeeze(dr, transcript)?;
    runs.absorb(dr, transcript)?; // the batch's values
    let beta = squeeze(dr, transcript)?;

    messages.s_commitment.absorb(dr, transcript)?;
    let xi = squeeze(dr, transcript)?;
    let z = squeeze(dr, transcript)?;
    let mut rounds = Vec::with_capacity(messages.rounds.len());
    for (l, r) in &messages.rounds {
        l.absorb(dr, transcript)?;
        r.absorb(dr, transcript)?;
        rounds.push(squeeze(dr, transcript)?);
    }

    Ok(Challenges {
        sampled,
        weights: Weights {
            mu,
            nu,
            mu_prime,
            nu_prime,
        },
        rho,
        r,
        alpha,
        u,
        beta,
        xi,
        z,
        rounds,
    })
}

#[cfg(test)]
#[path = "../../tests/decompression/transcript.rs"]
mod tests;

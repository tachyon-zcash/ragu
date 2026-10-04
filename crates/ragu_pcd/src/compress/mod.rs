//! Proof compression: the decider's checks restated over commitments and
//! openings, ending in one IPA opening per curve.
//!
//! [`Application::verify`](crate::Application::verify) holds every polynomial of a proof. A compressed
//! proof carries none: its [`Instance`] holds the commitments, the headers
//! and the scalars the decider derives or reads off polynomials, and the
//! prover's messages of three reductions on each curve stand in for the
//! polynomials. The verifier rederives the fuse's challenges from the
//! bridge commitments, recomputes the two nested stages the decider
//! recomputes, samples its own challenges from a transcript over the
//! instance and the output header, and then, on each curve:
//!
//! - [`revdot`] folds the revdot claims, the decider's and the wire
//!   bindings that pin the instance's wires to the stage commitments, to
//!   three, committing the fold's error terms, and reduces those to
//!   openings of five polynomials the verifier derives from the instance's
//!   commitments and the fold's, at a point $r$ or its dilation $rz$;
//! - [`batch`] combines those openings with the registry restriction's, the
//!   batch polynomial's and the accumulator's into one claim;
//! - the [`ipa`](crate::ipa) proves it.
//!
//! The reduction's [`claims`](revdot::claims) module records the revdot
//! claims' shapes, what the fold derives its commitments from, and
//! [`instance`] carries the instance and restates the decider's remaining
//! checks over it. Both curves run on one
//! transcript, the native side first at each step. What the decider checks
//! by recomputing commitments from polynomials needs no counterpart: every
//! polynomial commitment the compressed verifier reads is opened through
//! the IPA, the stage commitments inside the fold's challenge-weighted
//! combinations of them. The one point the instance carries that commits
//! to no polynomial, the nested challenge stage's commitment without its
//! $\beta$ term, is bound as the decider binds it: it enters the native
//! unified instance's $k(y)$, which the `bind_challenges` circuits' claims
//! hold it to.
//!
//! The transcript squeezes circuit-field elements, and every compression
//! challenge is the endoscalar lift of a squeeze, as the fuse's challenges
//! are: the squeeze's low 128 bits read as an endoscalar and lifted into
//! the field of the curve the challenge serves, through [`Lifted`]. The
//! lift is what lets a circuit over the other field scale that curve's
//! points by the challenge, which decompression needs; the nested curve's
//! squeezes first keep their canonical integers within the two fields'
//! common capacity. A squeeze outside the endoscalar range, a $2^{-129}$
//! event, rejects the proof. The lift is injective, so under ideal
//! transcript draws a nonzero degree-$d$ residual in one challenge
//! vanishes with probability at most $d/2^{128}$. These fresh compression
//! challenges are checked by the terminal verifier.
//!
//! Like an uncompressed proof, a compressed proof is not hiding: the
//! openings it carries are evaluations of the witness polynomials.

use ragu_circuits::polynomials::Rank;
use ragu_core::{Cycle, Result};
use ragu_primitives::{extract_endoscalar, lift_endoscalar};
use udon::curve::Affine;

use self::{
    batch::Batch,
    instance::Instance,
    revdot::{Reduction, fold::Derived, native_components, nested_components},
};
use crate::{
    SelectableBackend,
    header::Header,
    ipa::{CycleTranscript, IPA_TAG, IpaProof, IpaTranscript},
};

pub(crate) mod batch;
pub(crate) mod instance;
mod prover;
pub(crate) mod revdot;
mod verifier;

/// The prover's messages of the compression on one curve.
#[derive(Clone, Debug)]
pub(crate) struct Messages<P: Affine> {
    /// The revdot reduction's.
    pub reduction: Reduction<P>,
    /// The batch's.
    pub batch: Batch<P>,
    /// The IPA opening of the batched claim.
    pub opening: IpaProof<P>,
}

/// A compressed proof: the instance and the prover's messages on each
/// curve. Produced by [`Application::compress`](crate::Application::compress)
/// and checked by
/// [`Application::verify_compressed`](crate::Application::verify_compressed).
#[derive(Clone, Debug)]
pub struct CompressedProof<C: Cycle> {
    pub(crate) instance: Instance<C>,
    pub(crate) native: Messages<C::HostCurve>,
    pub(crate) nested: Messages<C::NestedCurve>,
}

impl<C: Cycle> CompressedProof<C> {
    /// Attaches the data the proof attests, producing [`CompressedPcd`].
    pub fn carry<H: Header<C::CircuitField>>(self, data: H::Data) -> CompressedPcd<C, H> {
        CompressedPcd { proof: self, data }
    }

    /// Whether the messages have the shape the verifier reads: one
    /// commitment per component, one opening per derived polynomial, one
    /// value per batched polynomial and one IPA round per bit of the rank.
    fn well_formed<R: Rank>(&self) -> bool {
        fn side<P: Affine, R: Rank>(messages: &Messages<P>) -> bool {
            let derived = Derived::ALL.len();
            // The batch covers the derived polynomials, the reduction's p
            // and q, and the four the instance opens.
            messages.reduction.openings.len() == derived
                && messages.batch.evaluations.len() == derived + 2 + instance::OPENED
                && messages.opening.rounds.len() == R::RANK as usize
        }
        self.instance.native.len() == native_components().count()
            && self.instance.nested.len() == nested_components().count()
            && side::<_, R>(&self.native)
            && side::<_, R>(&self.nested)
    }
}

/// Compressed proof-carrying data: a [`CompressedProof`] with the data it
/// attests, as [`Pcd`](crate::Pcd) pairs a proof with its data.
pub struct CompressedPcd<C: Cycle, H: Header<C::CircuitField>> {
    proof: CompressedProof<C>,
    data: H::Data,
}

impl<C: Cycle, H: Header<C::CircuitField>> CompressedPcd<C, H> {
    /// Returns a reference to the data that the proof accompanies.
    pub fn data(&self) -> &H::Data {
        &self.data
    }

    /// Returns a reference to the compressed proof.
    pub fn proof(&self) -> &CompressedProof<C> {
        &self.proof
    }

    /// Consumes the compressed proof-carrying data and returns the proof and
    /// data separately.
    pub fn into_parts(self) -> (CompressedProof<C>, H::Data) {
        (self.proof, self.data)
    }
}

impl<C: Cycle, H: Header<C::CircuitField>> Clone for CompressedPcd<C, H> {
    fn clone(&self) -> Self {
        CompressedPcd {
            proof: self.proof.clone(),
            data: self.data.clone(),
        }
    }
}

/// The challenges the verifier samples on one curve once the statement is
/// absorbed: $w$ for the registry restriction, $y$ and $z$ for the claims
/// and $\sigma$ for the wire bindings.
pub(crate) struct Sampled<F> {
    pub w: F,
    pub y: F,
    pub z: F,
    pub sigma: F,
}

impl<F> Sampled<F> {
    pub(crate) fn squeeze<P: Affine<Scalar = F>>(
        transcript: &mut impl IpaTranscript<P>,
    ) -> Result<Self> {
        Ok(Sampled {
            w: transcript.squeeze_challenge()?,
            y: transcript.squeeze_challenge()?,
            z: transcript.squeeze_challenge()?,
            sigma: transcript.squeeze_challenge()?,
        })
    }
}

/// A transcript whose challenges are endoscalar lifts, as the fuse's are:
/// each squeeze of the inner transcript is read as an endoscalar, its low
/// 128 bits, and lifted into the scalar field of the curve the challenge
/// serves, so that a circuit over the other field can scale that curve's
/// points by the challenge through the endomorphism while the field checks
/// use the lift. A squeeze outside the endoscalar range, a $2^{-129}$
/// event, rejects the proof, as [`Instance::challenges`] rejects such a
/// `pre_beta`.
pub(crate) struct Lifted<T>(pub T);

impl<C: Affine, T: IpaTranscript<C>> IpaTranscript<C> for Lifted<T> {
    fn write_point(&mut self, point: C) -> Result<()> {
        self.0.write_point(point)
    }

    fn write_scalar(&mut self, scalar: C::Scalar) -> Result<()> {
        self.0.write_scalar(scalar)
    }

    fn squeeze_challenge(&mut self) -> Result<C::Scalar> {
        Ok(lift_endoscalar(extract_endoscalar(
            self.0.squeeze_challenge()?,
        )?))
    }
}

/// The compression's transcript with the statement absorbed: the instance,
/// then the output header.
pub(crate) fn transcript<'params, C: Cycle, B: SelectableBackend>(
    params: &'params C::Params,
    instance: &Instance<C>,
    output_header: &[C::CircuitField],
) -> Result<CycleTranscript<'params, C, B>> {
    let mut transcript = CycleTranscript::<C, B>::new(params, IPA_TAG)?;
    instance.absorb(&mut transcript)?;
    for &element in output_header {
        transcript.host().write_scalar(element)?;
    }
    Ok(transcript)
}

#[cfg(test)]
#[path = "../../tests/compress.rs"]
mod tests;

#[cfg(test)]
#[path = "../../tests/compress_regressions.rs"]
mod regression_tests;

//! Proof compression: the decider's checks restated over commitments and
//! openings, ending in one IPA opening per curve.
//!
//! [`Application::verify`] holds every polynomial of a proof. A compressed
//! proof carries none: its [`Instance`] holds the commitments, the headers
//! and the scalars the decider derives or reads off polynomials, and the
//! prover's messages of three reductions on each curve stand in for the
//! polynomials. The verifier rederives the fuse's challenges from the
//! bridge commitments, recomputes the two nested stages the decider
//! recomputes, samples its own challenges from a transcript over the
//! instance and the output header, and then, on each curve:
//!
//! - [`revdot`] reduces the revdot claims, the decider's and the wire
//!   bindings that pin the instance's wires to the stage commitments, to
//!   openings of the committed polynomials at a point $r$ and its
//!   dilation $rz$;
//! - [`batch`] combines those openings with the registry restriction's, the
//!   batch polynomial's and the accumulator's into one claim;
//! - the [`ipa`] proves it.
//!
//! The [`claims`] module evaluates the revdot claims from the openings, and
//! [`instance`] carries the instance and restates the decider's remaining
//! checks over it. Both curves run on one transcript, the native side first
//! at each step. What the decider checks by recomputing commitments from
//! polynomials needs no counterpart: every commitment the compressed
//! verifier reads is opened through the IPA.
//!
//! Like an uncompressed proof, a compressed proof is not hiding: the
//! openings it carries are evaluations of the witness polynomials.

use alloc::borrow::Cow;

use ragu_arithmetic::{CurveAffine, Cycle, FixedGenerators, ff::Field, rand::CryptoRng};
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::Result;

use self::{
    batch::Batch,
    instance::Instance,
    revdot::{Openings, Reduction, native_components, nested_components},
};
use crate::{
    Application, Pcd, RAGU_TAG, SelectableBackend,
    header::Header,
    internal::ky,
    ipa::{self, Blind, CycleTranscript, IPA_TAG, IpaProof, IpaTranscript, MSM, Params},
};

pub(crate) mod batch;
pub(crate) mod claims;
pub(crate) mod instance;
pub(crate) mod revdot;

/// The backend whose kernels [`Application::verify_compressed`] consults for
/// the selected backend `B`, as [`Application::verify`] does.
type Verifier<B> = <B as SelectableBackend>::Verifier;

/// The polynomials batched on one curve beyond the components: the
/// reduction's $p$ and $q$, the registry restriction and the batch
/// polynomial.
const BATCHED_BEYOND_COMPONENTS: usize = 4;

/// The prover's messages of the compression on one curve.
#[derive(Clone, Debug)]
pub(crate) struct Messages<P: CurveAffine> {
    /// The revdot reduction's.
    pub reduction: Reduction<P>,
    /// The batch's.
    pub batch: Batch<P>,
    /// The IPA opening of the batched claim.
    pub opening: IpaProof<P>,
}

/// A compressed proof: the instance and the prover's messages on each
/// curve. Produced by [`Application::compress`] and checked by
/// [`Application::verify_compressed`].
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
    /// commitment and one pair of openings per component, one value per
    /// batched polynomial and one IPA round per bit of the rank.
    fn well_formed<R: Rank>(&self) -> bool {
        fn side<P: CurveAffine, R: Rank>(commitments: &[P], messages: &Messages<P>) -> bool {
            let components = commitments.len();
            messages.reduction.openings.len() == components
                && messages.batch.evaluations.len() == components + BATCHED_BEYOND_COMPONENTS
                && messages.opening.rounds.len() == R::RANK as usize
        }
        self.instance.native.len() == native_components().count()
            && self.instance.nested.len() == nested_components().count()
            && side::<_, R>(&self.instance.native, &self.native)
            && side::<_, R>(&self.instance.nested, &self.nested)
    }
}

/// Compressed proof-carrying data: a [`CompressedProof`] with the data it
/// attests, as [`Pcd`] pairs a proof with its data.
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
struct Sampled<F> {
    w: F,
    y: F,
    z: F,
    sigma: F,
}

impl<F> Sampled<F> {
    fn squeeze<P: CurveAffine<ScalarExt = F>, T: IpaTranscript<P>>(
        transcript: &mut T,
    ) -> Result<Self> {
        Ok(Sampled {
            w: transcript.squeeze_challenge()?,
            y: transcript.squeeze_challenge()?,
            z: transcript.squeeze_challenge()?,
            sigma: transcript.squeeze_challenge()?,
        })
    }
}

/// The compression's transcript with the statement absorbed: the instance,
/// then the output header.
fn transcript<'params, C: Cycle>(
    params: &'params C::Params,
    instance: &Instance<C>,
    output_header: &[C::CircuitField],
) -> Result<CycleTranscript<'params, C>> {
    let mut transcript = CycleTranscript::<C>::new(params, IPA_TAG)?;
    instance.absorb(&mut transcript)?;
    for &element in output_header {
        transcript.host().write_scalar(element)?;
    }
    Ok(transcript)
}

/// The prover's side past the reduction on one curve: the batch of
/// `openings` over `polys`, then the IPA opening of the batched claim.
fn open<P: CurveAffine, R: Rank, T: IpaTranscript<P>, RNG: CryptoRng>(
    polys: &[Cow<'_, sparse::Polynomial<P::Scalar, R>>],
    openings: &Openings<P>,
    generators: &impl FixedGenerators<P>,
    transcript: &mut T,
    rng: &mut RNG,
) -> Result<(Batch<P>, IpaProof<P>)> {
    let (batch, witness) =
        batch::batch::<_, R, _>(polys, &openings.claims, generators, transcript)?;
    let params = Params::with_k(generators, R::RANK);
    let opening = ipa::create_proof(
        &params,
        rng,
        transcript,
        &witness.p,
        Blind(P::Scalar::ZERO),
        witness.u,
    )?;
    Ok((batch, opening))
}

/// The verifier's side past the reduction on one curve: derives the batched
/// claim of `openings` from `batch` and checks `opening` against it.
fn check<P: CurveAffine, R: Rank, T: IpaTranscript<P>>(
    openings: &Openings<P>,
    batch: &Batch<P>,
    opening: &IpaProof<P>,
    generators: &impl FixedGenerators<P>,
    transcript: &mut T,
) -> Result<bool> {
    let claim = batch::verify(&openings.commitments, &openings.claims, batch, transcript)?;
    let params = Params::with_k(generators, R::RANK);
    let mut msm = MSM::new(&params);
    msm.append_term(P::Scalar::ONE, claim.commitment);
    Ok(
        ipa::verify_proof(&params, msm, transcript, opening, claim.point, claim.value)?
            .use_challenges()
            .eval(),
    )
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, B: SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// Compresses `pcd` into a [`CompressedPcd`] over the same data.
    ///
    /// The result carries the proof's instance and, on each curve, the
    /// messages of the revdot reduction, the batch and the IPA opening, in
    /// place of the proof's polynomials. Compressing does not check the
    /// proof: [`verify_compressed`](Self::verify_compressed) judges the
    /// instance the proof commits to, as [`verify`](Self::verify) judges
    /// the proof.
    pub fn compress<RNG: CryptoRng, H: Header<C::CircuitField>>(
        &self,
        pcd: &Pcd<C, R, H>,
        rng: &mut RNG,
    ) -> Result<CompressedPcd<C, H>> {
        let proof = pcd.proof();
        let instance = Instance::of::<R, HEADER_SIZE>(proof)?;
        let challenges = proof.challenges();
        let output_header = ky::output_header::<C, H, HEADER_SIZE>(pcd.data().clone())?;
        let mut transcript = transcript(self.params, &instance, &output_header)?;
        let native_sampled = Sampled::squeeze(&mut transcript.host())?;
        let nested_sampled = Sampled::squeeze(&mut transcript.nested())?;

        let native = {
            let registry = &self.native_registry;
            let generators = C::host_generators(self.params);
            let Sampled { w, y, z, sigma } = native_sampled;
            let masked =
                instance.native_bindings::<R, B, HEADER_SIZE>(&challenges, registry, sigma)?;
            let (reduction, witness) = revdot::reduce_native::<C, R, B, _>(
                proof,
                registry,
                generators,
                y,
                z,
                &masked,
                &mut transcript.host(),
            )?;
            let mut openings = witness.openings(instance.native.clone(), &reduction, z)?;
            let mut polys = witness.polys(native_components().map(|component| &proof[component]));
            let (commitments, claims) =
                instance.native_openings::<R, B>(&challenges, registry, w, polys.len());
            openings.commitments.extend(commitments);
            openings.claims.extend(claims);
            polys.extend(
                [proof.native_registry_xy_poly(), proof.native_p_poly()].map(Cow::Borrowed),
            );
            let (batch, opening) =
                open::<_, R, _, _>(&polys, &openings, generators, &mut transcript.host(), rng)?;
            Messages {
                reduction,
                batch,
                opening,
            }
        };

        let nested = {
            let registry = &self.nested_registry;
            let generators = C::nested_generators(self.params);
            let Sampled { w, y, z, sigma } = nested_sampled;
            let masked = instance.nested_bindings::<R, B>(&challenges, registry, sigma)?;
            let (reduction, witness) = revdot::reduce_nested::<C, R, B, _>(
                proof,
                registry,
                generators,
                y,
                z,
                &masked,
                &mut transcript.nested(),
            )?;
            let mut openings = witness.openings(instance.nested.clone(), &reduction, z)?;
            let mut polys = witness.polys(nested_components().map(|component| &proof[component]));
            let (commitments, claims) =
                instance.nested_openings::<R, B>(&challenges, registry, w, polys.len())?;
            openings.commitments.extend(commitments);
            openings.claims.extend(claims);
            polys.extend(
                [proof.nested_registry_xy_poly(), proof.nested_p_poly()].map(Cow::Borrowed),
            );
            let (batch, opening) =
                open::<_, R, _, _>(&polys, &openings, generators, &mut transcript.nested(), rng)?;
            Messages {
                reduction,
                batch,
                opening,
            }
        };

        Ok(CompressedProof {
            instance,
            native,
            nested,
        }
        .carry(pcd.data().clone()))
    }

    /// Verifies some [`CompressedPcd`] for the provided [`Header`].
    ///
    /// Returns `Ok(true)` if every check passes, `Ok(false)` if any fails
    /// (an invalid circuit id, a malformed proof, a rejected reduction or
    /// opening), or `Err` if an internal computation error occurs.
    ///
    /// The computational kernels are those of the sealed
    /// [`SelectableBackend::Verifier`] of the selected backend, as for
    /// [`verify`](Self::verify).
    pub fn verify_compressed<H: Header<C::CircuitField>>(
        &self,
        pcd: &CompressedPcd<C, H>,
    ) -> Result<bool> {
        let proof = pcd.proof();
        let instance = &proof.instance;

        // The proof's circuit_id must be in the registry's domain, for the
        // reason `verify` gives, and the headers must have the declared
        // size; and the messages must have the shape read below.
        if !self.native_registry.circuit_in_domain(instance.circuit_id)
            || instance.left_header.len() != HEADER_SIZE
            || instance.right_header.len() != HEADER_SIZE
            || !proof.well_formed::<R>()
        {
            return Ok(false);
        }

        // The fuse's challenges, from the bridge commitments in the fuse's
        // schedule, with pre_beta in the endoscalar range; and the nested
        // stages the decider recomputes from public data.
        let Some(challenges) =
            instance.challenges(&mut CycleTranscript::<C>::new(self.params, RAGU_TAG)?)?
        else {
            return Ok(false);
        };
        if !instance.stages_match::<R, Verifier<B>, HEADER_SIZE>(
            &challenges,
            C::nested_generators(self.params),
        )? {
            return Ok(false);
        }

        let output_header = ky::output_header::<C, H, HEADER_SIZE>(pcd.data().clone())?;
        let mut transcript = transcript(self.params, instance, &output_header)?;
        let native_sampled = Sampled::squeeze(&mut transcript.host())?;
        let nested_sampled = Sampled::squeeze(&mut transcript.nested())?;
        let (native_targets, nested_targets) = instance.targets::<HEADER_SIZE>(
            &challenges,
            &output_header,
            native_sampled.y,
            nested_sampled.y,
        )?;

        let native = {
            let registry = &self.native_registry;
            let Sampled { w, y, z, sigma } = native_sampled;
            let masked = instance.native_bindings::<R, Verifier<B>, HEADER_SIZE>(
                &challenges,
                registry,
                sigma,
            )?;
            let Some(mut openings) = revdot::verify_native::<C, R, _>(
                instance.circuit_id,
                |component| instance.native_commitment(component),
                registry,
                y,
                z,
                &native_targets,
                &masked,
                &proof.native.reduction,
                &mut transcript.host(),
            )?
            else {
                return Ok(false);
            };
            let (commitments, claims) = instance.native_openings::<R, Verifier<B>>(
                &challenges,
                registry,
                w,
                openings.commitments.len(),
            );
            openings.commitments.extend(commitments);
            openings.claims.extend(claims);
            check::<_, R, _>(
                &openings,
                &proof.native.batch,
                &proof.native.opening,
                C::host_generators(self.params),
                &mut transcript.host(),
            )?
        };
        if !native {
            return Ok(false);
        }

        let nested = {
            let registry = &self.nested_registry;
            let Sampled { w, y, z, sigma } = nested_sampled;
            let masked =
                instance.nested_bindings::<R, Verifier<B>>(&challenges, registry, sigma)?;
            let Some(mut openings) = revdot::verify_nested::<C, R, _>(
                |component| instance.nested_commitment(component),
                registry,
                y,
                z,
                &nested_targets,
                &masked,
                &proof.nested.reduction,
                &mut transcript.nested(),
            )?
            else {
                return Ok(false);
            };
            let (commitments, claims) = instance.nested_openings::<R, Verifier<B>>(
                &challenges,
                registry,
                w,
                openings.commitments.len(),
            )?;
            openings.commitments.extend(commitments);
            openings.claims.extend(claims);
            check::<_, R, _>(
                &openings,
                &proof.nested.batch,
                &proof.nested.opening,
                C::nested_generators(self.params),
                &mut transcript.nested(),
            )?
        };
        Ok(nested)
    }
}

#[cfg(test)]
#[path = "../../tests/compress.rs"]
mod tests;

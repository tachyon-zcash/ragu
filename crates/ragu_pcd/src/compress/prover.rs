//! The prover's side of the compression: [`Application::compress`].

use alloc::borrow::Cow;

use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{Error, FixedGenerators, Result};
use rand::CryptoRng;
use udon::curve::Affine;

use super::{
    CompressedPcd, CompressedProof, Messages, Sampled,
    batch::{self, Batch},
    instance::Instance,
    revdot::{self, Openings},
    transcript,
};
use crate::{
    Application, Pcd, RAGU_TAG, SelectableBackend,
    header::Header,
    internal::{ky, native, nested},
    ipa::{self, CycleTranscript, IpaCycle, IpaProof, IpaTranscript, Params},
    profile::ProfiledCycle,
};

/// Batches `openings` over `polys` and opens the batched claim through the
/// IPA, on one curve. Returns the batch's messages and the IPA proof.
fn open<P: Affine, R: Rank, B: SelectableBackend>(
    polys: &[Cow<'_, sparse::Polynomial<P::Scalar, R>>],
    openings: &Openings<P>,
    generators: &impl FixedGenerators<P>,
    u: P,
    transcript: &mut impl IpaTranscript<P>,
    rng: &mut impl CryptoRng,
) -> Result<(Batch<P>, IpaProof<P>)> {
    let (batch, witness) =
        batch::batch::<_, R, B>(polys, &openings.claims, generators, transcript)?;
    let params = Params::with_k(generators, u, R::RANK);
    let opening = ipa::create_proof::<B, _>(&params, rng, transcript, &witness.p, witness.u)?;
    Ok((batch, opening))
}

impl<C: IpaCycle + ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// Compresses `pcd` into a [`CompressedPcd`] over the same data.
    ///
    /// The result carries the proof's instance and, on each curve, the
    /// messages of the revdot reduction, the batch and the IPA opening, in
    /// place of the proof's polynomials. Compression checks the proof's shape,
    /// circuit index and stored transcript challenges. Accept the result only
    /// after [`verify_compressed`](Self::verify_compressed) succeeds.
    /// Together these checks also validate the original proof for reuse as a
    /// child.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidWitness`] if the proof's shape is malformed,
    /// its circuit index is outside this application's registry domain, or
    /// its stored challenges differ from the replayed transcript.
    pub fn compress<RNG: CryptoRng, H: Header<C::CircuitField>>(
        &self,
        pcd: &Pcd<C, R, H>,
        rng: &mut RNG,
    ) -> Result<CompressedPcd<C, H>> {
        let proof = pcd.proof();
        if !proof.well_formed::<HEADER_SIZE>() {
            return Err(Error::InvalidWitness("malformed proof shape".into()));
        }
        if !self.native_registry.circuit_in_domain(proof.circuit_id()) {
            return Err(Error::InvalidWitness(
                "proof circuit index is outside the registry domain".into(),
            ));
        }
        let instance = Instance::of::<R, HEADER_SIZE>(proof)?;
        // The compressed statement omits the stored challenges, but a parent
        // consumes them from the original proof. Hold every cached challenge
        // to the same transcript the verifier replays before proving anything.
        // This also checks the stored `u` used by `Instance::of` for v and v_n.
        // A later refactor may have `fuse` rederive a child's challenges from
        // its bridge commitments and treat the stored ones as a cache it
        // refreshes; then nothing reads the cache and this check can go.
        let mut fuse_transcript =
            CycleTranscript::<C, <B as SelectableBackend>::Verifier>::new(self.params, RAGU_TAG)?;
        let challenges = instance.challenges(&mut fuse_transcript)?.ok_or_else(|| {
            Error::InvalidWitness(
                "proof transcript challenge is outside the endoscalar range".into(),
            )
        })?;
        if challenges.in_order() != proof.challenges().in_order() {
            return Err(Error::InvalidWitness(
                "stored proof challenges differ from the transcript".into(),
            ));
        }
        let output_header = ky::output_header::<C, H, HEADER_SIZE>(pcd.data().clone())?;
        let mut transcript = transcript::<C, B>(self.params, &instance, &output_header)?;
        let native_sampled = Sampled::squeeze(&mut transcript.host())?;
        let nested_sampled = Sampled::squeeze(&mut transcript.nested())?;

        let native = {
            let registry = &self.native_registry;
            let generators = C::host_generators(self.params);
            let Sampled { w, y, z, sigma } = native_sampled;
            let masked =
                instance.native_bindings::<R, B, HEADER_SIZE>(&challenges, registry, sigma)?;
            let (reduction, witness) = revdot::reduce_native::<C, R, B>(
                proof,
                registry,
                generators,
                y,
                z,
                &masked,
                &mut transcript.host(),
            )?;
            let mut openings = witness.openings(&reduction, z)?;
            let mut polys = witness.polys();
            let (commitments, claims) =
                instance.native_openings::<R, B>(&challenges, registry, w, polys.len());
            openings.commitments.extend(commitments);
            openings.claims.extend(claims);
            polys.extend(
                [
                    proof.native_registry_xy_poly(),
                    proof.native_p_poly(),
                    &proof[native::RxComponent::AbA],
                    &proof[native::RxComponent::AbB],
                ]
                .map(Cow::Borrowed),
            );
            let u = *C::host_u(self.params);
            let (batch, opening) = open::<_, R, B>(
                &polys,
                &openings,
                generators,
                u,
                &mut transcript.host(),
                rng,
            )?;
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
            let (reduction, witness) = revdot::reduce_nested::<C, R, B>(
                proof,
                registry,
                generators,
                y,
                z,
                &masked,
                &mut transcript.nested(),
            )?;
            let mut openings = witness.openings(&reduction, z)?;
            let mut polys = witness.polys();
            let (commitments, claims) =
                instance.nested_openings::<R, B>(&challenges, registry, w, polys.len())?;
            openings.commitments.extend(commitments);
            openings.claims.extend(claims);
            polys.extend(
                [
                    proof.nested_registry_xy_poly(),
                    proof.nested_p_poly(),
                    &proof[nested::RxComponent::AbA],
                    &proof[nested::RxComponent::AbB],
                ]
                .map(Cow::Borrowed),
            );
            let u = *C::nested_u(self.params);
            let (batch, opening) = open::<_, R, B>(
                &polys,
                &openings,
                generators,
                u,
                &mut transcript.nested(),
                rng,
            )?;
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
}

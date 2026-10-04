//! The prover's side of the compression: [`Application::compress`].

use alloc::borrow::Cow;

use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{FixedGenerators, Result};
use rand::CryptoRng;
use udon::curve::Affine;

use super::{
    CompressedPcd, CompressedProof, Lifted, Messages, Sampled,
    batch::{self, Batch},
    instance::Instance,
    revdot::{self, Openings},
    transcript,
};
use crate::{
    Application, Pcd, SelectableBackend,
    header::Header,
    internal::{ky, native, nested},
    ipa::{self, IpaCycle, IpaProof, IpaTranscript, Params},
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

impl<C: IpaCycle, R: Rank, const HEADER_SIZE: usize, B: SelectableBackend>
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
        // The challenges as the proof stores them: a cache of the fuse's own
        // squeezes, which the decider holds to the transcript. `Instance::of`
        // reads the stored `u` for `v` and `v_n` the same way. The verifier
        // reads neither; it replays the challenges from the bridge
        // commitments through `Instance::challenges`. Should the stored
        // challenges ever be more than that cache, replay them here too and
        // evaluate `v` and `v_n` at the replayed `u`.
        let challenges = proof.challenges();
        let output_header = ky::output_header::<C, H, HEADER_SIZE>(pcd.data().clone())?;
        let mut transcript = transcript::<C, B>(self.params, &instance, &output_header)?;
        let native_sampled = Sampled::squeeze(&mut Lifted(transcript.host()))?;
        let nested_sampled = Sampled::squeeze(&mut Lifted(transcript.nested()))?;

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
                &mut Lifted(transcript.host()),
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
                &mut Lifted(transcript.host()),
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
                &mut Lifted(transcript.nested()),
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
                &mut Lifted(transcript.nested()),
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

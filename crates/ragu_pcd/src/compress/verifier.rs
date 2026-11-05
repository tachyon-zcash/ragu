//! The verifier's side of the compression: [`Application::verify_compressed`].

use ragu_circuits::polynomials::Rank;
use ragu_core::{Error, Result};

use super::{CompressedPcd, CompressedProof, Lifted, Sampled, batch, revdot, transcript};
use crate::{
    Application, RAGU_TAG, SelectableBackend,
    header::Header,
    internal::{ky, nested},
    ipa::{CycleTranscript, IpaCycle},
    profile::ProfiledCycle,
};

/// The backend whose kernels [`Application::verify_compressed`] consults for
/// the selected backend `B`, as `Application::verify_uncompressed` does.
type Verifier<B> = <B as SelectableBackend>::Verifier;

impl<C: IpaCycle + ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// Admits `proof` to the compression's transcript, as verification
    /// begins: its circuit id is in the registry's domain, for the reason
    /// `verify_uncompressed` gives; its headers have the declared size; its
    /// messages have the shape the verifier reads; the fuse's challenges,
    /// from the bridge commitments in the fuse's schedule, lie in the
    /// endoscalar range; and the two nested stages the decider
    /// recomputes from public data commit as the instance claims. Returns
    /// the fuse's challenges.
    ///
    /// [`verify_compressed`](Self::verify_compressed) runs these checks
    /// before the compression's transcript, and so does the decompression's
    /// witness preparation, which repeats the verifier's later computations
    /// but not these: a proof the verifier rejects here is refused before
    /// any proving.
    ///
    /// # Errors
    ///
    /// Fails with [`Error::InvalidWitness`] if a check rejects the proof, or
    /// with another error on an internal computation error.
    pub(crate) fn admit_compressed(
        &self,
        proof: &CompressedProof<C>,
    ) -> Result<nested::Challenges<C::CircuitField>> {
        let instance = &proof.instance;
        if !self.native_registry.circuit_in_domain(instance.circuit_id) {
            return Err(Error::InvalidWitness(
                "the circuit id is outside the registry's domain".into(),
            ));
        }
        if instance.left_header.len() != HEADER_SIZE || instance.right_header.len() != HEADER_SIZE {
            return Err(Error::InvalidWitness(
                "a child header does not have the declared size".into(),
            ));
        }
        if !proof.well_formed::<R>() {
            return Err(Error::InvalidWitness(
                "the messages do not have the shape the verifier reads".into(),
            ));
        }
        let mut fuse_transcript = CycleTranscript::<C>::fuse(self.params, RAGU_TAG)?;
        let challenges = instance
            .challenges(&mut fuse_transcript)?
            .ok_or_else(|| Error::InvalidWitness("pre_beta is out of range".into()))?;
        if challenges.lifts::<C>().is_err() {
            return Err(Error::InvalidWitness(
                "a fuse challenge is outside the endoscalar range".into(),
            ));
        }
        if !instance.stages_match::<R, Verifier<B>, HEADER_SIZE>(
            &challenges,
            C::nested_generators(self.params),
        )? {
            return Err(Error::InvalidWitness(
                "a recomputed nested stage does not commit as the instance claims".into(),
            ));
        }
        Ok(challenges)
    }

    /// Verifies some [`CompressedPcd`] for the provided [`Header`].
    ///
    /// Returns `Ok(true)` if every check passes, `Ok(false)` if any fails
    /// (an invalid circuit id, a malformed proof, a rejected reduction or
    /// opening), or `Err` if an internal computation error occurs.
    ///
    /// Uses this application's fixed profile, registries and public
    /// parameters, as `verify_uncompressed` does. Proof data cannot select
    /// another profile or setup; its circuit ID selects only within this
    /// application's registry.
    ///
    /// The registry and polynomial evaluations and the recomputed stage
    /// commitments go through the sealed [`SelectableBackend::Verifier`] of
    /// the selected backend, as in `verify_uncompressed`. This also applies to
    /// batch commitment combinations and IPA MSMs.
    pub fn verify_compressed<H: Header<C::CircuitField>>(
        &self,
        pcd: &CompressedPcd<C, H>,
    ) -> Result<bool> {
        // These checks report malformed proof messages and unusable
        // transcript challenges as InvalidWitness. Translate only those
        // proof-dependent failures: header encoding and static circuit
        // computations can use the same variant for internal errors.
        macro_rules! proof_check {
            ($result:expr) => {
                match $result {
                    Ok(value) => value,
                    Err(Error::InvalidWitness(_)) => return Ok(false),
                    Err(error) => return Err(error),
                }
            };
        }

        let proof = pcd.proof();
        let instance = &proof.instance;
        let challenges = proof_check!(self.admit_compressed(proof));

        let output_header = ky::output_header::<C, H, HEADER_SIZE>(pcd.data().clone())?;
        let mut transcript = proof_check!(transcript::<C, Verifier<B>, R>(
            self.params,
            instance,
            &output_header
        ));
        let native_sampled = proof_check!(Sampled::squeeze(&mut Lifted(transcript.host())));
        let nested_sampled = proof_check!(Sampled::squeeze(&mut Lifted(transcript.nested())));
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
            let Some(mut openings) = proof_check!(revdot::verify_native::<C, R, Verifier<B>>(
                instance.circuit_id,
                |component| instance.native_commitment(component),
                registry,
                y,
                z,
                &native_targets,
                &masked,
                &proof.native.reduction,
                &mut Lifted(transcript.host()),
            )) else {
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
            proof_check!(batch::verify_openings::<_, R, Verifier<B>>(
                &openings,
                &proof.native.batch,
                &proof.native.opening,
                C::host_generators(self.params),
                *C::host_u(self.params),
                &mut Lifted(transcript.host()),
            ))
        };
        if !native {
            return Ok(false);
        }

        let nested = {
            let registry = &self.nested_registry;
            let Sampled { w, y, z, sigma } = nested_sampled;
            let masked =
                instance.nested_bindings::<R, Verifier<B>>(&challenges, registry, sigma)?;
            let Some(mut openings) = proof_check!(revdot::verify_nested::<C, R, Verifier<B>>(
                |component| instance.nested_commitment(component),
                registry,
                y,
                z,
                &nested_targets,
                &masked,
                &proof.nested.reduction,
                &mut Lifted(transcript.nested()),
            )) else {
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
            proof_check!(batch::verify_openings::<_, R, Verifier<B>>(
                &openings,
                &proof.nested.batch,
                &proof.nested.opening,
                C::nested_generators(self.params),
                *C::nested_u(self.params),
                &mut Lifted(transcript.nested()),
            ))
        };
        Ok(nested)
    }
}

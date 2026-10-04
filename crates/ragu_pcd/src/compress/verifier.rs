//! The verifier's side of the compression: [`Application::verify_compressed`].

use ragu_circuits::polynomials::Rank;
use ragu_core::{Error, Result};

use super::{CompressedPcd, Sampled, batch, revdot, transcript};
use crate::{
    Application, RAGU_TAG, SelectableBackend,
    header::Header,
    internal::ky,
    ipa::{CycleTranscript, IpaCycle},
};

/// The backend whose kernels [`Application::verify_compressed`] consults for
/// the selected backend `B`, as [`Application::verify`] does.
type Verifier<B> = <B as SelectableBackend>::Verifier;

impl<C: IpaCycle, R: Rank, const HEADER_SIZE: usize, B: SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// Verifies some [`CompressedPcd`] for the provided [`Header`].
    ///
    /// Returns `Ok(true)` if every check passes, `Ok(false)` if any fails
    /// (an invalid circuit id, a malformed proof, a rejected reduction or
    /// opening), or `Err` if an internal computation error occurs.
    ///
    /// The registry and polynomial evaluations and the recomputed stage
    /// commitments go through the sealed [`SelectableBackend::Verifier`] of
    /// the selected backend, as in [`verify`](Self::verify). This also applies
    /// to transcript bridges, batch commitment combinations, and IPA MSMs.
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
        let mut fuse_transcript = CycleTranscript::<C, Verifier<B>>::new(self.params, RAGU_TAG)?;
        let Some(challenges) = proof_check!(instance.challenges(&mut fuse_transcript)) else {
            return Ok(false);
        };
        if !proof_check!(instance.stages_match::<R, Verifier<B>, HEADER_SIZE>(
            &challenges,
            C::nested_generators(self.params),
        )) {
            return Ok(false);
        }

        let output_header = ky::output_header::<C, H, HEADER_SIZE>(pcd.data().clone())?;
        let mut transcript = proof_check!(transcript::<C, Verifier<B>>(
            self.params,
            instance,
            &output_header,
        ));
        let native_sampled = proof_check!(Sampled::squeeze(&mut transcript.host()));
        let nested_sampled = proof_check!(Sampled::squeeze(&mut transcript.nested()));
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
            let Some(mut openings) = proof_check!(revdot::verify_native::<C, R, Verifier<B>, _>(
                instance.circuit_id,
                |component| instance.native_commitment(component),
                registry,
                y,
                z,
                &native_targets,
                &masked,
                &proof.native.reduction,
                &mut transcript.host(),
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
            proof_check!(batch::verify_openings::<_, R, Verifier<B>, _>(
                &openings,
                &proof.native.batch,
                &proof.native.opening,
                C::host_generators(self.params),
                *C::host_u(self.params),
                &mut transcript.host(),
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
            let Some(mut openings) = proof_check!(revdot::verify_nested::<C, R, Verifier<B>, _>(
                |component| instance.nested_commitment(component),
                registry,
                y,
                z,
                &nested_targets,
                &masked,
                &proof.nested.reduction,
                &mut transcript.nested(),
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
            proof_check!(batch::verify_openings::<_, R, Verifier<B>, _>(
                &openings,
                &proof.nested.batch,
                &proof.nested.opening,
                C::nested_generators(self.params),
                *C::nested_u(self.params),
                &mut transcript.nested(),
            ))
        };
        Ok(nested)
    }
}

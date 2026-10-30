//! Expansion of a [`MinimalProof`] into a [`Proof`]: the derived fields,
//! recomputed from the provided ones by the same rules the verifier holds
//! them to.

use alloc::sync::Arc;

use ragu_circuits::{polynomials::Rank, staging::StageExt as _};
use ragu_core::{Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::{GadgetExt as _, Point};
use udon::field::Field;

use super::{Cached, MinimalProof, Proof, ProofDerived, bridge_alpha_power};
use crate::{
    Application, RAGU_TAG, SelectableBackend,
    internal::{
        nested::{
            self, RxIndex,
            stages::{ab as nested_ab, challenges as nested_challenges},
        },
        transcript::Transcript,
    },
    profile::ProfiledCycle,
};

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// Rebuilds a [`Proof`] from its minimal form.
    ///
    /// The challenges are squeezed from the transcript over the bridge
    /// commitments in the fuse's schedule, the `ab` bridge stage from the
    /// bridge blinding and the native commitments it binds, and the nested
    /// challenge stage from the challenges' lifts and the children's headers.
    /// None of these is read from the input, so an expanded proof carries
    /// only values this application would derive itself.
    ///
    /// Expansion does not validate the provided fields or their commitments.
    /// [Compress](Self::compress) the expanded proof and accept it on
    /// [`verify_compressed`](Self::verify_compressed) before using it in
    /// another proof. The uncompressed `verify_minimal`, under `test-utils`,
    /// is a test oracle for that path.
    ///
    /// # Errors
    ///
    /// Returns an error if a bridge commitment is not an affine point or a
    /// squeezed challenge has no lift, which an honest transcript produces
    /// with negligible probability. A receiver of untrusted input treats
    /// either as a rejection, as `verify_minimal` does.
    pub fn expand(&self, proof: MinimalProof<C, R, HEADER_SIZE>) -> Result<Proof<C, R>> {
        let mut dr = Emulator::execute();
        let mut transcript = Transcript::new(&mut dr, C::circuit_poseidon(self.params), RAGU_TAG)?;
        macro_rules! absorb {
            ($point:expr) => {
                Point::constant(&mut dr, $point)?.write(&mut dr, &mut transcript)?
            };
        }
        macro_rules! squeeze {
            () => {
                *transcript.challenge(&mut dr)?.value().take()
            };
        }
        absorb!(proof.bridge_preamble_commitment);
        let w = squeeze!();
        absorb!(proof.bridge_s_prime_commitment);
        let y = squeeze!();
        let z = squeeze!();
        absorb!(proof.bridge_inner_error_commitment);
        let mu = squeeze!();
        absorb!(proof.bridge_outer_error_commitment);
        let mu_prime = squeeze!();
        absorb!(proof.bridge_ab_commitment.0);
        let x = squeeze!();
        absorb!(proof.bridge_query_commitment);
        let alpha = squeeze!();
        absorb!(proof.bridge_f_commitment);
        let u = squeeze!();
        absorb!(proof.bridge_eval_commitment);
        let pre_beta = squeeze!();

        let lifts = nested::Challenges {
            w,
            y,
            z,
            mu,
            mu_prime,
            x,
            alpha,
            u,
            pre_beta,
        }
        .lifts::<C>()?;
        let (challenge_lifts, beta_lift) = lifts.split_at(nested_challenges::NUM);
        let nested_challenges_rx = nested_challenges::Stage::<C::HostCurve, R, C::Profile>::rx(
            C::ScalarField::ZERO,
            &nested_challenges::Witness::new::<_, HEADER_SIZE>(
                challenge_lifts.try_into().expect("NUM challenge lifts"),
                &proof.left_header,
                &proof.right_header,
                beta_lift[0],
            ),
        )?;

        let bridge_ab_rx = nested_ab::Stage::<C::HostCurve, R, C::Profile>::rx(
            bridge_alpha_power(proof.bridge_alpha, RxIndex::BridgeAB),
            &nested_ab::Witness {
                a: proof.native_a_commitment.0,
                b: proof.native_b_commitment.0,
                native_points_ab: proof.native_points_ab_commitment.0,
            },
        )?;

        Ok(Proof::expand(
            proof,
            ProofDerived {
                w,
                y,
                z,
                mu,
                mu_prime,
                x,
                alpha,
                u,
                pre_beta,
                bridge_ab_rx: Cached(Arc::new(bridge_ab_rx)),
                nested_challenges_rx,
            },
        ))
    }
}

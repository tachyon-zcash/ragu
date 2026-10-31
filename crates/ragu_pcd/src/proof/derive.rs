//! The values a proof's encoding omits, derived from the ones it retains by
//! the same rules the verifier holds them to.

use alloc::{borrow::Cow, sync::Arc};

use ragu_circuits::{polynomials::Rank, staging::StageExt as _};
use ragu_core::{Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::{GadgetExt as _, Point};
use udon::field::Field;

use super::{Cached, Pcd, Proof, ProofDerived, bridge_alpha_power};
use crate::{
    Application, RAGU_TAG, SelectableBackend,
    header::Header,
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
    /// The proof-carrying data with every field of its proof set: borrowed
    /// when the proof was built in memory, or a copy with the derived fields
    /// filled when it was deserialized.
    ///
    /// Expects a proof whose shape the calling method has checked.
    pub(crate) fn complete<'p, H: Header<C::CircuitField>>(
        &self,
        pcd: &'p Pcd<C, R, H>,
    ) -> Result<Cow<'p, Pcd<C, R, H>>> {
        if pcd.proof.complete {
            return Ok(Cow::Borrowed(pcd));
        }
        let mut pcd = pcd.clone();
        self.derive(&mut pcd.proof)?;
        Ok(Cow::Owned(pcd))
    }

    /// [`complete`](Self::complete) for proof-carrying data the caller gives
    /// up, filling its proof in place.
    pub(crate) fn complete_owned<H: Header<C::CircuitField>>(
        &self,
        mut pcd: Pcd<C, R, H>,
    ) -> Result<Pcd<C, R, H>> {
        if !pcd.proof.complete {
            self.derive(&mut pcd.proof)?;
        }
        Ok(pcd)
    }

    /// Fills a deserialized proof's derived fields.
    ///
    /// The challenges are squeezed from the transcript over the bridge
    /// commitments in the fuse's schedule, the `ab` bridge stage from the
    /// bridge blinding and the native commitments it binds, and the nested
    /// challenge stage from the challenges' lifts and the children's headers.
    /// None of these is read from the encoding, so a deserialized proof
    /// carries only values this application derives itself.
    ///
    /// Expects a proof whose shape the calling method has checked.
    ///
    /// # Errors
    ///
    /// Returns an error if a squeezed challenge has no lift, which an honest
    /// transcript produces with negligible probability. Callers treat it as a
    /// rejection of the proof.
    pub(super) fn derive(&self, proof: &mut Proof<C, R>) -> Result<()> {
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

        proof.fill(ProofDerived {
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
        });
        Ok(())
    }
}

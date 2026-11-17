//! The compressed proof and proof-carrying data: the instance and the
//! prover's messages on each curve.

use ragu_circuits::polynomials::Rank;
use ragu_core::Cycle;
use udon::curve::Affine;

use crate::{
    header::{Header, NUM_ONLINE_FP_POLYS},
    profile::ProfiledCycle,
    protocol::{
        compress::{
            batch::Batch,
            instance::{self, Instance},
            revdot::{Reduction, fold::Derived, native_components, nested_components},
        },
        ipa::IpaProof,
    },
};

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

impl<C: ProfiledCycle> CompressedProof<C> {
    /// Attaches the data the proof attests, producing [`CompressedPcd`].
    pub fn carry<H: Header<C::CircuitField>>(self, data: H::Data) -> CompressedPcd<C, H> {
        CompressedPcd { proof: self, data }
    }

    /// The commitments of the step's own online polynomials, one per slot,
    /// as [`Pcd::commitments`](crate::Pcd::commitments) returns them before
    /// compression. The instance carries them and the verifier binds them,
    /// so a verifier that accepts the proof may compare them to the
    /// commitments it expects.
    pub fn online_commitments(&self) -> [C::HostCurve; NUM_ONLINE_FP_POLYS] {
        self.instance.online_commitments
    }

    /// Whether the messages have the shape the verifier reads: one
    /// commitment per component, one opening per derived polynomial, one
    /// value per batched polynomial and one IPA round per bit of the rank.
    pub(crate) fn well_formed<R: Rank>(&self) -> bool {
        fn side<P: Affine, R: Rank>(messages: &Messages<P>) -> bool {
            let derived = Derived::ALL.len();
            // The batch covers the derived polynomials, the reduction's p
            // and q, and the four the instance opens.
            messages.reduction.openings.len() == derived
                && messages.batch.evaluations.len() == derived + 2 + instance::OPENED
                && messages.opening.rounds.len() == R::RANK as usize
        }
        self.instance.native.len() == native_components::<C::Profile>().count()
            && self.instance.nested.len() == nested_components::<C::Profile>().count()
            && side::<_, R>(&self.native)
            && side::<_, R>(&self.nested)
    }
}

/// Compressed proof-carrying data: a [`CompressedProof`] with the data it
/// attests, as [`Pcd`](crate::Pcd) pairs a proof with its data.
pub struct CompressedPcd<C: Cycle, H: Header<C::CircuitField>> {
    pub(crate) proof: CompressedProof<C>,
    pub(crate) data: H::Data,
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

    /// The commitments of the step's own online polynomials; see
    /// [`CompressedProof::online_commitments`].
    pub fn online_commitments(&self) -> [C::HostCurve; NUM_ONLINE_FP_POLYS] {
        self.proof.instance.online_commitments
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

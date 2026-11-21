//! The compressed proof: the compression's instance and its messages on each
//! curve, and [`CompressedPcd`], which pairs it with the data it attests.

use ragu_core::Cycle;

use crate::{
    compress::{Messages, instance::Instance},
    header::{Header, NUM_ONLINE_FP_POLYS},
    profile::ProfiledCycle,
};

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

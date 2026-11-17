//! The inner product argument's definitions both roles share: the
//! parameters, the opening proof, the transcript and the MSM. The prover's
//! [`create_proof`](crate::prover::ipa::create_proof) and the verifier's
//! [`verify_proof`](crate::verifier::ipa::verify_proof) are implemented over
//! them in their role modules, and [`crate::ipa`] is the argument's public API
//! and its description.

pub(crate) mod msm;
mod params;
mod proof;
mod transcript;

pub use msm::MSM;
pub use params::{IpaCycle, Params};
pub use proof::IpaProof;
pub use transcript::{CycleTranscript, HostSide, IpaTranscript, NestedSide};

/// Domain separation tag for the compression, whose transcript runs from
/// the instance through the reductions to the IPAs, keeping it distinct from
/// the fuse's. A transcript handed to
/// [`create_proof`](crate::prover::ipa::create_proof) and
/// [`verify_proof`](crate::verifier::ipa::verify_proof) must be created with
/// it.
///
/// The prover and all verifier paths must agree on this tag. Changing it
/// breaks compatibility with existing proofs.
///
/// Profiles share this protocol domain. Compression opens the native and
/// nested registry restrictions against the receiving application's tagged
/// registries, preserving the fuse's setup binding.
pub const IPA_TAG: &[u8] = b"ragu-ipa-v1";

#[cfg(test)]
#[path = "../../../tests/ipa.rs"]
mod tests;

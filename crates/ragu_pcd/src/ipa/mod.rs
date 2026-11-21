//! Unblinded inner product argument (IPA) for polynomial commitments.
//!
//! Adapted from halo2's `halo2_proofs/src/poly/commitment`. Pedersen blinding
//! with generator `W` is omitted for now because compression currently proves
//! unblinded relations. An opening proves knowledge of `p` with
//! `P = <p, G>` and `p(x) = v`.
//!
//! Unblinded round commitments can be the identity for valid openings, which
//! [`CycleTranscript`] rejects. With two coefficients and `x = 0`, `R` is
//! necessarily the identity. This is a temporary completeness limitation;
//! future blinding would need to cover the round commitments to remove this
//! deterministic failure.
//!
//! The masking polynomial `s`, with `s(x) = 0`, is retained to mask the
//! coefficients folded by the argument. Fiat-Shamir goes through
//! [`IpaTranscript`], implemented for both curves by [`CycleTranscript`].
//!
//! This module is the argument's public API. The definitions both roles share
//! (the parameters, the opening proof, the transcript and the MSM) live here,
//! [`create_proof`] in `prover` and [`verify_proof`] in `verifier`.

// TODO: Revisit the removal of Pedersen blinds from `S`, `L`, and `R`
// during rerandomization work, including the resulting completeness failures.

pub(crate) mod msm;
mod params;
mod proof;
pub(crate) mod prover;
mod transcript;
pub(crate) mod verifier;

pub use msm::MSM;
pub use params::{IpaCycle, Params};
pub use proof::IpaProof;
pub use prover::create_proof;
pub use transcript::{CycleTranscript, HostSide, IpaTranscript, NestedSide};
pub use verifier::{Accumulator, Guard, verify_proof};

/// Domain separation tag for the compression, whose transcript runs from
/// the instance through the reductions to the IPAs, keeping it distinct from
/// the fuse's. A transcript handed to [`create_proof`] and [`verify_proof`]
/// must be created with it.
///
/// The prover and all verifier paths must agree on this tag. Changing it
/// breaks compatibility with existing proofs.
///
/// Profiles share this protocol domain. Compression opens the native and
/// nested registry restrictions against the receiving application's tagged
/// registries, preserving the fuse's setup binding.
pub const IPA_TAG: &[u8] = b"ragu-ipa-v1";

#[cfg(test)]
#[path = "../../tests/ipa.rs"]
mod tests;

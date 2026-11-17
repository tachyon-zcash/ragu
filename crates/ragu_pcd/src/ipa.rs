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
//! live in `protocol::ipa`, [`create_proof`] in `prover::ipa` and
//! [`verify_proof`] in `verifier::ipa`.

// TODO: Revisit the removal of Pedersen blinds from `S`, `L`, and `R`
// during rerandomization work, including the resulting completeness failures.

pub use crate::{
    protocol::ipa::{
        CycleTranscript, HostSide, IPA_TAG, IpaCycle, IpaProof, IpaTranscript, MSM, NestedSide,
        Params,
    },
    prover::ipa::create_proof,
    verifier::ipa::{Accumulator, Guard, verify_proof},
};

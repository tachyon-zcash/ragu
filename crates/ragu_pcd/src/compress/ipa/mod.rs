//! Unblinded inner product argument (IPA) for polynomial commitments.
//!
//! Adapted from halo2's `halo2_proofs/src/poly/commitment`, without the
//! Pedersen blinds halo2 puts on `S`, `L` and `R` with its generator `W`. An
//! opening proves knowledge of `p` with `P = <p, G>` and `p(x) = v`.
//!
//! The opening's messages show nothing of `p` beyond `P` and `v`: the random
//! masking polynomial `s` below makes the coefficients the argument folds
//! uniform. `P` itself has no blind, so the commitment is not hiding, and
//! compression, the opening's one use in this crate, does not need it to
//! be. Blinding `S`, `L` and `R` would not make a compressed proof hiding,
//! since the proof carries evaluations of the polynomials of the proof it
//! compresses outside the opening. A proof that must stay private is passed
//! through [`Application::rerandomize`](crate::Application::rerandomize) before
//! [`Application::compress`](crate::Application::compress) instead. The
//! compressed proof is computed from the rerandomized one, so it shows no
//! more of the proof that was rerandomized than the rerandomized proof does.
//! Rerandomization hides its input only under the standard profile.
//!
//! Unblinded round commitments can be the identity for valid openings, which
//! [`CycleTranscript`] rejects. Only one case is certain: with two
//! coefficients and `x = 0`, the polynomial the argument folds,
//! `p - v + ξ s`, has a zero constant coefficient, the one coefficient `R`
//! commits to. Compression opens over more than one round at a fresh
//! challenge, where a round commitment is the identity only with negligible
//! probability.
//!
//! The masking polynomial `s`, with `s(x) = 0`, is retained to mask the
//! coefficients folded by the argument. Fiat-Shamir goes through
//! [`IpaTranscript`], implemented for both curves by [`CycleTranscript`].

use alloc::{sync::Arc, vec::Vec};
use core::ops::Deref;

use ragu_core::{Cycle, FixedGenerators, PreparedMsm};
use udon::curve::Affine;

use crate::SelectableBackend;

pub(crate) mod fingerprint;
mod msm;
mod prover;
mod transcript;
mod verifier;

pub use msm::MSM;
pub use prover::create_proof;
pub(crate) use transcript::convert_challenge;
pub use transcript::{CycleTranscript, HostSide, IpaTranscript, NestedSide};
pub(crate) use verifier::challenge_polynomial;
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

/// Log-size unblinded IPA opening proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpaProof<C: Affine> {
    /// Unblinded commitment to the masking polynomial $s$ with $s(x) = 0$.
    pub s_commitment: C,
    /// Cross-term commitments $(L_j, R_j)$, one pair per round.
    pub rounds: Vec<(C, C)>,
    /// Final collapsed coefficient.
    pub c: C::Scalar,
}

/// A cycle whose parameters also fix the IPA's generator $u$ on each curve:
/// a point with no known discrete-log relation to the vector generators,
/// which the argument uses to bind the claimed value into the commitment it
/// opens.
pub trait IpaCycle: Cycle {
    /// The host curve's $u$.
    fn host_u(params: &Self::Params) -> &Self::HostCurve;
    /// The nested curve's $u$.
    fn nested_u(params: &Self::Params) -> &Self::NestedCurve;
    /// The nested curve's vector generator at `index`: the parameters' own
    /// where their table reaches, and past it one of the generators baked
    /// for the runs of the compression's transcript, which it commits at
    /// the degrees their stages take in a proof's decompression at the
    /// aggregator rank (see [`CycleTranscript`]); `None` past both. The
    /// baked tables reach every run, so the second case is for a table
    /// shorter than theirs.
    fn nested_generator(params: &Self::Params, index: usize) -> Option<Self::NestedCurve>;
}

/// The vector generators and the generator $U$ that binds the inner
/// product value. Commitments have no separate blinding generator.
#[derive(Clone, Debug)]
pub struct Params<C: Affine> {
    pub(crate) k: u32,
    pub(crate) n: u64,
    pub(crate) g: Generators<C>,
    pub(crate) u: C,
}

#[derive(Clone, Debug)]
pub(crate) enum Generators<C: Affine> {
    Owned(Vec<C>),
    Prepared(Arc<PreparedMsm<C>>),
}

impl<C: Affine> Generators<C> {
    fn prepared(&self) -> Option<&PreparedMsm<C>> {
        match self {
            Self::Owned(_) => None,
            Self::Prepared(bases) => Some(bases),
        }
    }
}

impl<C: Affine> Deref for Generators<C> {
    type Target = [C];

    fn deref(&self) -> &[C] {
        match self {
            Self::Owned(bases) => bases,
            Self::Prepared(bases) => bases.bases(),
        }
    }
}

impl<C: Affine> Params<C> {
    /// Bundles every vector generator of `generators` into parameters.
    ///
    /// # Panics
    ///
    /// Panics if the generator count is not a power of two.
    pub fn new<G: FixedGenerators<C>>(generators: &G, u: C) -> Self {
        let n = generators.g().len();
        assert!(
            n.is_power_of_two(),
            "generator count must be a power of two"
        );
        Self::with_k(generators, u, n.ilog2())
    }

    /// Bundles the first $2^k$ vector generators of `generators` into
    /// parameters, for polynomials of at most that many coefficients.
    ///
    /// # Panics
    ///
    /// Panics if `generators` holds fewer than $2^k$ vector generators.
    pub fn with_k<G: FixedGenerators<C>>(generators: &G, u: C, k: u32) -> Self {
        let n = 1usize << k;
        assert!(
            generators.g().len() >= n,
            "not enough generators for k = {k}"
        );
        Params {
            k,
            n: n as u64,
            g: Generators::Owned(generators.g()[..n].to_vec()),
            u,
        }
    }

    pub(crate) fn for_verifier<G: FixedGenerators<C>>(
        generators: &G,
        u: C,
        k: u32,
        prepared: Option<&Arc<PreparedMsm<C>>>,
    ) -> Self {
        prepared.map_or_else(
            || Self::with_k(generators, u, k),
            |prepared| Self::with_prepared(Arc::clone(prepared), u, k),
        )
    }

    pub(crate) fn with_prepared(generators: Arc<PreparedMsm<C>>, u: C, k: u32) -> Self {
        let n = 1usize << k;
        assert_eq!(
            generators.bases().len(),
            n,
            "prepared generators match the IPA rank"
        );
        Self {
            k,
            n: n as u64,
            g: Generators::Prepared(generators),
            u,
        }
    }

    /// Commits to the polynomial with coefficients `poly` as $\langle p,G\rangle$.
    /// Uses the selected backend `B` to evaluate the commitment.
    ///
    /// # Panics
    ///
    /// Panics if `poly` does not have exactly $2^k$ coefficients.
    pub fn commit<B: SelectableBackend>(&self, poly: &[C::Scalar]) -> C::Projective {
        assert_eq!(poly.len(), self.n as usize);
        msm::multiexp::<C, B>(poly, &self.g)
    }
}

#[cfg(test)]
#[path = "../../../tests/ipa.rs"]
mod tests;

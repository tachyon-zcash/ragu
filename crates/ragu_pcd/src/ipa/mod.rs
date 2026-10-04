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

use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_backend::ReferenceBackend;
use ragu_core::{Cycle, FixedGenerators};
use udon::curve::Affine;

use crate::SelectableBackend;

mod msm;
mod prover;
mod transcript;
mod verifier;

pub use msm::MSM;
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
}

/// The vector generators and the generator $U$ that binds the inner
/// product value. Commitments have no separate blinding generator.
/// The backend `B` evaluates commitments and the IPA's MSMs.
#[derive(Clone, Debug)]
pub struct Params<C: Affine, B: SelectableBackend = ReferenceBackend> {
    pub(crate) k: u32,
    pub(crate) n: u64,
    pub(crate) g: Vec<C>,
    pub(crate) u: C,
    backend: PhantomData<B>,
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
            g: generators.g()[..n].to_vec(),
            u,
            backend: PhantomData,
        }
    }
}

impl<C: Affine, B: SelectableBackend> Params<C, B> {
    /// Selects the backend used for commitments, proving, and verification
    /// with these parameters. The generators are unchanged.
    /// Only Ragu-owned backends may be selected through [`SelectableBackend`].
    ///
    /// ```compile_fail,E0277
    /// use ragu_backend::Backend;
    /// use ragu_pcd::ipa::Params;
    /// use udon::curve::Affine;
    ///
    /// #[derive(Clone, Copy, Debug, Default)]
    /// struct CustomBackend;
    /// impl Backend for CustomBackend {}
    ///
    /// fn select<C: Affine>(params: Params<C>) {
    ///     let _ = params.with_backend::<CustomBackend>();
    /// }
    /// ```
    pub fn with_backend<NewB: SelectableBackend>(self) -> Params<C, NewB> {
        Params {
            k: self.k,
            n: self.n,
            g: self.g,
            u: self.u,
            backend: PhantomData,
        }
    }

    /// Commits to the polynomial with coefficients `poly` as $\langle p,G\rangle$.
    ///
    /// # Panics
    ///
    /// Panics if `poly` does not have exactly $2^k$ coefficients.
    pub fn commit(&self, poly: &[C::Scalar]) -> C::Projective {
        assert_eq!(poly.len(), self.n as usize);
        msm::multiexp::<C, B>(poly, &self.g)
    }
}

#[cfg(test)]
#[path = "../../tests/ipa.rs"]
mod tests;

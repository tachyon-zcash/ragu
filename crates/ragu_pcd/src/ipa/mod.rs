//! Inner product argument (IPA) for polynomial commitments.
//!
//! Adapted from halo2's `halo2_proofs/src/poly/commitment`: the prover and
//! verifier keep the original structure, and the batch verifier is not
//! ported. Fiat-Shamir goes through the [`IpaTranscript`] trait, which the
//! fuse's transcript implements for both curves as [`CycleTranscript`].

use alloc::vec::Vec;

use ragu_arithmetic::{CurveAffine, FixedGenerators, ff::Field, msm};

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

/// Log-size IPA opening proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpaProof<C: CurveAffine> {
    /// Commitment to the blinding polynomial $S$.
    pub s_commitment: C,
    /// Cross-term commitments $(L_j, R_j)$, one pair per round.
    pub rounds: Vec<(C, C)>,
    /// Final collapsed coefficient.
    pub c: C::ScalarExt,
    /// Synthetic blinding factor.
    pub f: C::ScalarExt,
}

/// The public parameters of the polynomial commitment scheme, mirroring
/// halo2's `Params<C>`: the vector generators, the blinding generator $W$ and
/// the generator $U$ that binds the inner product value.
#[derive(Clone, Debug)]
pub struct Params<C: CurveAffine> {
    pub(crate) k: u32,
    pub(crate) n: u64,
    pub(crate) g: Vec<C>,
    pub(crate) w: C,
    pub(crate) u: C,
}

impl<C: CurveAffine> Params<C> {
    /// Bundles every vector generator of `generators` into parameters.
    ///
    /// # Panics
    ///
    /// Panics if the generator count is not a power of two.
    pub fn new<G: FixedGenerators<C>>(generators: &G) -> Self {
        let n = generators.g().len();
        assert!(
            n.is_power_of_two(),
            "generator count must be a power of two"
        );
        Self::with_k(generators, n.ilog2())
    }

    /// Bundles the first $2^k$ vector generators of `generators` into
    /// parameters, for polynomials of at most that many coefficients.
    ///
    /// # Panics
    ///
    /// Panics if `generators` holds fewer than $2^k$ vector generators.
    pub fn with_k<G: FixedGenerators<C>>(generators: &G, k: u32) -> Self {
        let n = 1usize << k;
        assert!(
            generators.g().len() >= n,
            "not enough generators for k = {k}"
        );
        Params {
            k,
            n: n as u64,
            g: generators.g()[..n].to_vec(),
            w: *generators.h(),
            u: *generators.u(),
        }
    }

    /// Commits to the polynomial with coefficients `poly` under the blinding
    /// factor `r`.
    ///
    /// # Panics
    ///
    /// Panics if `poly` does not have exactly $2^k$ coefficients.
    pub fn commit(&self, poly: &[C::Scalar], r: Blind<C::Scalar>) -> C::Curve {
        assert_eq!(poly.len(), self.n as usize);

        let mut tmp_scalars = Vec::with_capacity(poly.len() + 1);
        let mut tmp_bases = Vec::with_capacity(poly.len() + 1);

        tmp_scalars.extend(poly.iter());
        tmp_scalars.push(r.0);

        tmp_bases.extend(self.g.iter());
        tmp_bases.push(self.w);

        msm::<C, _, _>(&tmp_scalars, &tmp_bases)
    }
}

/// Wrapper type around a blinding factor, distinguishing it from other
/// scalars at the type level. Mirrors halo2's `Blind<F>`.
#[derive(Copy, Clone, Debug)]
pub struct Blind<F>(pub F);

impl<F: Field> Default for Blind<F> {
    fn default() -> Self {
        Blind(F::ONE)
    }
}

impl<F: Field> core::ops::Add for Blind<F> {
    type Output = Self;

    fn add(self, rhs: Blind<F>) -> Self {
        Blind(self.0 + rhs.0)
    }
}

impl<F: Field> core::ops::Mul for Blind<F> {
    type Output = Self;

    fn mul(self, rhs: Blind<F>) -> Self {
        Blind(self.0 * rhs.0)
    }
}

impl<F: Field> core::ops::AddAssign for Blind<F> {
    fn add_assign(&mut self, rhs: Blind<F>) {
        self.0 += rhs.0;
    }
}

impl<F: Field> core::ops::MulAssign for Blind<F> {
    fn mul_assign(&mut self, rhs: Blind<F>) {
        self.0 *= rhs.0;
    }
}

impl<F: Field> core::ops::AddAssign<F> for Blind<F> {
    fn add_assign(&mut self, rhs: F) {
        self.0 += rhs;
    }
}

impl<F: Field> core::ops::MulAssign<F> for Blind<F> {
    fn mul_assign(&mut self, rhs: F) {
        self.0 *= rhs;
    }
}

#[cfg(test)]
#[path = "../../tests/ipa.rs"]
mod tests;

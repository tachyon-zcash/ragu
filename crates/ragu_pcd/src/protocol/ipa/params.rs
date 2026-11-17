//! IPA parameters and cycle requirements.
use alloc::vec::Vec;

use ragu_core::{Cycle, FixedGenerators};
use udon::curve::Affine;

use crate::{SelectableBackend, protocol::ipa::msm};
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
#[derive(Clone, Debug)]
pub struct Params<C: Affine> {
    pub(crate) k: u32,
    pub(crate) n: u64,
    pub(crate) g: Vec<C>,
    pub(crate) u: C,
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

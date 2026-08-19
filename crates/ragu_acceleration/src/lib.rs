//! # `ragu_acceleration`
//!
//! Optimized implementations of Ragu's computational backend.

#![no_std]
#![deny(missing_docs)]

#[cfg(feature = "native-msm")]
extern crate alloc;

#[cfg(feature = "native-msm")]
mod msm;

/// Ragu's accelerated computational backend.
///
/// With the `native-msm` feature, MSMs use Zakura's signed-Booth multiexp
/// (from `zakura-halo2-proofs`, over the same `zakura-pasta-curves` types Ragu
/// itself uses). Without it, the correctness-first implementation is retained.
#[derive(Clone, Copy, Debug, Default)]
pub struct AcceleratedBackend;

impl ragu_backend::Backend for AcceleratedBackend {
    fn msm<
        'a,
        C: ragu_arithmetic::CurveAffine,
        A: IntoIterator<Item = &'a C::Scalar>,
        Bases: IntoIterator<Item = &'a C>,
    >(
        coeffs: A,
        bases: Bases,
    ) -> C::Curve
    where
        Bases::IntoIter: Clone + Sync,
    {
        #[cfg(feature = "native-msm")]
        {
            let coeffs: alloc::vec::Vec<_> = coeffs.into_iter().copied().collect();
            let bases: alloc::vec::Vec<_> = bases.into_iter().copied().collect();
            msm::accelerated_msm(&coeffs, &bases)
        }

        #[cfg(not(feature = "native-msm"))]
        {
            ragu_arithmetic::msm(coeffs, bases)
        }
    }
}

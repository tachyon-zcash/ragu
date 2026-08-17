//! # `ragu_acceleration`
//!
//! Optimized implementations of Ragu's computational backend.

#![no_std]
#![deny(missing_docs)]

/// Ragu's accelerated computational backend.
///
/// It currently inherits every correctness-first default from
/// [`ragu_backend::Backend`]. Optimized overrides will be added individually
/// alongside reference-equivalence tests.
#[derive(Clone, Copy, Debug, Default)]
pub struct AcceleratedBackend;

impl ragu_backend::Backend for AcceleratedBackend {}

#[cfg(test)]
mod tests {
    extern crate std;

    use ragu_arithmetic::{
        group::{Curve, Group},
        pasta_curves::pallas,
    };
    use ragu_backend::{Backend, ReferenceBackend};
    use std::vec::Vec;

    use super::AcceleratedBackend;

    #[test]
    fn accelerated_msm_matches_reference_across_sizes() {
        for size in [0, 1, 2, 3, 15, 16, 17, 31, 32, 33, 255] {
            let generator = pallas::Point::generator();
            let scalars: Vec<_> = (0..size)
                .map(|i| pallas::Scalar::from((i as u64 + 1).pow(2)))
                .collect();
            let bases: Vec<_> = (0..size)
                .map(|i| (generator * pallas::Scalar::from(3 * i as u64 + 1)).to_affine())
                .collect();

            let reference = ReferenceBackend::msm(scalars.iter(), bases.iter());
            let accelerated = AcceleratedBackend::msm(scalars.iter(), bases.iter());

            assert_eq!(accelerated, reference, "MSM mismatch at size {size}");
        }
    }
}

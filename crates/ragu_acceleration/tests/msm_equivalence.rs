use ragu_acceleration::AcceleratedBackend;
use ragu_arithmetic::{
    group::{Curve, Group},
    pasta_curves::pallas,
};
use ragu_backend::{Backend, ReferenceBackend};

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

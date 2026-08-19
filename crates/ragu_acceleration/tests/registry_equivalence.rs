use proptest::prelude::*;
use ragu_acceleration::AcceleratedBackend;
use ragu_arithmetic::pasta_curves::pallas;
use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::{
    polynomials::{TestRank, sparse::Polynomial},
    registry::{CircuitIndex, RegistryBuilder},
};
use ragu_testing::{circuits::SquareCircuit, strategies::prime_field_element};

fn coeffs(poly: Polynomial<pallas::Scalar, TestRank>) -> Vec<pallas::Scalar> {
    poly.iter_coeffs().collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn accelerated_registry_operations_match_reference_and_canonical(
        w in prime_field_element(),
        x in prime_field_element(),
        y in prime_field_element(),
        circuit_index in 0usize..8,
    ) {
        let registry = RegistryBuilder::<pallas::Scalar, TestRank>::new()
            .register_circuit(SquareCircuit { times: 1 })
            .unwrap()
            .register_circuit(SquareCircuit { times: 2 })
            .unwrap()
            .register_circuit(SquareCircuit { times: 3 })
            .unwrap()
            .finalize()
            .unwrap();
        let registry_at = registry.at(w);
        let circuit = CircuitIndex::new(circuit_index);

        let accelerated_xy = coeffs(AcceleratedBackend::registry_xy(&registry, x, y));
        let reference_xy = coeffs(ReferenceBackend::registry_xy(&registry, x, y));
        let canonical_xy = coeffs(registry.xy(x, y));
        prop_assert_eq!(accelerated_xy.as_slice(), reference_xy.as_slice());
        prop_assert_eq!(reference_xy.as_slice(), canonical_xy.as_slice());

        let accelerated_circuit_y = coeffs(AcceleratedBackend::registry_circuit_y(
            &registry, circuit, y,
        ));
        let reference_circuit_y = coeffs(ReferenceBackend::registry_circuit_y(
            &registry, circuit, y,
        ));
        let canonical_circuit_y = coeffs(registry.circuit_y(circuit, y));
        prop_assert_eq!(
            accelerated_circuit_y.as_slice(),
            reference_circuit_y.as_slice(),
        );
        prop_assert_eq!(
            reference_circuit_y.as_slice(),
            canonical_circuit_y.as_slice(),
        );

        let accelerated_at_x = coeffs(AcceleratedBackend::registry_at_x(&registry_at, x));
        let reference_at_x = coeffs(ReferenceBackend::registry_at_x(&registry_at, x));
        let canonical_at_x = coeffs(registry_at.x(x));
        prop_assert_eq!(accelerated_at_x.as_slice(), reference_at_x.as_slice());
        prop_assert_eq!(reference_at_x.as_slice(), canonical_at_x.as_slice());

        let accelerated_at_y = coeffs(AcceleratedBackend::registry_at_y(&registry_at, y));
        let reference_at_y = coeffs(ReferenceBackend::registry_at_y(&registry_at, y));
        let canonical_at_y = coeffs(registry_at.y(y));
        prop_assert_eq!(accelerated_at_y.as_slice(), reference_at_y.as_slice());
        prop_assert_eq!(reference_at_y.as_slice(), canonical_at_y.as_slice());

        let accelerated_wxy = AcceleratedBackend::registry_wxy(&registry, w, x, y);
        let reference_wxy = ReferenceBackend::registry_wxy(&registry, w, x, y);
        let canonical_wxy = registry.wxy(w, x, y);
        prop_assert_eq!(accelerated_wxy, reference_wxy);
        prop_assert_eq!(reference_wxy, canonical_wxy);
    }
}

use proptest::prelude::*;
use proptest::test_runner::TestCaseResult;
use ragu_acceleration::AcceleratedBackend;
use ragu_arithmetic::{
    ff::{FromUniformBytes, PrimeField},
    pasta_curves::{pallas, vesta},
};
use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::{
    polynomials::{TestRank, sparse::Polynomial},
    registry::{CircuitIndex, RegistryBuilder},
};
use ragu_testing::{circuits::SquareCircuit, strategies::prime_field_element};

fn coeffs<F: PrimeField>(poly: Polynomial<F, TestRank>) -> Vec<F> {
    poly.iter_coeffs().collect()
}

fn arb_registry_shape() -> impl Strategy<Value = (Vec<usize>, usize)> {
    proptest::collection::vec(0usize..=8, 1..=4).prop_flat_map(|circuit_times| {
        let num_circuits = circuit_times.len();
        (Just(circuit_times), 0..num_circuits)
    })
}

fn check_registry_operations<F>(
    w: F,
    x: F,
    y: F,
    circuit_times: Vec<usize>,
    circuit_index: usize,
) -> TestCaseResult
where
    F: PrimeField + FromUniformBytes<64> + From<u64>,
{
    let mut builder = RegistryBuilder::<F, TestRank>::new();
    for times in circuit_times {
        builder = builder.register_circuit(SquareCircuit { times }).unwrap();
    }
    let registry = builder.finalize().unwrap();
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
    let reference_circuit_y = coeffs(ReferenceBackend::registry_circuit_y(&registry, circuit, y));
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

    let accelerated_wx_at_y =
        AcceleratedBackend::sparse_eval(&AcceleratedBackend::registry_at_x(&registry_at, x), y);
    let accelerated_wy_at_x =
        AcceleratedBackend::sparse_eval(&AcceleratedBackend::registry_at_y(&registry_at, y), x);
    let reference_wx_at_y =
        ReferenceBackend::sparse_eval(&ReferenceBackend::registry_at_x(&registry_at, x), y);
    let reference_wy_at_x =
        ReferenceBackend::sparse_eval(&ReferenceBackend::registry_at_y(&registry_at, y), x);
    prop_assert_eq!(accelerated_wx_at_y, canonical_wxy);
    prop_assert_eq!(accelerated_wy_at_x, canonical_wxy);
    prop_assert_eq!(reference_wx_at_y, canonical_wxy);
    prop_assert_eq!(reference_wy_at_x, canonical_wxy);

    let circuit_w = circuit.omega_j::<F>();
    let canonical_sxy = registry.wxy(circuit_w, x, y);
    let registry_at_circuit = registry.at(circuit_w);
    let accelerated_s_x_y = AcceleratedBackend::sparse_eval(
        &AcceleratedBackend::registry_at_x(&registry_at_circuit, x),
        y,
    );
    let accelerated_s_y_x = AcceleratedBackend::sparse_eval(
        &AcceleratedBackend::registry_circuit_y(&registry, circuit, y),
        x,
    );
    let accelerated_s_xy_w = AcceleratedBackend::sparse_eval(
        &AcceleratedBackend::registry_xy(&registry, x, y),
        circuit_w,
    );
    let reference_s_x_y =
        ReferenceBackend::sparse_eval(&ReferenceBackend::registry_at_x(&registry_at_circuit, x), y);
    let reference_s_y_x = ReferenceBackend::sparse_eval(
        &ReferenceBackend::registry_circuit_y(&registry, circuit, y),
        x,
    );
    let reference_s_xy_w =
        ReferenceBackend::sparse_eval(&ReferenceBackend::registry_xy(&registry, x, y), circuit_w);
    prop_assert_eq!(accelerated_s_x_y, canonical_sxy);
    prop_assert_eq!(accelerated_s_y_x, canonical_sxy);
    prop_assert_eq!(accelerated_s_xy_w, canonical_sxy);
    prop_assert_eq!(reference_s_x_y, canonical_sxy);
    prop_assert_eq!(reference_s_y_x, canonical_sxy);
    prop_assert_eq!(reference_s_xy_w, canonical_sxy);

    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn accelerated_pallas_registry_operations_match_reference_and_canonical(
        w in prime_field_element::<pallas::Scalar>(),
        x in prime_field_element::<pallas::Scalar>(),
        y in prime_field_element::<pallas::Scalar>(),
        (circuit_times, circuit_index) in arb_registry_shape(),
    ) {
        check_registry_operations(w, x, y, circuit_times, circuit_index)?;
    }

    #[test]
    fn accelerated_vesta_registry_operations_match_reference_and_canonical(
        w in prime_field_element::<vesta::Scalar>(),
        x in prime_field_element::<vesta::Scalar>(),
        y in prime_field_element::<vesta::Scalar>(),
        (circuit_times, circuit_index) in arb_registry_shape(),
    ) {
        check_registry_operations(w, x, y, circuit_times, circuit_index)?;
    }
}

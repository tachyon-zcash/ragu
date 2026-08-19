use proptest::prelude::*;
use proptest::test_runner::TestCaseResult;
use ragu_acceleration::AcceleratedBackend;
use ragu_arithmetic::{
    CurveAffine, Cycle, FixedGenerators,
    ff::{FromUniformBytes, PrimeField},
    group::Curve,
    pasta_curves::{pallas, vesta},
};
use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::{
    polynomials::{TestRank, sparse::Polynomial},
    registry::{CircuitIndex, RegistryBuilder},
};
use ragu_pasta::Pasta;
use ragu_testing::{circuits::SquareCircuit, strategies::prime_field_element};

fn coeffs<F: PrimeField>(poly: &Polynomial<F, TestRank>) -> Vec<F> {
    poly.iter_coeffs().collect()
}

fn check_structured_commitment<F, C, G>(
    canonical: &Polynomial<F, TestRank>,
    reference: &Polynomial<F, TestRank>,
    accelerated: &Polynomial<F, TestRank>,
    generators: &G,
) -> TestCaseResult
where
    F: PrimeField,
    C: CurveAffine<ScalarExt = F>,
    G: FixedGenerators<C>,
{
    let canonical_commitment = canonical.commit(generators);
    prop_assert_eq!(
        ReferenceBackend::sparse_commit(reference, generators),
        canonical_commitment,
    );
    prop_assert_eq!(
        AcceleratedBackend::sparse_commit(accelerated, generators),
        canonical_commitment,
    );
    prop_assert_eq!(
        ReferenceBackend::sparse_commit_to_affine(reference, generators),
        canonical_commitment.to_affine(),
    );
    prop_assert_eq!(
        AcceleratedBackend::sparse_commit_to_affine(accelerated, generators),
        canonical_commitment.to_affine(),
    );

    Ok(())
}

fn arb_registry_shape() -> impl Strategy<Value = (Vec<usize>, usize)> {
    proptest::collection::vec(0usize..=8, 1..=4).prop_flat_map(|circuit_times| {
        let num_circuits = circuit_times.len();
        (Just(circuit_times), 0..num_circuits)
    })
}

fn check_registry_operations<F, C, G>(
    w: F,
    x: F,
    y: F,
    circuit_times: Vec<usize>,
    circuit_index: usize,
    generators: &G,
) -> TestCaseResult
where
    F: PrimeField + FromUniformBytes<64> + From<u64>,
    C: CurveAffine<ScalarExt = F>,
    G: FixedGenerators<C>,
{
    let mut builder = RegistryBuilder::<F, TestRank>::new();
    for times in circuit_times {
        builder = builder.register_circuit(SquareCircuit { times }).unwrap();
    }
    let registry = builder.finalize().unwrap();
    let registry_at = registry.at(w);
    let circuit = CircuitIndex::new(circuit_index);

    let accelerated_xy = AcceleratedBackend::registry_xy(&registry, x, y);
    let reference_xy = ReferenceBackend::registry_xy(&registry, x, y);
    let canonical_xy = registry.xy(x, y);
    prop_assert_eq!(coeffs(&accelerated_xy), coeffs(&reference_xy));
    prop_assert_eq!(coeffs(&reference_xy), coeffs(&canonical_xy));
    check_structured_commitment::<_, C, _>(
        &canonical_xy,
        &reference_xy,
        &accelerated_xy,
        generators,
    )?;

    let accelerated_circuit_y = AcceleratedBackend::registry_circuit_y(&registry, circuit, y);
    let reference_circuit_y = ReferenceBackend::registry_circuit_y(&registry, circuit, y);
    let canonical_circuit_y = registry.circuit_y(circuit, y);
    prop_assert_eq!(coeffs(&accelerated_circuit_y), coeffs(&reference_circuit_y),);
    prop_assert_eq!(coeffs(&reference_circuit_y), coeffs(&canonical_circuit_y),);
    check_structured_commitment::<_, C, _>(
        &canonical_circuit_y,
        &reference_circuit_y,
        &accelerated_circuit_y,
        generators,
    )?;

    let accelerated_at_x = AcceleratedBackend::registry_at_x(&registry_at, x);
    let reference_at_x = ReferenceBackend::registry_at_x(&registry_at, x);
    let canonical_at_x = registry_at.x(x);
    prop_assert_eq!(coeffs(&accelerated_at_x), coeffs(&reference_at_x));
    prop_assert_eq!(coeffs(&reference_at_x), coeffs(&canonical_at_x));
    check_structured_commitment::<_, C, _>(
        &canonical_at_x,
        &reference_at_x,
        &accelerated_at_x,
        generators,
    )?;

    let accelerated_at_y = AcceleratedBackend::registry_at_y(&registry_at, y);
    let reference_at_y = ReferenceBackend::registry_at_y(&registry_at, y);
    let canonical_at_y = registry_at.y(y);
    prop_assert_eq!(coeffs(&accelerated_at_y), coeffs(&reference_at_y));
    prop_assert_eq!(coeffs(&reference_at_y), coeffs(&canonical_at_y));
    check_structured_commitment::<_, C, _>(
        &canonical_at_y,
        &reference_at_y,
        &accelerated_at_y,
        generators,
    )?;

    let accelerated_wxy = AcceleratedBackend::registry_wxy(&registry, w, x, y);
    let reference_wxy = ReferenceBackend::registry_wxy(&registry, w, x, y);
    let canonical_wxy = registry.wxy(w, x, y);
    prop_assert_eq!(accelerated_wxy, reference_wxy);
    prop_assert_eq!(reference_wxy, canonical_wxy);

    let accelerated_wx_at_y = AcceleratedBackend::sparse_eval(&accelerated_at_x, y);
    let accelerated_wy_at_x = AcceleratedBackend::sparse_eval(&accelerated_at_y, x);
    let reference_wx_at_y = ReferenceBackend::sparse_eval(&reference_at_x, y);
    let reference_wy_at_x = ReferenceBackend::sparse_eval(&reference_at_y, x);
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
    let accelerated_s_y_x = AcceleratedBackend::sparse_eval(&accelerated_circuit_y, x);
    let accelerated_s_xy_w = AcceleratedBackend::sparse_eval(&accelerated_xy, circuit_w);
    let reference_s_x_y =
        ReferenceBackend::sparse_eval(&ReferenceBackend::registry_at_x(&registry_at_circuit, x), y);
    let reference_s_y_x = ReferenceBackend::sparse_eval(&reference_circuit_y, x);
    let reference_s_xy_w = ReferenceBackend::sparse_eval(&reference_xy, circuit_w);
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
        check_registry_operations::<_, pallas::Affine, _>(
            w,
            x,
            y,
            circuit_times,
            circuit_index,
            Pasta::nested_generators(Pasta::baked()),
        )?;
    }

    #[test]
    fn accelerated_vesta_registry_operations_match_reference_and_canonical(
        w in prime_field_element::<vesta::Scalar>(),
        x in prime_field_element::<vesta::Scalar>(),
        y in prime_field_element::<vesta::Scalar>(),
        (circuit_times, circuit_index) in arb_registry_shape(),
    ) {
        check_registry_operations::<_, vesta::Affine, _>(
            w,
            x,
            y,
            circuit_times,
            circuit_index,
            Pasta::host_generators(Pasta::baked()),
        )?;
    }
}

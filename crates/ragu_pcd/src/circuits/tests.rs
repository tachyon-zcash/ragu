use super::*;
use crate::*;
use native::{
    InternalCircuitIndex,
    stages::{error_m, error_n, eval, preamble, query},
};
use ragu_circuits::staging::{Stage, StageExt};
use ragu_pasta::{Pasta, fp, fq};

pub(crate) type R = ragu_circuits::polynomials::R<13>;

// When changing HEADER_SIZE, update the constraint counts by running:
//   cargo test -p ragu_pcd --release print_internal_circuit -- --nocapture
// Then copy-paste the output into the check_constraints! calls in the test below.
pub(crate) const HEADER_SIZE: usize = 65;

// Number of dummy application circuits to register before testing internal
// circuits. This ensures the tests work correctly even when application
// steps are present.
const NUM_APP_STEPS: usize = 6000;

type Preamble = preamble::Stage<Pasta, R, HEADER_SIZE>;
type ErrorN = error_n::Stage<Pasta, R, HEADER_SIZE, NativeParameters>;
type ErrorM = error_m::Stage<Pasta, R, HEADER_SIZE, NativeParameters>;
type Query = query::Stage<Pasta, R, HEADER_SIZE>;
type Eval = eval::Stage<Pasta, R, HEADER_SIZE>;

#[rustfmt::skip]
#[test]
fn test_internal_circuit_constraint_counts() {
    let pasta = Pasta::baked();

    let app = ApplicationBuilder::<Pasta, R, HEADER_SIZE>::new()
        .register_dummy_circuits(NUM_APP_STEPS)
        .unwrap()
        .finalize(pasta)
        .unwrap();

    let circuits = app.native_registry.circuits();

    macro_rules! check_constraints {
        ($variant:ident, mul = $mul:expr, lin = $lin:expr) => {{
            let idx: usize = InternalCircuitIndex::$variant.circuit_index().into();
            let circuit = &circuits[idx];
            let (actual_mul, actual_lin) = circuit.constraint_counts();
            assert_eq!(
                actual_mul,
                $mul,
                "{}: multiplication constraints: expected {}, got {}",
                stringify!($variant),
                $mul,
                actual_mul
            );
            assert_eq!(
                actual_lin,
                $lin,
                "{}: linear constraints: expected {}, got {}",
                stringify!($variant),
                $lin,
                actual_lin
            );
        }};
    }

    check_constraints!(Hashes1Circuit,         mul = 2045, lin = 3423);
    check_constraints!(Hashes2Circuit,         mul = 1879, lin = 2952);
    check_constraints!(PartialCollapseCircuit, mul = 1756, lin = 1919);
    check_constraints!(FullCollapseCircuit,    mul = 811 , lin = 809);
    check_constraints!(ComputeVCircuit,        mul = 1195, lin = 1862);
}

#[rustfmt::skip]
#[test]
fn test_internal_stage_parameters() {
    macro_rules! check_stage {
        ($Stage:ty, skip = $skip:expr, num = $num:expr) => {{
            assert_eq!(<$Stage>::skip_multiplications(), $skip, "{}: skip", stringify!($Stage));
            assert_eq!(<$Stage as StageExt<_, _>>::num_multiplications(), $num, "{}: num", stringify!($Stage));
        }};
    }

    check_stage!(Preamble, skip =   0, num = 225);
    check_stage!(ErrorN,  skip = 225, num = 186);
    check_stage!(ErrorM,  skip = 411, num = 399);
    check_stage!(Query,   skip = 225, num =  34);
    check_stage!(Eval,    skip = 259, num =  18);
}

/// Helper test to print current constraint counts in copy-pasteable format.
/// Run with: `cargo test -p ragu_pcd --release print_internal_circuit -- --nocapture`
#[test]
fn print_internal_circuit_constraint_counts() {
    let pasta = Pasta::baked();

    let app = ApplicationBuilder::<Pasta, R, HEADER_SIZE>::new()
        .register_dummy_circuits(NUM_APP_STEPS)
        .unwrap()
        .finalize(pasta)
        .unwrap();

    let circuits = app.native_registry.circuits();

    let variants = [
        ("Hashes1Circuit", InternalCircuitIndex::Hashes1Circuit),
        ("Hashes2Circuit", InternalCircuitIndex::Hashes2Circuit),
        (
            "PartialCollapseCircuit",
            InternalCircuitIndex::PartialCollapseCircuit,
        ),
        (
            "FullCollapseCircuit",
            InternalCircuitIndex::FullCollapseCircuit,
        ),
        ("ComputeVCircuit", InternalCircuitIndex::ComputeVCircuit),
    ];

    println!("\n// Copy-paste the following into test_internal_circuit_constraint_counts:");
    for (name, variant) in variants {
        let idx: usize = variant.circuit_index().into();
        let circuit = &circuits[idx];
        let (mul, lin) = circuit.constraint_counts();
        println!(
            "        check_constraints!({:<24} mul = {:<4}, lin = {});",
            format!("{},", name),
            mul,
            lin
        );
    }
}

/// Helper test to print current stage parameters in copy-pasteable format.
/// Run with: `cargo test -p ragu_pcd --release print_internal_stage -- --nocapture`
#[test]
fn print_internal_stage_parameters() {
    macro_rules! print_stage {
        ($Stage:ty) => {{
            let skip = <$Stage>::skip_multiplications();
            let num = <$Stage as StageExt<_, _>>::num_multiplications();
            println!(
                "        check_stage!({:<8} skip = {:>3}, num = {:>3});",
                format!("{},", stringify!($Stage)),
                skip,
                num
            );
        }};
    }

    println!("\n// Copy-paste the following into test_internal_stage_parameters:");
    print_stage!(Preamble);
    print_stage!(ErrorN);
    print_stage!(ErrorM);
    print_stage!(Query);
    print_stage!(Eval);
}

/// Test that the native registry digest hasn't changed unexpectedly.
///
/// This test verifies that gadget refactorings don't accidentally change the
/// underlying wiring polynomial. If a refactoring produces the same digest,
/// then it's mathematically equivalent.
#[test]
fn test_native_registry_digest() {
    let pasta = Pasta::baked();

    let app = ApplicationBuilder::<Pasta, R, HEADER_SIZE>::new()
        .register_dummy_circuits(NUM_APP_STEPS)
        .unwrap()
        .finalize(pasta)
        .unwrap();

    let expected = fp!(0x243cf33204aca781b6897e3cdc309363c93fa2e2611cd2fab7b58bf846d5d389);

    assert_eq!(
        app.native_registry.key().value(),
        expected,
        "Native registry digest changed unexpectedly!"
    );
}

/// Test that the nested registry digest hasn't changed unexpectedly.
///
/// This test verifies that gadget refactorings don't accidentally change the
/// underlying wiring polynomial. If a refactoring produces the same digest,
/// then it's mathematically equivalent.
#[test]
fn test_nested_registry_digest() {
    let pasta = Pasta::baked();

    let app = ApplicationBuilder::<Pasta, R, HEADER_SIZE>::new()
        .register_dummy_circuits(NUM_APP_STEPS)
        .unwrap()
        .finalize(pasta)
        .unwrap();

    let expected = fq!(0x0a8eeda61431380b0121a2a396891b6441a8314d1ceb4c59b595a369933d3403);

    assert_eq!(
        app.nested_registry.key().value(),
        expected,
        "Nested registry digest changed unexpectedly!"
    );
}

/// Helper test to print current registry digests in copy-pasteable format.
/// Run with: `cargo test -p ragu_pcd --release print_registry_digests -- --nocapture`
#[test]
fn print_registry_digests() {
    use ff::PrimeField;

    let pasta = Pasta::baked();

    let app = ApplicationBuilder::<Pasta, R, HEADER_SIZE>::new()
        .register_dummy_circuits(NUM_APP_STEPS)
        .unwrap()
        .finalize(pasta)
        .unwrap();

    let native_digest = app.native_registry.key();
    let nested_digest = app.nested_registry.key();

    // Convert to big-endian hex for repr256! format
    let native_bytes: Vec<u8> = native_digest
        .value()
        .to_repr()
        .as_ref()
        .iter()
        .rev()
        .cloned()
        .collect();
    let nested_bytes: Vec<u8> = nested_digest
        .value()
        .to_repr()
        .as_ref()
        .iter()
        .rev()
        .cloned()
        .collect();

    println!("\n// Copy-paste the following into the registry digest tests:");
    println!(
        "    let expected = fp!(0x{});",
        native_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
    println!(
        "    let expected = fq!(0x{});",
        nested_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
}

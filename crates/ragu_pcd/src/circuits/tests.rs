use super::*;
use crate::*;
use ff::Field;
use native::{
    InternalCircuitIndex,
    stages::{error_m, error_n, eval, preamble, query},
};
use ragu_arithmetic::Cycle;
use ragu_circuits::{
    polynomials::structured,
    staging::{Stage, StageExt},
};
use ragu_pasta::{Pasta, fp, fq};
use rand::{SeedableRng, rngs::StdRng};

pub(crate) type R = ragu_circuits::polynomials::ProductionRank;

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
    check_constraints!(ComputeVCircuit,        mul = 1140, lin = 1774);
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
    check_stage!(Query,   skip = 225, num =  23);
    check_stage!(Eval,    skip = 248, num =  18);
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

    let expected = fp!(0x3fa421a73ff73957cc8c40c4184c576f0e28e2cf88a4281b9f28fad818ad9726);

    assert_eq!(
        app.native_registry.digest(),
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

    let expected = fq!(0x245758c98f3c46ca03bfafe1bb50c38d0dcaed48231fd7547f40e3b208e67729);

    assert_eq!(
        app.nested_registry.digest(),
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

    let native_digest = app.native_registry.digest();
    let nested_digest = app.nested_registry.digest();

    // Convert to big-endian hex for repr256! format
    let native_bytes: Vec<u8> = native_digest
        .to_repr()
        .as_ref()
        .iter()
        .rev()
        .cloned()
        .collect();
    let nested_bytes: Vec<u8> = nested_digest
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

const BEHAVIORAL_HEADER_SIZE: usize = 4;

fn behavioral_app() -> crate::Application<'static, Pasta, R, BEHAVIORAL_HEADER_SIZE> {
    let pasta = Pasta::baked();
    ApplicationBuilder::<Pasta, R, BEHAVIORAL_HEADER_SIZE>::new()
        .finalize(pasta)
        .unwrap()
}

fn seed_behavioral_proof() -> &'static crate::Proof<Pasta, R> {
    use std::sync::OnceLock;
    static CACHED: OnceLock<crate::Proof<Pasta, R>> = OnceLock::new();
    CACHED.get_or_init(|| {
        let app = behavioral_app();
        let mut rng = StdRng::seed_from_u64(502);
        app.seed(&mut rng, step::internal::trivial::Trivial::new(), ())
            .unwrap()
            .0
    })
}

macro_rules! valid_circuit_commitment_binds {
    ($test_name:ident, $rx:ident, $blind:ident, $commitment:ident) => {
        #[test]
        fn $test_name() {
            let app = behavioral_app();
            let proof = seed_behavioral_proof();
            let gens = Pasta::host_generators(app.params);
            let c = &proof.circuits;
            assert_eq!(
                c.$rx.commit(gens, c.$blind),
                c.$commitment,
                "{} commitment mismatch",
                stringify!($rx)
            );
        }
    };
}

valid_circuit_commitment_binds!(
    seeded_hashes_1_commitment_binds,
    hashes_1_rx,
    hashes_1_blind,
    hashes_1_commitment
);
valid_circuit_commitment_binds!(
    seeded_hashes_2_commitment_binds,
    hashes_2_rx,
    hashes_2_blind,
    hashes_2_commitment
);
valid_circuit_commitment_binds!(
    seeded_partial_collapse_commitment_binds,
    partial_collapse_rx,
    partial_collapse_blind,
    partial_collapse_commitment
);
valid_circuit_commitment_binds!(
    seeded_full_collapse_commitment_binds,
    full_collapse_rx,
    full_collapse_blind,
    full_collapse_commitment
);
valid_circuit_commitment_binds!(
    seeded_compute_v_commitment_binds,
    compute_v_rx,
    compute_v_blind,
    compute_v_commitment
);

/// Baseline: a seeded proof with internal circuits passes verification.
#[test]
fn seeded_proof_with_internal_circuits_verifies() {
    let app = behavioral_app();
    let proof = seed_behavioral_proof();
    let mut rng = StdRng::seed_from_u64(502_001);
    let pcd = proof.clone().carry::<()>(());
    let result = app.verify(&pcd, &mut rng).expect("verify should not error");
    assert!(result, "seeded proof should verify");
}

macro_rules! corrupted_circuit_rx_rejects {
    ($test_name:ident, $field:ident) => {
        #[test]
        fn $test_name() {
            let app = behavioral_app();
            let proof = seed_behavioral_proof();
            let mut corrupted = proof.clone();
            corrupted.circuits.$field = structured::Polynomial::new();
            let pcd = corrupted.carry::<()>(());
            let mut rng = StdRng::seed_from_u64(502_002);
            let result = app.verify(&pcd, &mut rng).expect("verify should not error");
            assert!(
                !result,
                "corrupted {} should be rejected",
                stringify!($field)
            );
        }
    };
}

corrupted_circuit_rx_rejects!(corrupted_hashes_1_rx_rejects, hashes_1_rx);
corrupted_circuit_rx_rejects!(corrupted_hashes_2_rx_rejects, hashes_2_rx);
corrupted_circuit_rx_rejects!(corrupted_partial_collapse_rx_rejects, partial_collapse_rx);
corrupted_circuit_rx_rejects!(corrupted_full_collapse_rx_rejects, full_collapse_rx);
corrupted_circuit_rx_rejects!(corrupted_compute_v_rx_rejects, compute_v_rx);

/// Seeding with the same RNG produces identical internal circuit commitments and blinds.
#[test]
fn deterministic_internal_circuit_synthesis() {
    let pasta = Pasta::baked();
    let app = ApplicationBuilder::<Pasta, R, BEHAVIORAL_HEADER_SIZE>::new()
        .finalize(pasta)
        .unwrap();

    let mut rng1 = StdRng::seed_from_u64(502_100);
    let (proof1, _) = app
        .seed(&mut rng1, step::internal::trivial::Trivial::new(), ())
        .unwrap();

    let mut rng2 = StdRng::seed_from_u64(502_100);
    let (proof2, _) = app
        .seed(&mut rng2, step::internal::trivial::Trivial::new(), ())
        .unwrap();

    let c1 = &proof1.circuits;
    let c2 = &proof2.circuits;

    assert_eq!(c1.hashes_1_commitment, c2.hashes_1_commitment);
    assert_eq!(c1.hashes_1_blind, c2.hashes_1_blind);
    assert_eq!(c1.hashes_2_commitment, c2.hashes_2_commitment);
    assert_eq!(c1.hashes_2_blind, c2.hashes_2_blind);
    assert_eq!(
        c1.partial_collapse_commitment,
        c2.partial_collapse_commitment
    );
    assert_eq!(c1.partial_collapse_blind, c2.partial_collapse_blind);
    assert_eq!(c1.full_collapse_commitment, c2.full_collapse_commitment);
    assert_eq!(c1.full_collapse_blind, c2.full_collapse_blind);
    assert_eq!(c1.compute_v_commitment, c2.compute_v_commitment);
    assert_eq!(c1.compute_v_blind, c2.compute_v_blind);
}

/// Each internal circuit's rx polynomial has at least one non-zero coefficient,
/// confirming synthesis produced nontrivial witness polynomials.
#[test]
fn seeded_internal_circuits_are_nontrivial() {
    let proof = seed_behavioral_proof();
    let is_nonzero = |poly: &structured::Polynomial<<Pasta as Cycle>::CircuitField, R>| {
        poly.iter_coeffs()
            .any(|coeff| coeff != <Pasta as Cycle>::CircuitField::ZERO)
    };
    let c = &proof.circuits;
    assert!(is_nonzero(&c.hashes_1_rx), "hashes_1 is trivial");
    assert!(is_nonzero(&c.hashes_2_rx), "hashes_2 is trivial");
    assert!(
        is_nonzero(&c.partial_collapse_rx),
        "partial_collapse is trivial"
    );
    assert!(is_nonzero(&c.full_collapse_rx), "full_collapse is trivial");
    assert!(is_nonzero(&c.compute_v_rx), "compute_v is trivial");
}

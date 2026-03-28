use super::*;
use crate::*;
use native::{
    InternalCircuitIndex, InternalCircuitValues, RevdotParameters, RxIndex, RxValues,
    stages::{eval, inner_error, outer_error, preamble, query},
};
use ragu_circuits::staging::{Stage, StageExt};
use ragu_pasta::{Pasta, fp, fq};

#[cfg(feature = "std")]
use ff::Field;
#[cfg(feature = "std")]
use ragu_arithmetic::Cycle;
#[cfg(feature = "std")]
use ragu_circuits::polynomials::structured;
#[cfg(feature = "std")]
use rand::{SeedableRng, rngs::StdRng};

pub type R = ragu_circuits::polynomials::ProductionRank;

use ff::PrimeField;
use ragu_circuits::polynomials::Rank;
use ragu_core::{
    drivers::emulator::{Emulator, Wireless},
    gadgets::{Bound, Gadget},
    maybe::Empty,
};

pub fn assert_stage_values<F, R, S>(stage: &S)
where
    F: PrimeField,
    R: Rank,
    S: Stage<F, R>,
    for<'dr> Bound<'dr, Emulator<Wireless<Empty, F>>, S::OutputKind>:
        Gadget<'dr, Emulator<Wireless<Empty, F>>>,
{
    let mut emulator = Emulator::counter();
    let output = stage
        .witness(&mut emulator, Empty)
        .expect("allocation should succeed");

    assert_eq!(
        output.num_wires().expect("wire counting should succeed"),
        S::values(),
        "Stage::values() does not match actual wire count"
    );
}

// When changing HEADER_SIZE, update the constraint counts by running:
//   cargo test -p ragu_pcd --release print_internal_circuit -- --nocapture
// Then copy-paste the output into the check_constraints! calls in the test below.
pub const HEADER_SIZE: usize = 65;

// Number of dummy application circuits to register before testing internal
// circuits. This ensures the tests work correctly even when application
// steps are present.
const NUM_APP_STEPS: usize = 6000;

type Preamble = preamble::Stage<Pasta, R, HEADER_SIZE>;
type OuterError = outer_error::Stage<Pasta, R, HEADER_SIZE, RevdotParameters>;
type InnerError = inner_error::Stage<Pasta, R, HEADER_SIZE, RevdotParameters>;
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

    macro_rules! check_constraints {
        ($variant:ident, mul = $mul:expr, lin = $lin:expr) => {{
            let circuit_index = InternalCircuitIndex::$variant.circuit_index();
            let (actual_mul, actual_lin) = app.native_registry.constraint_counts(circuit_index);
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

    check_constraints!(Hashes1Circuit,         mul = 2045, lin = 3422);
    check_constraints!(Hashes2Circuit,         mul = 1879, lin = 2951);
    check_constraints!(InnerCollapseCircuit,  mul = 1756, lin = 1918);
    check_constraints!(OuterCollapseCircuit,  mul = 811 , lin = 808);
    check_constraints!(ComputeVCircuit,        mul = 1140, lin = 1773);
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
    check_stage!(OuterError,  skip = 225, num = 186);
    check_stage!(InnerError,  skip = 411, num = 399);
    check_stage!(Query,   skip = 225, num =  23);
    check_stage!(Eval,    skip = 248, num =  18);
}

/// Helper test to print current constraint counts in copy-pasteable format.
/// Run with: `cargo test -p ragu_pcd --release --features multicore print_internal_circuit -- --nocapture`
#[cfg(feature = "multicore")]
#[test]
fn print_internal_circuit_constraint_counts() {
    use alloc::format;
    use std::println;

    let pasta = Pasta::baked();

    let app = ApplicationBuilder::<Pasta, R, HEADER_SIZE>::new()
        .register_dummy_circuits(NUM_APP_STEPS)
        .unwrap()
        .finalize(pasta)
        .unwrap();

    let variants = [
        ("Hashes1Circuit", InternalCircuitIndex::Hashes1Circuit),
        ("Hashes2Circuit", InternalCircuitIndex::Hashes2Circuit),
        (
            "InnerCollapseCircuit",
            InternalCircuitIndex::InnerCollapseCircuit,
        ),
        (
            "OuterCollapseCircuit",
            InternalCircuitIndex::OuterCollapseCircuit,
        ),
        ("ComputeVCircuit", InternalCircuitIndex::ComputeVCircuit),
    ];

    println!("\n// Copy-paste the following into test_internal_circuit_constraint_counts:");
    for (name, variant) in variants {
        let circuit_index = variant.circuit_index();
        let (mul, lin) = app.native_registry.constraint_counts(circuit_index);
        println!(
            "        check_constraints!({:<24} mul = {:<4}, lin = {});",
            format!("{},", name),
            mul,
            lin
        );
    }
}

/// Helper test to print current stage parameters in copy-pasteable format.
/// Run with: `cargo test -p ragu_pcd --release --features multicore print_internal_stage -- --nocapture`
#[cfg(feature = "multicore")]
#[test]
fn print_internal_stage_parameters() {
    use alloc::format;
    use std::println;

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
    print_stage!(OuterError);
    print_stage!(InnerError);
    print_stage!(Query);
    print_stage!(Eval);
}

/// Verifies the native registry digest matches the expected value.
///
/// This test ensures the wiring polynomial structure is mathematically
/// equivalent to the reference implementation by comparing cryptographic
/// digests.
#[test]
fn test_native_registry_digest() {
    let pasta = Pasta::baked();

    let app = ApplicationBuilder::<Pasta, R, HEADER_SIZE>::new()
        .register_dummy_circuits(NUM_APP_STEPS)
        .unwrap()
        .finalize(pasta)
        .unwrap();

    let expected = fp!(0x07c92629c59ab07c4f51c5b9fa976f2a2489e9a68c43cda8805d29405fbb2df9);

    assert_eq!(
        app.native_registry.digest(),
        expected,
        "Native registry digest changed unexpectedly!"
    );
}

/// Verifies the nested registry digest matches the expected value.
///
/// This test ensures the wiring polynomial structure is mathematically
/// equivalent to the reference implementation by comparing cryptographic
/// digests.
#[test]
fn test_nested_registry_digest() {
    let pasta = Pasta::baked();

    let app = ApplicationBuilder::<Pasta, R, HEADER_SIZE>::new()
        .register_dummy_circuits(NUM_APP_STEPS)
        .unwrap()
        .finalize(pasta)
        .unwrap();

    let expected = fq!(0x3fc83d6620ddaa901105e3b851b6763fc36d889eda11607770e8f461aced66fb);

    assert_eq!(
        app.nested_registry.digest(),
        expected,
        "Nested registry digest changed unexpectedly!"
    );
}

/// Helper test to print current registry digests in copy-pasteable format.
/// Run with: `cargo test -p ragu_pcd --release --features multicore print_registry_digests -- --nocapture`
#[cfg(feature = "multicore")]
#[test]
fn print_registry_digests() {
    use alloc::{format, string::String, vec::Vec};
    use ff::PrimeField;
    use std::println;

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

#[test]
fn test_internal_circuit_index_all_exhaustive() {
    let mut collected = alloc::vec::Vec::new();
    let _values = InternalCircuitValues::from_fn(|id| {
        collected.push(id);
    });
    assert_eq!(collected.as_slice(), InternalCircuitIndex::ALL);
}

#[test]
fn test_rx_index_all_exhaustive() {
    let mut collected = alloc::vec::Vec::new();
    let _values = RxValues::from_fn(|id| {
        collected.push(id);
    });
    assert_eq!(collected.as_slice(), RxIndex::ALL);
}

#[cfg(feature = "std")]
const BEHAVIORAL_HEADER_SIZE: usize = 4;

#[cfg(feature = "std")]
fn behavioral_app() -> crate::Application<'static, Pasta, R, BEHAVIORAL_HEADER_SIZE> {
    let pasta = Pasta::baked();
    ApplicationBuilder::<Pasta, R, BEHAVIORAL_HEADER_SIZE>::new()
        .finalize(pasta)
        .unwrap()
}

#[cfg(feature = "std")]
fn seed_behavioral_proof() -> &'static crate::Proof<Pasta, R> {
    use std::sync::OnceLock;
    static CACHED: OnceLock<crate::Proof<Pasta, R>> = OnceLock::new();
    CACHED.get_or_init(|| {
        let app = behavioral_app();
        let mut rng = StdRng::seed_from_u64(502);
        let (pcd, _aux) = app
            .seed(&mut rng, step::internal::trivial::Trivial::new(), ())
            .unwrap();
        pcd.into_parts().0
    })
}

#[cfg(feature = "std")]
macro_rules! valid_circuit_commitment_binds {
    ($test_name:ident, $circuit:ident) => {
        #[test]
        fn $test_name() {
            let proof = seed_behavioral_proof();
            let gens = Pasta::host_generators(Pasta::baked());
            let triple = &proof.circuits.$circuit;
            assert_eq!(
                triple.rx.commit(gens, triple.blind),
                triple.commitment.into(),
                "{} commitment mismatch",
                stringify!($circuit)
            );
        }
    };
}

#[cfg(feature = "std")]
valid_circuit_commitment_binds!(seeded_hashes_1_commitment_binds, hashes_1);
#[cfg(feature = "std")]
valid_circuit_commitment_binds!(seeded_hashes_2_commitment_binds, hashes_2);
#[cfg(feature = "std")]
valid_circuit_commitment_binds!(seeded_inner_collapse_commitment_binds, inner_collapse);
#[cfg(feature = "std")]
valid_circuit_commitment_binds!(seeded_outer_collapse_commitment_binds, outer_collapse);
#[cfg(feature = "std")]
valid_circuit_commitment_binds!(seeded_compute_v_commitment_binds, compute_v);

/// Baseline: a seeded proof with internal circuits passes verification.
#[cfg(feature = "std")]
#[test]
fn seeded_proof_with_internal_circuits_verifies() {
    let app = behavioral_app();
    let proof = seed_behavioral_proof();
    let mut rng = StdRng::seed_from_u64(502_001);
    let pcd = proof.clone().carry::<()>(());
    let result = app.verify(&pcd, &mut rng).expect("verify should not error");
    assert!(result, "seeded proof should verify");
}

#[cfg(feature = "std")]
macro_rules! corrupted_circuit_rx_rejects {
    ($test_name:ident, $circuit:ident) => {
        #[test]
        fn $test_name() {
            let app = behavioral_app();
            let proof = seed_behavioral_proof();
            let mut corrupted = proof.clone();
            corrupted.circuits.$circuit.rx = structured::Polynomial::new();
            let pcd = corrupted.carry::<()>(());
            let mut rng = StdRng::seed_from_u64(502_002);
            let result = app.verify(&pcd, &mut rng).expect("verify should not error");
            assert!(
                !result,
                "corrupted {} should be rejected",
                stringify!($circuit)
            );
        }
    };
}

#[cfg(feature = "std")]
corrupted_circuit_rx_rejects!(corrupted_hashes_1_rx_rejects, hashes_1);
#[cfg(feature = "std")]
corrupted_circuit_rx_rejects!(corrupted_hashes_2_rx_rejects, hashes_2);
#[cfg(feature = "std")]
corrupted_circuit_rx_rejects!(corrupted_inner_collapse_rx_rejects, inner_collapse);
#[cfg(feature = "std")]
corrupted_circuit_rx_rejects!(corrupted_outer_collapse_rx_rejects, outer_collapse);
#[cfg(feature = "std")]
corrupted_circuit_rx_rejects!(corrupted_compute_v_rx_rejects, compute_v);

/// Seeding with the same RNG produces identical internal circuit commitments and blinds.
#[cfg(feature = "std")]
#[test]
fn deterministic_internal_circuit_synthesis() {
    let pasta = Pasta::baked();
    let app = ApplicationBuilder::<Pasta, R, BEHAVIORAL_HEADER_SIZE>::new()
        .finalize(pasta)
        .unwrap();

    let mut rng1 = StdRng::seed_from_u64(502_100);
    let (pcd1, _) = app
        .seed(&mut rng1, step::internal::trivial::Trivial::new(), ())
        .unwrap();
    let (proof1, _) = pcd1.into_parts();

    let mut rng2 = StdRng::seed_from_u64(502_100);
    let (pcd2, _) = app
        .seed(&mut rng2, step::internal::trivial::Trivial::new(), ())
        .unwrap();
    let (proof2, _) = pcd2.into_parts();

    let c1 = &proof1.circuits;
    let c2 = &proof2.circuits;

    assert_eq!(c1.hashes_1.commitment, c2.hashes_1.commitment);
    assert_eq!(c1.hashes_1.blind, c2.hashes_1.blind);
    assert_eq!(c1.hashes_2.commitment, c2.hashes_2.commitment);
    assert_eq!(c1.hashes_2.blind, c2.hashes_2.blind);
    assert_eq!(c1.inner_collapse.commitment, c2.inner_collapse.commitment);
    assert_eq!(c1.inner_collapse.blind, c2.inner_collapse.blind);
    assert_eq!(c1.outer_collapse.commitment, c2.outer_collapse.commitment);
    assert_eq!(c1.outer_collapse.blind, c2.outer_collapse.blind);
    assert_eq!(c1.compute_v.commitment, c2.compute_v.commitment);
    assert_eq!(c1.compute_v.blind, c2.compute_v.blind);
}

/// Each internal circuit's rx polynomial has at least one non-zero coefficient,
/// confirming synthesis produced nontrivial witness polynomials.
#[cfg(feature = "std")]
#[test]
fn seeded_internal_circuits_are_nontrivial() {
    let proof = seed_behavioral_proof();
    let is_nonzero = |poly: &structured::Polynomial<<Pasta as Cycle>::CircuitField, R>| {
        poly.iter_coeffs()
            .any(|coeff| coeff != <Pasta as Cycle>::CircuitField::ZERO)
    };
    let c = &proof.circuits;
    assert!(is_nonzero(&c.hashes_1.rx), "hashes_1 is trivial");
    assert!(is_nonzero(&c.hashes_2.rx), "hashes_2 is trivial");
    assert!(
        is_nonzero(&c.inner_collapse.rx),
        "inner_collapse is trivial"
    );
    assert!(
        is_nonzero(&c.outer_collapse.rx),
        "outer_collapse is trivial"
    );
    assert!(is_nonzero(&c.compute_v.rx), "compute_v is trivial");
}

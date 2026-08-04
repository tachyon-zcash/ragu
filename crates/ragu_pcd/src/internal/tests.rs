use native::{InternalCircuitIndex, InternalCircuitValues, RxIndex, RxValues};
use ragu_circuits::staging::Stage;
use ragu_pasta::{Pasta, fp, fq};

use super::*;
use crate::*;
pub type R = ragu_circuits::polynomials::ProductionRank;

use ragu_arithmetic::ff::PrimeField;
use ragu_circuits::polynomials::Rank;
use ragu_core::{
    drivers::emulator::{Emulator, Wireless},
    gadgets::{Bound, Gadget},
    maybe::Empty,
};

/// A stage allocates exactly `Stage::values()` wires.
pub fn assert_stage_values<F, R, S>(stage: &S)
where
    F: PrimeField,
    R: Rank,
    S: Stage<F, R>,
    for<'dr> Bound<'dr, Emulator<Wireless<Empty, F>>, S::OutputKind>:
        Gadget<'dr, Emulator<Wireless<Empty, F>>>,
{
    let mut emulator = Emulator::counter();
    let num_wires = stage
        .witness(&mut emulator, Empty)
        .expect("allocation should succeed")
        .num_wires()
        .expect("wire counting should succeed");
    assert_eq!(
        num_wires,
        S::values(),
        "Stage::values() does not match actual wire count"
    );
}

// When changing HEADER_SIZE, update the constraint counts by running:
//   cargo test -p ragu_pcd --release print_internal_circuit -- --nocapture
// Then copy-paste the output into the check_constraints! calls in the test below.
pub const HEADER_SIZE: usize = 105;

// Number of dummy application circuits to register before testing internal
// circuits. This ensures the tests work correctly even when application
// steps are present.
const NUM_APP_STEPS: usize = 6000;

fn dummy_app<'params, const HDR: usize, const POLYS: usize, const CLAIMS: usize>(
    pasta: &'params <Pasta as ragu_arithmetic::Cycle>::Params,
    steps: usize,
) -> crate::Application<'params, Pasta, R, HDR, AppHooks<POLYS, CLAIMS>> {
    ApplicationBuilder::<Pasta, R, HDR, AppHooks<POLYS, CLAIMS>>::new(pasta)
        .register_dummy_circuits(steps)
        .unwrap()
        .finalize()
        .unwrap()
}

macro_rules! check_constraints {
    ($app:expr, $variant:ident, mul = $mul:expr, lin = $lin:expr) => {{
        let circuit_index = InternalCircuitIndex::$variant.circuit_index();
        let (actual_gates, actual_constraints) =
            $app.native_registry.constraint_counts(circuit_index);
        assert_eq!(
            actual_gates,
            $mul,
            "{}: gates: expected {}, got {}",
            stringify!($variant),
            $mul,
            actual_gates
        );
        assert_eq!(
            actual_constraints,
            $lin,
            "{}: constraints: expected {}, got {}",
            stringify!($variant),
            $lin,
            actual_constraints
        );
    }};
}

#[rustfmt::skip]
#[test]
fn test_internal_circuit_constraint_counts() {
    let pasta = Pasta::baked();

    let app = dummy_app::<HEADER_SIZE, 0, 0>(pasta, NUM_APP_STEPS);

    check_constraints!(app, Hashes1Circuit,       mul = 1451, lin = 2068);
    check_constraints!(app, Hashes2Circuit,       mul = 1999, lin = 2951);
    check_constraints!(app, InnerCollapseCircuit, mul = 1876, lin = 1918);
    check_constraints!(app, OuterCollapseCircuit, mul = 2043, lin = 3042);
    check_constraints!(app, ComputeVCircuit,      mul = 1255, lin = 1773);
}

/// The stage types `test_internal_stage_parameters` pins, at eight
/// polynomials.
mod pinned_chain {
    use ragu_pasta::Pasta;

    use super::{HEADER_SIZE, R};
    use crate::{
        AppHooks,
        internal::native::{RevdotParameters, stages},
    };

    type J = AppHooks<8, 1>;

    pub type Preamble = stages::preamble::Stage<Pasta, R, HEADER_SIZE, J>;
    pub type OuterError = stages::outer_error::Stage<Pasta, R, HEADER_SIZE, J, RevdotParameters>;
    pub type InnerError = stages::inner_error::Stage<Pasta, R, HEADER_SIZE, J, RevdotParameters>;
    pub type Query = stages::query::Stage<Pasta, R, HEADER_SIZE, J>;
    pub type Eval = stages::eval::Stage<Pasta, R, HEADER_SIZE, J>;
}

#[rustfmt::skip]
#[test]
fn test_internal_stage_parameters() {
    use ragu_circuits::staging::{Stage as _, StageExt as _};

    macro_rules! check_stage {
        ($stage:ty, skip = $skip:expr, num = $num:expr) => {{
            assert_eq!(<$stage>::skip_gates(), $skip, "{}: skip", stringify!($stage));
            assert_eq!(<$stage>::num_gates(), $num, "{}: num", stringify!($stage));
        }};
    }

    check_stage!(pinned_chain::Preamble,    skip =   1, num = 365);
    check_stage!(pinned_chain::OuterError,  skip = 366, num = 186);
    check_stage!(pinned_chain::InnerError,  skip = 552, num = 399);
    check_stage!(pinned_chain::Query,       skip = 366, num =  23);
    check_stage!(pinned_chain::Eval,        skip = 389, num =  26);
}

/// Helper test to print current constraint counts in copy-pasteable format.
/// Run with: `cargo test -p ragu_pcd --release print_internal_circuit -- --nocapture`
#[test]
fn print_internal_circuit_constraint_counts() {
    use alloc::format;
    use std::println;

    let pasta = Pasta::baked();

    let app = dummy_app::<HEADER_SIZE, 0, 0>(pasta, NUM_APP_STEPS);

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
            "    check_constraints!(app, {:<22} mul = {:>4}, lin = {:>4});",
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
    use std::println;

    use ragu_circuits::staging::StageExt as _;

    fn line<S: ragu_circuits::staging::Stage<ragu_pasta::Fp, R>>(name: &str) {
        println!(
            "    check_stage!(pinned_chain::{:<12} skip = {:>3}, num = {:>3});",
            alloc::format!("{name},"),
            S::skip_gates(),
            S::num_gates()
        );
    }

    println!("\n// Copy-paste the following into test_internal_stage_parameters:");
    line::<pinned_chain::Preamble>("Preamble");
    line::<pinned_chain::OuterError>("OuterError");
    line::<pinned_chain::InnerError>("InnerError");
    line::<pinned_chain::Query>("Query");
    line::<pinned_chain::Eval>("Eval");
}

/// Verifies the native registry digest matches the expected value.
///
/// This test ensures the wiring polynomial structure is mathematically
/// equivalent to the reference implementation by comparing cryptographic
/// digests.
#[test]
fn test_native_registry_digest() {
    let pasta = Pasta::baked();

    let app = dummy_app::<HEADER_SIZE, 0, 0>(pasta, NUM_APP_STEPS);

    let expected = fp!(0x31e1786b198ad8953d0ec1699a2d1c7ed26d312a7c8c67099cb5a517259e54e3);

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

    let app = dummy_app::<HEADER_SIZE, 0, 0>(pasta, NUM_APP_STEPS);

    let expected = fq!(0x2f4bf855b80a694facbe9a2c26ee8d1dae9e15bb7b7eba54ca53f5c166e1d150);

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
    use alloc::{format, string::String, vec::Vec};
    use std::println;

    use ragu_arithmetic::ff::PrimeField;

    let pasta = Pasta::baked();

    let app = dummy_app::<HEADER_SIZE, 0, 0>(pasta, NUM_APP_STEPS);

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

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
pub const HEADER_SIZE: usize = 90;

// Number of dummy application circuits to register before testing internal
// circuits. This ensures the tests work correctly even when application
// steps are present.
const NUM_APP_STEPS: usize = 6000;

fn dummy_app<
    'params,
    const HDR: usize,
    const POLYS: usize,
    const CLAIMS: usize,
    const CHALLENGES: usize,
>(
    pasta: &'params <Pasta as ragu_arithmetic::Cycle>::Params,
    steps: usize,
) -> crate::Application<'params, Pasta, R, HDR, AppHooks<POLYS, CLAIMS, CHALLENGES, 2>> {
    ApplicationBuilder::<Pasta, R, HDR, AppHooks<POLYS, CLAIMS, CHALLENGES, 2>>::new(pasta)
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

    let app = dummy_app::<HEADER_SIZE, 0, 0, 0>(pasta, NUM_APP_STEPS);

    check_constraints!(app, Hashes1Circuit,          mul = 1406, lin = 2038);
    check_constraints!(app, Hashes2Circuit,          mul = 1954, lin = 2951);
    check_constraints!(app, InnerCollapseCircuit,    mul = 1831, lin = 1918);
    check_constraints!(app, OuterCollapseCircuit,    mul = 1848, lin = 2742);
    check_constraints!(app, ComputeVCircuit,         mul = 1239, lin = 1819);
    // `ChallengeBinding`'s count includes `OuterError`'s 186 gates: it
    // reaches the derived challenges on the branch below `OuterError`, and a
    // circuit's trace spans every gate up to its last stage, so it pays for
    // the stage it skips on the way.
    check_constraints!(app, ChallengeBindingCircuit, mul =  518, lin =   71);
}

/// Prints the constraint counts the pin tests expect, for re-pinning.
///
/// Run with: `cargo test -p ragu_pcd print_internal_circuit_constraint -- --ignored --nocapture`
#[test]
#[ignore = "prints the pinned constraint counts; run explicitly"]
fn print_internal_circuit_constraint_counts() {
    use std::println;

    let pasta = Pasta::baked();

    let print = |registry: &ragu_circuits::registry::Registry<_, R>, test: &str| {
        println!("\n// Copy-paste the following into {test}:");
        for variant in [
            InternalCircuitIndex::Hashes1Circuit,
            InternalCircuitIndex::Hashes2Circuit,
            InternalCircuitIndex::InnerCollapseCircuit,
            InternalCircuitIndex::OuterCollapseCircuit,
            InternalCircuitIndex::ComputeVCircuit,
            InternalCircuitIndex::ChallengeBindingCircuit,
        ] {
            let (mul, lin) = registry.constraint_counts(variant.circuit_index());
            println!(
                "    check_constraints!(app, {:<24} mul = {:>4}, lin = {:>4});",
                alloc::format!("{variant:?},"),
                mul,
                lin
            );
        }
    };

    print(
        &dummy_app::<HEADER_SIZE, 0, 0, 0>(pasta, NUM_APP_STEPS).native_registry,
        "test_internal_circuit_constraint_counts",
    );
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

    type J = AppHooks<8, 1, 1, 2>;

    pub type Preamble = stages::preamble::Stage<Pasta, R, HEADER_SIZE, J>;
    pub type OuterError = stages::outer_error::Stage<Pasta, R, HEADER_SIZE, J, RevdotParameters>;
    pub type InnerError = stages::inner_error::Stage<Pasta, R, HEADER_SIZE, J, RevdotParameters>;
    pub type Query = stages::query::Stage<Pasta, R, HEADER_SIZE, J>;
    pub type Eval = stages::eval::Stage<Pasta, R, HEADER_SIZE, J>;
    pub type Challenges = stages::challenges::Stage<Pasta, R, HEADER_SIZE, J, RevdotParameters>;
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

    check_stage!(pinned_chain::Preamble,    skip =   1, num = 320);
    check_stage!(pinned_chain::OuterError,  skip = 321, num = 186);
    check_stage!(pinned_chain::InnerError,  skip = 507, num = 399);
    check_stage!(pinned_chain::Query,       skip = 321, num =  27);
    check_stage!(pinned_chain::Eval,        skip = 348, num =  28);
    check_stage!(pinned_chain::Challenges,  skip = 507, num =   3);
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
    line::<pinned_chain::Challenges>("Challenges");
}

/// Verifies the native registry digest matches the expected value.
///
/// This test ensures the wiring polynomial structure is mathematically
/// equivalent to the reference implementation by comparing cryptographic
/// digests.
#[test]
fn test_native_registry_digest() {
    let pasta = Pasta::baked();

    let app = dummy_app::<HEADER_SIZE, 0, 0, 0>(pasta, NUM_APP_STEPS);

    // At `POLYS = 0, CLAIMS = 0, CHALLENGES = 0` every hook-dependent width
    // collapses.
    let expected = fp!(0x2bb64a4adaa9e869d9187bec77ae9f8c8788703ca013ff9bae02b6fdbc02dec0);

    assert_eq!(
        app.native_registry.digest(),
        expected,
        "Native registry digest changed unexpectedly!"
    );
}

/// Pins the nested registry digest at the zero layout.
#[test]
fn test_nested_registry_digest() {
    let pasta = Pasta::baked();

    let app = dummy_app::<HEADER_SIZE, 0, 0, 0>(pasta, NUM_APP_STEPS);

    let expected = fq!(0x06bb3145242fd72534249a81cf321e7e4608d2610f745aa4eafa42887528f9d9);

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
    use alloc::{format, string::String};
    use std::println;

    use ragu_arithmetic::ff::PrimeField;

    let pasta = Pasta::baked();

    // Big-endian hex, the `fp!`/`fq!` literal form.
    fn hex<F: PrimeField>(digest: F) -> String {
        digest
            .to_repr()
            .as_ref()
            .iter()
            .rev()
            .map(|b| format!("{:02x}", b))
            .collect()
    }

    let zero_layout = dummy_app::<HEADER_SIZE, 0, 0, 0>(pasta, NUM_APP_STEPS);

    println!("\n// Copy-paste the following into the registry digest tests:");
    println!(
        "    // test_native_registry_digest\n    let expected = fp!(0x{});",
        hex(zero_layout.native_registry.digest())
    );
    println!(
        "    // test_nested_registry_digest\n    let expected = fq!(0x{});",
        hex(zero_layout.nested_registry.digest())
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

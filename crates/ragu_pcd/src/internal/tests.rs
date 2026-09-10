use native::{
    InternalCircuitIndex, InternalCircuitValues, RevdotParameters, RxIndex, RxValues,
    stages::{eval, inner_error, outer_error, preamble, query},
};
use ragu_circuits::{
    Circuit,
    staging::{Stage, StageExt},
};
use ragu_pasta::{Fp, Pasta, fp, fq};

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
pub const HEADER_SIZE: usize = 105;

// Number of dummy application circuits to register before testing internal
// circuits. Internal circuit construction depends on the resulting registry
// domain size, and other tests still build an application with this many
// placeholder steps.
const NUM_APP_STEPS: usize = 6000;

type Preamble = preamble::Stage<Pasta, R, HEADER_SIZE>;
type OuterError = outer_error::Stage<Pasta, R, HEADER_SIZE, RevdotParameters>;
type InnerError = inner_error::Stage<Pasta, R, HEADER_SIZE, RevdotParameters>;
type Query = query::Stage<Pasta, R, HEADER_SIZE>;
type Eval = eval::Stage<Pasta, R, HEADER_SIZE>;
type NativeEndoscalar = crate::internal::endoscalar::EndoscalarStage;
type PointsInputs = native::stages::points::InputsStage<
    <Pasta as ragu_arithmetic::Cycle>::NestedCurve,
    { native::NUM_ENDOSCALING_POINTS },
>;
type PointsInterstitials = native::stages::points::InterstitialsStage<
    <Pasta as ragu_arithmetic::Cycle>::NestedCurve,
    { native::NUM_ENDOSCALING_POINTS },
>;

fn synthesis_counts(circuit: impl Circuit<Fp>) -> (usize, usize) {
    let counts = ragu_circuits::testing::synthesis_counts(&circuit).unwrap();
    (counts.num_gates, counts.num_constraints)
}

/// Like [`internal_circuit_counts`], reporting a synthesis failure (such as
/// an exceeded gate bound) instead of panicking.
fn try_internal_circuit_counts(variant: InternalCircuitIndex) -> Result<(usize, usize)> {
    fn counts(circuit: impl Circuit<Fp>) -> Result<(usize, usize)> {
        let counts = ragu_circuits::testing::synthesis_counts(&circuit)?;
        Ok((counts.num_gates, counts.num_constraints))
    }
    let pasta = Pasta::baked();
    let (_, log2_circuits) = native::total_circuit_counts(NUM_APP_STEPS);
    match variant {
        InternalCircuitIndex::Hashes1Circuit => counts(native::circuits::hashes_1::Circuit::<
            Pasta,
            R,
            HEADER_SIZE,
            RevdotParameters,
        >::new(pasta, log2_circuits)),
        InternalCircuitIndex::Hashes2Circuit => counts(native::circuits::hashes_2::Circuit::<
            Pasta,
            R,
            HEADER_SIZE,
            RevdotParameters,
        >::new(pasta)),
        InternalCircuitIndex::InnerCollapseCircuit => {
            counts(native::circuits::inner_collapse::Circuit::<
                Pasta,
                R,
                HEADER_SIZE,
                RevdotParameters,
            >::new())
        }
        InternalCircuitIndex::OuterCollapseCircuit => {
            counts(native::circuits::outer_collapse::Circuit::<
                Pasta,
                R,
                HEADER_SIZE,
                RevdotParameters,
            >::new())
        }
        InternalCircuitIndex::ComputeVCircuit => {
            counts(native::circuits::compute_v::Circuit::<Pasta, R, HEADER_SIZE>::new())
        }
        InternalCircuitIndex::BindChallengesCircuit(k) => {
            crate::with_binder!(k, Pasta, R, HEADER_SIZE, pasta, |circuit| counts(circuit))
        }
        InternalCircuitIndex::BindBetaCircuit => counts(native::circuits::bind_beta::Circuit::<
            Pasta,
            R,
            HEADER_SIZE,
            RevdotParameters,
        >::new(pasta)),
        InternalCircuitIndex::BindEndoscalarCircuit => {
            counts(native::circuits::bind_endoscalar::Circuit::<Pasta, R>::new())
        }
        InternalCircuitIndex::EndoscalingStep(step) => {
            counts(native::circuits::endoscaling_step::Circuit::<
                <Pasta as ragu_arithmetic::Cycle>::NestedCurve,
                R,
                { native::NUM_ENDOSCALING_POINTS },
            >::new(step as usize))
        }
        _ => panic!("constraint counts only apply to internal circuits"),
    }
}

fn internal_circuit_counts(variant: InternalCircuitIndex) -> (usize, usize) {
    let pasta = Pasta::baked();
    let (_, log2_circuits) = native::total_circuit_counts(NUM_APP_STEPS);

    match variant {
        InternalCircuitIndex::Hashes1Circuit => {
            synthesis_counts(native::circuits::hashes_1::Circuit::<
                Pasta,
                R,
                HEADER_SIZE,
                RevdotParameters,
            >::new(pasta, log2_circuits))
        }
        InternalCircuitIndex::Hashes2Circuit => {
            synthesis_counts(native::circuits::hashes_2::Circuit::<
                Pasta,
                R,
                HEADER_SIZE,
                RevdotParameters,
            >::new(pasta))
        }
        InternalCircuitIndex::InnerCollapseCircuit => {
            synthesis_counts(native::circuits::inner_collapse::Circuit::<
                Pasta,
                R,
                HEADER_SIZE,
                RevdotParameters,
            >::new())
        }
        InternalCircuitIndex::OuterCollapseCircuit => {
            synthesis_counts(native::circuits::outer_collapse::Circuit::<
                Pasta,
                R,
                HEADER_SIZE,
                RevdotParameters,
            >::new())
        }
        InternalCircuitIndex::ComputeVCircuit => {
            synthesis_counts(native::circuits::compute_v::Circuit::<Pasta, R, HEADER_SIZE>::new())
        }
        InternalCircuitIndex::BindChallengesCircuit(k) => {
            crate::with_binder!(k, Pasta, R, HEADER_SIZE, Pasta::baked(), |circuit| {
                synthesis_counts(circuit)
            })
        }
        InternalCircuitIndex::BindBetaCircuit => {
            synthesis_counts(native::circuits::bind_beta::Circuit::<
                Pasta,
                R,
                HEADER_SIZE,
                RevdotParameters,
            >::new(Pasta::baked()))
        }
        InternalCircuitIndex::BindEndoscalarCircuit => {
            synthesis_counts(native::circuits::bind_endoscalar::Circuit::<Pasta, R>::new())
        }
        InternalCircuitIndex::EndoscalingStep(step) => {
            synthesis_counts(native::circuits::endoscaling_step::Circuit::<
                <Pasta as ragu_arithmetic::Cycle>::NestedCurve,
                R,
                { native::NUM_ENDOSCALING_POINTS },
            >::new(step as usize))
        }
        _ => panic!("constraint counts only apply to internal circuits"),
    }
}

#[rustfmt::skip]
#[test]
fn test_internal_circuit_constraint_counts() {
    macro_rules! check_constraints {
        ($variant:ident($k:expr), mul = $mul:expr, lin = $lin:expr) => {{
            let (actual_gates, actual_constraints) =
                internal_circuit_counts(InternalCircuitIndex::$variant($k));
            assert_eq!(
                actual_gates,
                $mul,
                "{}({}): gates: expected {}, got {}",
                stringify!($variant),
                $k,
                $mul,
                actual_gates
            );
            assert_eq!(
                actual_constraints,
                $lin,
                "{}({}): constraints: expected {}, got {}",
                stringify!($variant),
                $k,
                $lin,
                actual_constraints
            );
        }};
        ($variant:ident, mul = $mul:expr, lin = $lin:expr) => {{
            let (actual_gates, actual_constraints) =
                internal_circuit_counts(InternalCircuitIndex::$variant);
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

    check_constraints!(Hashes1Circuit,              mul = 1453, lin = 2068);
    check_constraints!(Hashes2Circuit,              mul = 2001, lin = 2951);
    check_constraints!(InnerCollapseCircuit,        mul = 1878, lin = 1918);
    check_constraints!(OuterCollapseCircuit,        mul = 2045, lin = 3042);
    check_constraints!(ComputeVCircuit,             mul = 1707, lin = 2494);
    check_constraints!(BindChallengesCircuit(0),    mul = 1928, lin = 2921);
    check_constraints!(BindChallengesCircuit(1),    mul = 1933, lin = 2931);
    check_constraints!(BindChallengesCircuit(2),    mul = 1933, lin = 2931);
    check_constraints!(BindChallengesCircuit(3),    mul = 1933, lin = 2931);
    check_constraints!(BindChallengesCircuit(4),    mul = 1944, lin = 2953);
    check_constraints!(BindBetaCircuit,             mul = 1976, lin = 2913);
    check_constraints!(BindEndoscalarCircuit,       mul = 732,  lin = 1387);
    // Every native endoscaling step lays out the same.
    for step in 0..native::NUM_ENDOSCALING_STEPS as u32 {
        check_constraints!(EndoscalingStep(step),   mul = 2023, lin = 3677);
    }
}

#[rustfmt::skip]
#[test]
fn test_internal_stage_parameters() {
    macro_rules! check_stage {
        ($Stage:ty, skip = $skip:expr, num = $num:expr) => {{
            assert_eq!(<$Stage as Stage<Fp, R>>::skip_gates(), $skip, "{}: skip", stringify!($Stage));
            assert_eq!(<$Stage as StageExt<Fp, R>>::num_gates(), $num, "{}: num", stringify!($Stage));
        }};
    }

    check_stage!(Preamble, skip =   1, num = 347);
    check_stage!(OuterError, skip = 348, num = 186);
    check_stage!(InnerError, skip = 534, num = 399);
    check_stage!(Query,   skip = 348, num =  75);
    check_stage!(Eval,    skip = 423, num =  57);
    check_stage!(NativeEndoscalar,    skip =   1, num =  64);
    check_stage!(PointsInputs,        skip =  65, num =  97);
    check_stage!(PointsInterstitials, skip = 162, num =  24);
}

/// Helper test to print current constraint counts in copy-pasteable format.
/// Run with: `cargo test -p ragu_pcd --release print_internal_circuit -- --nocapture`
#[test]
fn print_internal_circuit_constraint_counts() {
    use alloc::format;
    use std::println;

    let variants = InternalCircuitIndex::ALL.into_iter().filter(|variant| {
        !matches!(
            variant,
            InternalCircuitIndex::PreambleStage
                | InternalCircuitIndex::InnerErrorStage
                | InternalCircuitIndex::OuterErrorStage
                | InternalCircuitIndex::QueryStage
                | InternalCircuitIndex::EvalStage
                | InternalCircuitIndex::EndoscalarStage
                | InternalCircuitIndex::PointsInputsStage
                | InternalCircuitIndex::PointsInterstitialsStage
                | InternalCircuitIndex::InnerErrorFinalStaged
                | InternalCircuitIndex::OuterErrorFinalStaged
                | InternalCircuitIndex::EvalFinalStaged
                | InternalCircuitIndex::PointsInputsFinalStaged
                | InternalCircuitIndex::PointsInterstitialsFinalStaged
        )
    });

    println!("\n// Copy-paste the following into test_internal_circuit_constraint_counts:");
    for variant in variants {
        match try_internal_circuit_counts(variant) {
            Ok((mul, lin)) => println!(
                "        check_constraints!({:<28} mul = {:<4}, lin = {});",
                format!("{variant:?},"),
                mul,
                lin
            ),
            Err(err) => println!("        // {variant:?}: synthesis failed: {err}"),
        }
    }
}

/// Helper test to print current stage parameters in copy-pasteable format.
/// Run with: `cargo test -p ragu_pcd --release print_internal_stage -- --nocapture`
#[test]
fn print_internal_stage_parameters() {
    use alloc::format;
    use std::println;

    macro_rules! print_stage {
        ($Stage:ty) => {{
            let skip = <$Stage as Stage<Fp, R>>::skip_gates();
            let num = <$Stage as StageExt<Fp, R>>::num_gates();
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
    print_stage!(NativeEndoscalar);
    print_stage!(PointsInputs);
    print_stage!(PointsInterstitials);
}

/// The nested circuits' gate and constraint counts, by [`nested::InternalCircuitIndex`].
///
/// # Panics
///
/// Panics for the bonding entries, which are masks rather than circuits.
fn nested_circuit_counts(variant: nested::InternalCircuitIndex) -> (usize, usize) {
    use crate::internal::{endoscalar, nested::NUM_ENDOSCALING_POINTS};
    use ragu_circuits::staging::MultiStage;
    use ragu_pasta::EqAffine;

    fn counts(circuit: impl Circuit<ragu_pasta::Fq>) -> (usize, usize) {
        let counts = ragu_circuits::testing::synthesis_counts(&circuit).unwrap();
        (counts.num_gates, counts.num_constraints)
    }
    match variant {
        nested::InternalCircuitIndex::EndoscalingStep(step) => {
            counts(MultiStage::new(endoscalar::EndoscalingStep::<
                EqAffine,
                R,
                NUM_ENDOSCALING_POINTS,
            >::new(step as usize)))
        }
        nested::InternalCircuitIndex::Export => {
            counts(MultiStage::new(nested::circuits::export::Circuit::<
                EqAffine,
                R,
            >::new()))
        }
        nested::InternalCircuitIndex::Collapse => {
            counts(MultiStage::new(nested::circuits::collapse::Circuit::<
                EqAffine,
                R,
            >::new()))
        }
        nested::InternalCircuitIndex::ComputeV => {
            counts(MultiStage::new(nested::circuits::compute_v::Circuit::<
                EqAffine,
                R,
            >::new()))
        }
        nested::InternalCircuitIndex::Loading => {
            counts(MultiStage::new(nested::circuits::loading::Circuit::<
                EqAffine,
                R,
            >::new()))
        }
        _ => panic!("constraint counts only apply to nested circuits"),
    }
}

/// The nested circuits [`nested_circuit_counts`] covers, in
/// [`nested::InternalCircuitIndex::ALL`] order.
fn nested_circuits() -> impl Iterator<Item = nested::InternalCircuitIndex> {
    nested::InternalCircuitIndex::ALL
        .into_iter()
        .filter(|variant| {
            matches!(
                variant,
                nested::InternalCircuitIndex::EndoscalingStep(_)
                    | nested::InternalCircuitIndex::Export
                    | nested::InternalCircuitIndex::Collapse
                    | nested::InternalCircuitIndex::ComputeV
                    | nested::InternalCircuitIndex::Loading
            )
        })
}

#[rustfmt::skip]
#[test]
fn test_nested_circuit_constraint_counts() {
    // Every endoscaling step but the last walks four points and lays out
    // the same; the pins below are per variant.
    let steps = crate::internal::endoscalar::num_steps(nested::NUM_ENDOSCALING_POINTS);
    let mut expected = alloc::vec::Vec::new();
    for step in 0..steps {
        expected.push((nested::InternalCircuitIndex::EndoscalingStep(step as u32), (2033, 3677)));
    }
    expected.push((nested::InternalCircuitIndex::Export,   (1318, 1400)));
    expected.push((nested::InternalCircuitIndex::Collapse, (1572, 1641)));
    expected.push((nested::InternalCircuitIndex::ComputeV, (1601, 1687)));
    expected.push((nested::InternalCircuitIndex::Loading,  (752,  211)));

    let actual: alloc::vec::Vec<_> = nested_circuits()
        .map(|variant| (variant, nested_circuit_counts(variant)))
        .collect();
    assert_eq!(actual, expected, "(variant, (gates, constraints))");
}

#[rustfmt::skip]
#[test]
fn test_nested_stage_parameters() {
    use crate::internal::{endoscalar, nested::{NUM_ENDOSCALING_POINTS, stages}};
    use ragu_pasta::{EqAffine, Fq};

    macro_rules! check_stage {
        ($Stage:ty, skip = $skip:expr, num = $num:expr) => {{
            assert_eq!(<$Stage as Stage<Fq, R>>::skip_gates(), $skip, "{}: skip", stringify!($Stage));
            assert_eq!(<$Stage as StageExt<Fq, R>>::num_gates(), $num, "{}: num", stringify!($Stage));
        }};
    }

    check_stage!(endoscalar::EndoscalarStage,                          skip =   1, num =  64);
    check_stage!(endoscalar::PointsStage<EqAffine, NUM_ENDOSCALING_POINTS>, skip =  65, num = 131);
    check_stage!(stages::preamble::Stage<EqAffine, R>,                 skip = 196, num = 104);
    check_stage!(stages::s_prime::Stage<EqAffine, R>,                  skip = 300, num =   2);
    check_stage!(stages::inner_error::Stage<EqAffine, R>,              skip = 302, num = 254);
    check_stage!(stages::outer_error::Stage<EqAffine, R>,              skip = 556, num =  73);
    check_stage!(stages::ab::Stage<EqAffine, R>,                       skip = 629, num =   2);
    check_stage!(stages::query::Stage<EqAffine, R>,                    skip = 631, num =  70);
    check_stage!(stages::f::Stage<EqAffine, R>,                        skip = 701, num =   1);
    check_stage!(stages::eval::Stage<EqAffine, R>,                     skip = 702, num =  50);
    check_stage!(stages::challenges::Stage<EqAffine, R>,               skip = 752, num =  11);
    check_stage!(stages::beta::Stage<EqAffine, R>,                     skip = 763, num =   1);
}

/// Helper test to print the nested circuits' current counts and the nested
/// stage parameters, to pin in the two tests above.
/// Run with: `cargo test -p ragu_pcd --release print_nested -- --nocapture`
#[test]
fn print_nested_circuit_constraint_counts() {
    use crate::internal::{
        endoscalar,
        nested::{NUM_ENDOSCALING_POINTS, stages},
    };
    use ragu_pasta::{EqAffine, Fq};
    use std::println;

    println!("\n// Copy-paste into test_nested_circuit_constraint_counts:");
    for variant in nested_circuits() {
        let (mul, lin) = nested_circuit_counts(variant);
        println!("    {variant:?}: gates = {mul}, constraints = {lin}");
    }

    macro_rules! print_stage {
        ($name:expr, $Stage:ty) => {{
            println!(
                "    {:<12} skip = {:>3}, num = {:>3}",
                $name,
                <$Stage as Stage<Fq, R>>::skip_gates(),
                <$Stage as StageExt<Fq, R>>::num_gates()
            );
        }};
    }
    println!("\n// Copy-paste into test_nested_stage_parameters:");
    print_stage!("endoscalar", endoscalar::EndoscalarStage);
    print_stage!("points", endoscalar::PointsStage<EqAffine, NUM_ENDOSCALING_POINTS>);
    print_stage!("preamble", stages::preamble::Stage<EqAffine, R>);
    print_stage!("s_prime", stages::s_prime::Stage<EqAffine, R>);
    print_stage!("inner_error", stages::inner_error::Stage<EqAffine, R>);
    print_stage!("outer_error", stages::outer_error::Stage<EqAffine, R>);
    print_stage!("ab", stages::ab::Stage<EqAffine, R>);
    print_stage!("query", stages::query::Stage<EqAffine, R>);
    print_stage!("f", stages::f::Stage<EqAffine, R>);
    print_stage!("eval", stages::eval::Stage<EqAffine, R>);
    print_stage!("challenges", stages::challenges::Stage<EqAffine, R>);
    print_stage!("beta", stages::beta::Stage<EqAffine, R>);
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

    let expected = fp!(0x1032b1e6b974da312e49d900128772a156aa39fda91edcc6dae62004d3720f65);

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

    let expected = fq!(0x262ac3839779e06670f33689843dd3a66b7435ad935fd5123f4fe86560e63b78);

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

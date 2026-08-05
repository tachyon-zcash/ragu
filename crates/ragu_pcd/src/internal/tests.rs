use native::{
    InternalCircuitIndex, InternalCircuitValues, RevdotParameters, RxIndex, RxValues,
    stages::{eval, inner_error, outer_error, preamble, query},
};
use ragu_circuits::{
    Circuit,
    staging::{Stage, StageExt},
};
use ragu_core::pasta::{Fp, Fq, Pasta};

use super::*;
use crate::*;
pub type R = ragu_circuits::polynomials::ProductionRank;

use ragu_circuits::polynomials::Rank;
use ragu_core::{
    drivers::emulator::{Emulator, Wireless},
    gadgets::{Bound, Gadget},
    maybe::Empty,
};
use udon::field::Field;

pub fn assert_stage_values<F, R, S>(stage: &S)
where
    F: Field,
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
pub const HEADER_SIZE: usize = 103;

// Number of trivial application circuits to register before testing internal
// circuits. Internal circuit construction depends on the resulting registry
// domain size, and other tests still build an application with this many
// placeholder steps.
const NUM_APP_STEPS: usize = 6000;

fn dummy_app<'params, const HDR: usize>(
    pasta: &'params <Pasta as ragu_core::Cycle>::Params,
    steps: usize,
) -> crate::Application<'params, Pasta, R, HDR> {
    ApplicationBuilder::<Pasta, R, HDR>::new(pasta)
        .register_dummy_circuits(steps)
        .unwrap()
        .finalize()
        .unwrap()
}

// The pins below are taken at the empty hook layout, where every
// hook-dependent width collapses to what it was before hooks existed.
type P0 = <NoHooks as HookConfig>::PolyWitnesses;
type Preamble = preamble::Stage<Pasta, R, HEADER_SIZE, NoHooks>;
type OuterError = outer_error::Stage<Pasta, R, HEADER_SIZE, NoHooks, RevdotParameters>;
type InnerError = inner_error::Stage<Pasta, R, HEADER_SIZE, NoHooks, RevdotParameters>;
type Query = query::Stage<Pasta, R, HEADER_SIZE, NoHooks>;
type Eval = eval::Stage<Pasta, R, HEADER_SIZE, NoHooks>;
type Challenges =
    native::stages::challenges::Stage<Pasta, R, HEADER_SIZE, NoHooks, RevdotParameters>;
type NestedCurve = <Pasta as ragu_core::Cycle>::NestedCurve;
type PointsBinding = native::stages::points::BindingStage<NestedCurve>;
type PointsChildren = native::stages::points::ChildrenStage<NestedCurve, P0>;
type PointsRegistryWx = native::stages::points::RegistryWxStage<NestedCurve, P0>;
type PointsAb = native::stages::points::AbStage<NestedCurve, P0>;
type PointsF = native::stages::points::FStage<NestedCurve, P0>;
type PointsWalk = native::stages::points::WalkStage<NestedCurve, P0>;

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
    let pasta = crate::pasta::baked();
    let (_, log2_circuits) = native::total_circuit_counts(NUM_APP_STEPS, 0);
    match variant {
        InternalCircuitIndex::Hashes1Circuit => counts(native::circuits::hashes_1::Circuit::<
            Pasta,
            R,
            HEADER_SIZE,
            NoHooks,
            RevdotParameters,
        >::new(pasta, log2_circuits)),
        InternalCircuitIndex::Hashes2Circuit => counts(native::circuits::hashes_2::Circuit::<
            Pasta,
            R,
            HEADER_SIZE,
            NoHooks,
            RevdotParameters,
        >::new(pasta)),
        InternalCircuitIndex::InnerCollapseCircuit => {
            counts(native::circuits::inner_collapse::Circuit::<
                Pasta,
                R,
                HEADER_SIZE,
                NoHooks,
                RevdotParameters,
            >::new())
        }
        InternalCircuitIndex::OuterCollapseCircuit => {
            counts(native::circuits::outer_collapse::Circuit::<
                Pasta,
                R,
                HEADER_SIZE,
                NoHooks,
                RevdotParameters,
            >::new())
        }
        InternalCircuitIndex::ComputeVCircuit => counts(native::circuits::compute_v::Circuit::<
            Pasta,
            R,
            HEADER_SIZE,
            NoHooks,
        >::new()),
        InternalCircuitIndex::ChallengeBindingCircuit => {
            counts(native::circuits::challenge_binding::Circuit::<
                Pasta,
                R,
                HEADER_SIZE,
                NoHooks,
            >::new(pasta))
        }
        InternalCircuitIndex::BindChallengesCircuit(k) => {
            crate::with_binder!(k, Pasta, R, HEADER_SIZE, NoHooks, pasta, |circuit| counts(
                circuit
            ))
        }
        InternalCircuitIndex::BindBetaCircuit => counts(native::circuits::bind_beta::Circuit::<
            Pasta,
            R,
            HEADER_SIZE,
            NoHooks,
            RevdotParameters,
        >::new(pasta)),
        InternalCircuitIndex::BindEndoscalarCircuit => {
            counts(native::circuits::bind_endoscalar::Circuit::<
                Pasta,
                R,
                NoHooks,
            >::new())
        }
        InternalCircuitIndex::EndoscalingStep(step) => {
            counts(native::circuits::endoscaling_step::Circuit::<
                Pasta,
                R,
                NoHooks,
            >::new(step as usize))
        }
        _ => panic!("constraint counts only apply to internal circuits"),
    }
}

fn internal_circuit_counts(variant: InternalCircuitIndex) -> (usize, usize) {
    let pasta = crate::pasta::baked();
    let (_, log2_circuits) = native::total_circuit_counts(NUM_APP_STEPS, 0);

    match variant {
        InternalCircuitIndex::Hashes1Circuit => {
            synthesis_counts(native::circuits::hashes_1::Circuit::<
                Pasta,
                R,
                HEADER_SIZE,
                NoHooks,
                RevdotParameters,
            >::new(pasta, log2_circuits))
        }
        InternalCircuitIndex::Hashes2Circuit => {
            synthesis_counts(native::circuits::hashes_2::Circuit::<
                Pasta,
                R,
                HEADER_SIZE,
                NoHooks,
                RevdotParameters,
            >::new(pasta))
        }
        InternalCircuitIndex::InnerCollapseCircuit => {
            synthesis_counts(native::circuits::inner_collapse::Circuit::<
                Pasta,
                R,
                HEADER_SIZE,
                NoHooks,
                RevdotParameters,
            >::new())
        }
        InternalCircuitIndex::OuterCollapseCircuit => {
            synthesis_counts(native::circuits::outer_collapse::Circuit::<
                Pasta,
                R,
                HEADER_SIZE,
                NoHooks,
                RevdotParameters,
            >::new())
        }
        InternalCircuitIndex::ComputeVCircuit => {
            synthesis_counts(native::circuits::compute_v::Circuit::<
                Pasta,
                R,
                HEADER_SIZE,
                NoHooks,
            >::new())
        }
        InternalCircuitIndex::ChallengeBindingCircuit => {
            synthesis_counts(native::circuits::challenge_binding::Circuit::<
                Pasta,
                R,
                HEADER_SIZE,
                NoHooks,
            >::new(pasta))
        }
        InternalCircuitIndex::BindChallengesCircuit(k) => {
            let pasta = crate::pasta::baked();
            crate::with_binder!(k, Pasta, R, HEADER_SIZE, NoHooks, pasta, |circuit| {
                synthesis_counts(circuit)
            })
        }
        InternalCircuitIndex::BindBetaCircuit => {
            synthesis_counts(native::circuits::bind_beta::Circuit::<
                Pasta,
                R,
                HEADER_SIZE,
                NoHooks,
                RevdotParameters,
            >::new(crate::pasta::baked()))
        }
        InternalCircuitIndex::BindEndoscalarCircuit => {
            synthesis_counts(native::circuits::bind_endoscalar::Circuit::<
                Pasta,
                R,
                NoHooks,
            >::new())
        }
        InternalCircuitIndex::EndoscalingStep(step) => {
            synthesis_counts(native::circuits::endoscaling_step::Circuit::<
                Pasta,
                R,
                NoHooks,
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

    check_constraints!(Hashes1Circuit,              mul = 1992, lin = 3095);
    check_constraints!(Hashes2Circuit,              mul = 2044, lin = 2986);
    check_constraints!(InnerCollapseCircuit,        mul = 1921, lin = 1953);
    check_constraints!(OuterCollapseCircuit,        mul = 1592, lin = 2081);
    check_constraints!(ComputeVCircuit,             mul = 1862, lin = 2733);
    check_constraints!(ChallengeBindingCircuit,     mul = 608,  lin = 106);
    check_constraints!(BindChallengesCircuit(0),    mul = 1985, lin = 2956);
    check_constraints!(BindChallengesCircuit(1),    mul = 1990, lin = 2966);
    check_constraints!(BindChallengesCircuit(2),    mul = 1990, lin = 2966);
    check_constraints!(BindChallengesCircuit(3),    mul = 1990, lin = 2966);
    check_constraints!(BindChallengesCircuit(4),    mul = 2001, lin = 2988);
    check_constraints!(BindBetaCircuit,             mul = 2029, lin = 3016);
    check_constraints!(BindEndoscalarCircuit,       mul = 788,  lin = 1458);
    // The nested batch has one point more than a multiple of four, so every
    // native endoscaling step walks four points and lays out the same.
    for step in 0..native::num_endoscaling_steps(0) as u32 {
        check_constraints!(EndoscalingStep(step),   mul = 2028, lin = 3678);
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

    check_stage!(PointsBinding,    skip =   1, num =  26);
    check_stage!(Preamble,         skip =  27, num = 349);
    check_stage!(OuterError,       skip = 376, num = 186);
    check_stage!(InnerError,       skip = 562, num = 399);
    check_stage!(Query,            skip = 376, num =  84);
    check_stage!(Eval,             skip = 460, num =  62);
    check_stage!(Challenges,       skip = 562, num =   0);
    check_stage!(PointsChildren,   skip =  27, num =  68);
    check_stage!(PointsRegistryWx, skip =  95, num =   2);
    check_stage!(PointsAb,         skip =  97, num =   3);
    check_stage!(PointsF,          skip = 100, num =   2);
    check_stage!(PointsWalk,       skip = 102, num =  89);
}

/// The stage chain at eight witnessed polynomials, one poly-query and one
/// two-wide derived challenge, where every hook-dependent width is visible:
/// the preamble's hook regions, the challenges stage, the eval stage's
/// evaluations, and the walks the extra points lengthen.
mod hooked_chain {
    use super::{HEADER_SIZE, NestedCurve, R};
    use crate::{
        AppHooks, HookConfig,
        internal::native::{RevdotParameters, stages},
    };

    type J = AppHooks<8, 1, 1, 2>;
    type L = <J as HookConfig>::PolyWitnesses;

    pub type Preamble = stages::preamble::Stage<ragu_core::pasta::Pasta, R, HEADER_SIZE, J>;
    pub type OuterError =
        stages::outer_error::Stage<ragu_core::pasta::Pasta, R, HEADER_SIZE, J, RevdotParameters>;
    pub type InnerError =
        stages::inner_error::Stage<ragu_core::pasta::Pasta, R, HEADER_SIZE, J, RevdotParameters>;
    pub type Query = stages::query::Stage<ragu_core::pasta::Pasta, R, HEADER_SIZE, J>;
    pub type Eval = stages::eval::Stage<ragu_core::pasta::Pasta, R, HEADER_SIZE, J>;
    pub type Challenges =
        stages::challenges::Stage<ragu_core::pasta::Pasta, R, HEADER_SIZE, J, RevdotParameters>;
    pub type PointsChildren = stages::points::ChildrenStage<NestedCurve, L>;
    pub type PointsWalk = stages::points::WalkStage<NestedCurve, L>;
}

#[rustfmt::skip]
#[test]
fn test_hooked_stage_parameters() {
    macro_rules! check_stage {
        ($Stage:ty, skip = $skip:expr, num = $num:expr) => {{
            assert_eq!(<$Stage as Stage<Fp, R>>::skip_gates(), $skip, "{}: skip", stringify!($Stage));
            assert_eq!(<$Stage as StageExt<Fp, R>>::num_gates(), $num, "{}: num", stringify!($Stage));
        }};
    }

    check_stage!(hooked_chain::Preamble,       skip =  27, num = 369);
    check_stage!(hooked_chain::OuterError,     skip = 396, num = 186);
    check_stage!(hooked_chain::InnerError,     skip = 582, num = 399);
    check_stage!(hooked_chain::Query,          skip = 396, num =  89);
    check_stage!(hooked_chain::Eval,           skip = 485, num =  73);
    check_stage!(hooked_chain::Challenges,     skip = 582, num =   3);
    check_stage!(hooked_chain::PointsChildren, skip =  27, num =  80);
    check_stage!(hooked_chain::PointsWalk,     skip = 114, num =  92);
}

/// Helper test to print current constraint counts in copy-pasteable format.
/// Run with: `cargo test -p ragu_pcd --release print_internal_circuit -- --nocapture`
#[test]
fn print_internal_circuit_constraint_counts() {
    use alloc::format;
    use std::println;

    let variants = InternalCircuitIndex::all(0).filter(|variant| {
        !matches!(
            variant,
            InternalCircuitIndex::PreambleStage
                | InternalCircuitIndex::InnerErrorStage
                | InternalCircuitIndex::OuterErrorStage
                | InternalCircuitIndex::QueryStage
                | InternalCircuitIndex::EvalStage
                | InternalCircuitIndex::ChallengesStage
                | InternalCircuitIndex::PointsBindingStage
                | InternalCircuitIndex::PointsChildrenStage
                | InternalCircuitIndex::PointsRegistryWxStage
                | InternalCircuitIndex::PointsAbStage
                | InternalCircuitIndex::PointsFStage
                | InternalCircuitIndex::PointsWalkStage
                | InternalCircuitIndex::InnerErrorFinalStaged
                | InternalCircuitIndex::OuterErrorFinalStaged
                | InternalCircuitIndex::EvalFinalStaged
                | InternalCircuitIndex::ChallengesFinalStaged
                | InternalCircuitIndex::PointsWalkFinalStaged
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
    print_stage!(PointsBinding);
    print_stage!(Preamble);
    print_stage!(OuterError);
    print_stage!(InnerError);
    print_stage!(Query);
    print_stage!(Eval);
    print_stage!(Challenges);
    print_stage!(PointsChildren);
    print_stage!(PointsRegistryWx);
    print_stage!(PointsAb);
    print_stage!(PointsF);
    print_stage!(PointsWalk);

    println!("\n// Copy-paste the following into test_hooked_stage_parameters:");
    print_stage!(hooked_chain::Preamble);
    print_stage!(hooked_chain::OuterError);
    print_stage!(hooked_chain::InnerError);
    print_stage!(hooked_chain::Query);
    print_stage!(hooked_chain::Eval);
    print_stage!(hooked_chain::Challenges);
    print_stage!(hooked_chain::PointsChildren);
    print_stage!(hooked_chain::PointsWalk);
}

/// The nested circuits' gate and constraint counts, by [`nested::InternalCircuitIndex`].
///
/// # Panics
///
/// Panics for the bonding entries, which are masks rather than circuits.
fn nested_circuit_counts(variant: nested::InternalCircuitIndex) -> (usize, usize) {
    use ragu_circuits::staging::MultiStage;
    use ragu_core::pasta::EqAffine;

    fn counts(circuit: impl Circuit<ragu_core::pasta::Fq>) -> (usize, usize) {
        let counts = ragu_circuits::testing::synthesis_counts(&circuit).unwrap();
        (counts.num_gates, counts.num_constraints)
    }
    match variant {
        nested::InternalCircuitIndex::EndoscalingStep(step) => counts(MultiStage::new(
            nested::EndoscalingStep::<EqAffine, R, P0>::new(step as usize),
        )),
        nested::InternalCircuitIndex::Export => {
            counts(MultiStage::new(nested::circuits::export::Circuit::<
                EqAffine,
                R,
                P0,
            >::new()))
        }
        nested::InternalCircuitIndex::Collapse => {
            counts(MultiStage::new(nested::circuits::collapse::Circuit::<
                EqAffine,
                R,
                P0,
            >::new()))
        }
        nested::InternalCircuitIndex::ComputeV => {
            counts(MultiStage::new(nested::circuits::compute_v::Circuit::<
                EqAffine,
                R,
                P0,
            >::new()))
        }
        nested::InternalCircuitIndex::Loading => {
            counts(MultiStage::new(nested::circuits::loading::Circuit::<
                EqAffine,
                R,
                P0,
            >::new()))
        }
        _ => panic!("constraint counts only apply to nested circuits"),
    }
}

/// The nested circuits [`nested_circuit_counts`] covers, in
/// [`nested::InternalCircuitIndex::all`] order.
fn nested_circuits() -> impl Iterator<Item = nested::InternalCircuitIndex> {
    nested::InternalCircuitIndex::all(0).filter(|variant| {
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
    // The native batch has one point more than a multiple of four, so every
    // endoscaling step walks four points and lays out the same; the pins
    // below are per variant.
    let steps = crate::internal::endoscalar::num_steps::<{ nested::ENDOSCALINGS_PER_STEP }>(
        nested::num_endoscaling_points(0),
    );
    let mut expected = alloc::vec::Vec::new();
    for step in 0..steps {
        expected.push((nested::InternalCircuitIndex::EndoscalingStep(step as u32), (2048, 3677)));
    }
    expected.push((nested::InternalCircuitIndex::Export,   (1415, 1550)));
    expected.push((nested::InternalCircuitIndex::Collapse, (1644, 1716)));
    expected.push((nested::InternalCircuitIndex::ComputeV, (1688, 1792)));
    expected.push((nested::InternalCircuitIndex::Loading,  (789,  235)));

    let actual: alloc::vec::Vec<_> = nested_circuits()
        .map(|variant| (variant, nested_circuit_counts(variant)))
        .collect();
    assert_eq!(actual, expected, "(variant, (gates, constraints))");
}

#[rustfmt::skip]
#[test]
fn test_nested_stage_parameters() {
    use crate::internal::{endoscalar, nested::stages};
    use ragu_core::pasta::{EqAffine, Fq};

    macro_rules! check_stage {
        ($Stage:ty, skip = $skip:expr, num = $num:expr) => {{
            assert_eq!(<$Stage as Stage<Fq, R>>::skip_gates(), $skip, "{}: skip", stringify!($Stage));
            assert_eq!(<$Stage as StageExt<Fq, R>>::num_gates(), $num, "{}: num", stringify!($Stage));
        }};
    }

    check_stage!(endoscalar::EndoscalarStage,                          skip =   1, num =  64);
    check_stage!(nested::PointsStage<EqAffine, P0>,                        skip =  65, num = 146);
    check_stage!(stages::preamble::Stage<EqAffine, R, P0>,                 skip = 211, num = 119);
    check_stage!(stages::s_prime::Stage<EqAffine, R, P0>,                  skip = 330, num =   3);
    check_stage!(stages::inner_error::Stage<EqAffine, R, P0>,              skip = 333, num = 254);
    check_stage!(stages::outer_error::Stage<EqAffine, R, P0>,              skip = 587, num =  73);
    check_stage!(stages::ab::Stage<EqAffine, R, P0>,                       skip = 660, num =   3);
    check_stage!(stages::query::Stage<EqAffine, R, P0>,                    skip = 663, num =  73);
    check_stage!(stages::f::Stage<EqAffine, R, P0>,                        skip = 736, num =   2);
    check_stage!(stages::eval::Stage<EqAffine, R, P0>,                     skip = 738, num =  51);
    check_stage!(stages::challenges::Stage<EqAffine, R, P0>,               skip = 789, num =  12);
}

/// Helper test to print the nested circuits' current counts and the nested
/// stage parameters, to pin in the two tests above.
/// Run with: `cargo test -p ragu_pcd --release print_nested -- --nocapture`
#[test]
fn print_nested_circuit_constraint_counts() {
    use std::println;

    use ragu_core::pasta::{EqAffine, Fq};

    use crate::internal::{endoscalar, nested::stages};

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
    print_stage!("points", nested::PointsStage<EqAffine, P0>);
    print_stage!("preamble", stages::preamble::Stage<EqAffine, R, P0>);
    print_stage!("s_prime", stages::s_prime::Stage<EqAffine, R, P0>);
    print_stage!("inner_error", stages::inner_error::Stage<EqAffine, R, P0>);
    print_stage!("outer_error", stages::outer_error::Stage<EqAffine, R, P0>);
    print_stage!("ab", stages::ab::Stage<EqAffine, R, P0>);
    print_stage!("query", stages::query::Stage<EqAffine, R, P0>);
    print_stage!("f", stages::f::Stage<EqAffine, R, P0>);
    print_stage!("eval", stages::eval::Stage<EqAffine, R, P0>);
    print_stage!("challenges", stages::challenges::Stage<EqAffine, R, P0>);
}

/// Checks that only step slots can satisfy an application instance.
///
/// The application `circuit_id` is only checked for registry-domain
/// membership, so a prover may point it at any native slot. Every slot other
/// than a step must fail an application instance for every trace. Stage masks
/// and unassigned slots fail on the constant term: their wiring polynomial has
/// no `ONE` row. Internal circuits fail on the linear term: their last public
/// output is the zero suffix appended by the unified output builder, so that
/// row has no wires and contributes zero for every trace, while an application
/// instance's linear coefficient is its output header suffix, which is never
/// zero.
#[test]
fn test_non_step_slots_reject_application_instances() {
    use alloc::{format, string::String, vec::Vec};

    use ragu_circuits::registry::CircuitIndex;
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use udon::field::Field;

    let app = ApplicationBuilder::<Pasta, R, HEADER_SIZE>::new(crate::pasta::baked())
        .finalize()
        .unwrap();
    let registry = &app.native_registry;
    let x = Fp::random(|bytes| StdRng::seed_from_u64(0).fill_bytes(bytes));

    let steps = InternalCircuitIndex::num(0)..registry.num_circuits();
    let unprotected: Vec<String> = (0..registry.num_circuits().next_power_of_two())
        .filter(|slot| !steps.contains(slot))
        .filter(|&slot| {
            let sx = registry.wx(CircuitIndex::new(slot).omega_j(), x);
            let mut coeffs = sx.iter_coeffs();
            let constant = coeffs.next().unwrap();
            let linear = coeffs.next().unwrap();
            constant != Fp::ZERO && linear != Fp::ZERO
        })
        .map(|slot| match InternalCircuitIndex::all(0).nth(slot) {
            Some(id) => format!("{id:?}"),
            None => format!("slot {slot}"),
        })
        .collect();

    assert!(
        unprotected.is_empty(),
        "non-step slots that can satisfy an application instance: {unprotected:?}"
    );
}

#[test]
fn supplied_tags_reach_both_registries() -> Result<()> {
    let tags = RegistryTags::<Pasta>::from_beacon(&[0x42; 32], &[0x24; 20]);
    let native = tags.native.value();
    let nested = tags.nested.value();
    let app = ApplicationBuilder::<Pasta, R, 4>::new(crate::pasta::baked())
        .with_registry_tags(tags)
        .finalize()?;
    assert_eq!(app.native_registry.tag(), native);
    assert_eq!(app.nested_registry.tag(), nested);
    Ok(())
}

/// Verifies the native registry uses the fixed tag enabled by the testing feature.
#[test]
fn test_native_registry_tag() {
    let pasta = crate::pasta::baked();

    let app = dummy_app::<HEADER_SIZE>(pasta, NUM_APP_STEPS);

    let expected = Fp::new(udon::fp_hex!(
        "0x247e382a1523800d0fc7bccd9b0e1e57eecd7a9758c4b7537f4ed76f5f54fe43"
    ));

    assert_eq!(
        app.native_registry.tag(),
        expected,
        "Native registry tag changed unexpectedly!"
    );
}

/// Verifies the nested registry uses the fixed tag enabled by the testing feature.
#[test]
fn test_nested_registry_tag() {
    let pasta = crate::pasta::baked();

    let app = dummy_app::<HEADER_SIZE>(pasta, NUM_APP_STEPS);

    let expected = Fq::new(udon::fq_hex!(
        "0x009ad8ef87fe4e7dc6e51df8807db0f783f39978e29787ab3e00a28c15d2bdbd"
    ));

    assert_eq!(
        app.nested_registry.tag(),
        expected,
        "Nested registry tag changed unexpectedly!"
    );
}

/// Helper test to print current registry tags in copy-pasteable format.
/// Run with: `cargo test -p ragu_pcd --release print_registry_tags -- --nocapture`
#[test]
fn print_registry_tags() {
    use alloc::{format, string::String, vec::Vec};
    use std::println;

    let pasta = crate::pasta::baked();

    let app = dummy_app::<HEADER_SIZE>(pasta, NUM_APP_STEPS);

    let native_tag = app.native_registry.tag();
    let nested_tag = app.nested_registry.tag();

    // Convert to big-endian hex for repr256! format
    let native_bytes: Vec<u8> = native_tag
        .to_bytes()
        .as_ref()
        .iter()
        .rev()
        .cloned()
        .collect();
    let nested_bytes: Vec<u8> = nested_tag
        .to_bytes()
        .as_ref()
        .iter()
        .rev()
        .cloned()
        .collect();

    println!("\n// Copy-paste the following into the registry tag tests:");
    println!(
        "    let expected = Fp::new(fp_hex!(\"0x{}\"));",
        native_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
    println!(
        "    let expected = Fq::new(fq_hex!(\"0x{}\"));",
        nested_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
}

#[test]
fn test_internal_circuit_index_all_exhaustive() {
    let mut collected = alloc::vec::Vec::new();
    for polys in [0, 4, 8] {
        collected.clear();
        let _values = InternalCircuitValues::from_fn(polys, |id| {
            collected.push(id);
        });
        let all: alloc::vec::Vec<_> = InternalCircuitIndex::all(polys).collect();
        assert_eq!(collected, all);
        assert_eq!(all.len(), InternalCircuitIndex::num(polys));
    }
}

#[test]
fn test_rx_index_all_exhaustive() {
    let mut collected = alloc::vec::Vec::new();
    for polys in [0, 4, 8] {
        collected.clear();
        let _values = RxValues::from_fn(polys, |id| {
            collected.push(id);
        });
        let all: alloc::vec::Vec<_> = RxIndex::all(polys).collect();
        assert_eq!(collected, all);
        assert_eq!(all.len(), RxIndex::num(polys));
    }
}

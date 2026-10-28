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

type Preamble = preamble::Stage<Pasta, R, HEADER_SIZE>;
type OuterError =
    outer_error::Stage<Pasta, R, HEADER_SIZE, RevdotParameters<crate::profile::Standard>>;
type InnerError =
    inner_error::Stage<Pasta, R, HEADER_SIZE, RevdotParameters<crate::profile::Standard>>;
type Query = query::Stage<Pasta, R, HEADER_SIZE>;
type Eval = eval::Stage<Pasta, R, HEADER_SIZE>;
type NestedCurve = <Pasta as ragu_core::Cycle>::NestedCurve;
type PointsBinding = native::stages::points::BindingStage<NestedCurve, crate::profile::Standard>;
type PointsChildren = native::stages::points::ChildrenStage<NestedCurve, crate::profile::Standard>;
type PointsRegistryWx =
    native::stages::points::RegistryWxStage<NestedCurve, crate::profile::Standard>;
type PointsAb = native::stages::points::AbStage<NestedCurve, crate::profile::Standard>;
type PointsF = native::stages::points::FStage<NestedCurve, crate::profile::Standard>;
type PointsWalk = native::stages::points::WalkStage<NestedCurve, crate::profile::Standard>;

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
    let (_, log2_circuits) =
        native::total_circuit_counts::<crate::profile::Standard>(NUM_APP_STEPS);
    match variant {
        InternalCircuitIndex::Hashes1Circuit => counts(native::circuits::hashes_1::Circuit::<
            Pasta,
            R,
            HEADER_SIZE,
            RevdotParameters<crate::profile::Standard>,
        >::new(pasta, log2_circuits)),
        InternalCircuitIndex::Hashes2Circuit => counts(native::circuits::hashes_2::Circuit::<
            Pasta,
            R,
            HEADER_SIZE,
            RevdotParameters<crate::profile::Standard>,
        >::new(pasta)),
        InternalCircuitIndex::InnerCollapseCircuit => {
            counts(native::circuits::inner_collapse::Circuit::<
                Pasta,
                R,
                HEADER_SIZE,
                RevdotParameters<crate::profile::Standard>,
            >::new())
        }
        InternalCircuitIndex::OuterCollapseCircuit => {
            counts(native::circuits::outer_collapse::Circuit::<
                Pasta,
                R,
                HEADER_SIZE,
                RevdotParameters<crate::profile::Standard>,
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
            RevdotParameters<crate::profile::Standard>,
        >::new(pasta)),
        InternalCircuitIndex::BindEndoscalarCircuit => {
            counts(native::circuits::bind_endoscalar::Circuit::<Pasta, R>::new())
        }
        InternalCircuitIndex::EndoscalingStep(step) => {
            counts(native::circuits::endoscaling_step::Circuit::<Pasta, R>::new(step as usize))
        }
        _ => panic!("constraint counts only apply to internal circuits"),
    }
}

fn internal_circuit_counts(variant: InternalCircuitIndex) -> (usize, usize) {
    let pasta = crate::pasta::baked();
    let (_, log2_circuits) =
        native::total_circuit_counts::<crate::profile::Standard>(NUM_APP_STEPS);

    match variant {
        InternalCircuitIndex::Hashes1Circuit => {
            synthesis_counts(native::circuits::hashes_1::Circuit::<
                Pasta,
                R,
                HEADER_SIZE,
                RevdotParameters<crate::profile::Standard>,
            >::new(pasta, log2_circuits))
        }
        InternalCircuitIndex::Hashes2Circuit => {
            synthesis_counts(native::circuits::hashes_2::Circuit::<
                Pasta,
                R,
                HEADER_SIZE,
                RevdotParameters<crate::profile::Standard>,
            >::new(pasta))
        }
        InternalCircuitIndex::InnerCollapseCircuit => {
            synthesis_counts(native::circuits::inner_collapse::Circuit::<
                Pasta,
                R,
                HEADER_SIZE,
                RevdotParameters<crate::profile::Standard>,
            >::new())
        }
        InternalCircuitIndex::OuterCollapseCircuit => {
            synthesis_counts(native::circuits::outer_collapse::Circuit::<
                Pasta,
                R,
                HEADER_SIZE,
                RevdotParameters<crate::profile::Standard>,
            >::new())
        }
        InternalCircuitIndex::ComputeVCircuit => {
            synthesis_counts(native::circuits::compute_v::Circuit::<Pasta, R, HEADER_SIZE>::new())
        }
        InternalCircuitIndex::BindChallengesCircuit(k) => {
            crate::with_binder!(k, Pasta, R, HEADER_SIZE, crate::pasta::baked(), |circuit| {
                synthesis_counts(circuit)
            })
        }
        InternalCircuitIndex::BindBetaCircuit => {
            synthesis_counts(native::circuits::bind_beta::Circuit::<
                Pasta,
                R,
                HEADER_SIZE,
                RevdotParameters<crate::profile::Standard>,
            >::new(crate::pasta::baked()))
        }
        InternalCircuitIndex::BindEndoscalarCircuit => {
            synthesis_counts(native::circuits::bind_endoscalar::Circuit::<Pasta, R>::new())
        }
        InternalCircuitIndex::EndoscalingStep(step) => synthesis_counts(
            native::circuits::endoscaling_step::Circuit::<Pasta, R>::new(step as usize),
        ),
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

    check_constraints!(Hashes1Circuit, mul = 1818, lin = 3085);
    check_constraints!(Hashes2Circuit, mul = 1875, lin = 2984);
    check_constraints!(InnerCollapseCircuit, mul = 678, lin = 514);
    check_constraints!(OuterCollapseCircuit, mul = 1124, lin = 1483);
    check_constraints!(ComputeVCircuit, mul = 1853, lin = 2739);
    check_constraints!(BindBetaCircuit, mul = 1860, lin = 3014);

    check_constraints!(BindChallengesCircuit(0), mul = 1972, lin = 2954);
    check_constraints!(BindChallengesCircuit(1), mul = 1977, lin = 2964);
    check_constraints!(BindChallengesCircuit(2), mul = 1977, lin = 2964);
    check_constraints!(BindChallengesCircuit(3), mul = 1988, lin = 2986);
    check_constraints!(BindEndoscalarCircuit, mul = 771, lin = 1428);
    // Every native endoscaling step walks four points.
    for step in 0..native::NUM_ENDOSCALING_STEPS as u32 {
        check_constraints!(EndoscalingStep(step), mul = 2023, lin = 3678);
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

    check_stage!(PointsBinding, skip = 1, num = 26);
    check_stage!(Preamble, skip = 27, num = 347);
    check_stage!(OuterError, skip = 374, num = 19);
    check_stage!(InnerError, skip = 393, num = 42);
    check_stage!(Query, skip = 374, num = 78);
    check_stage!(Eval, skip = 452, num = 57);
    check_stage!(PointsChildren, skip = 27, num = 64);
    check_stage!(PointsRegistryWx, skip = 91, num = 2);
    check_stage!(PointsAb, skip = 93, num = 3);
    check_stage!(PointsF, skip = 96, num = 2);
    check_stage!(PointsWalk, skip = 98, num = 88);
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
                | InternalCircuitIndex::PointsBindingStage
                | InternalCircuitIndex::PointsChildrenStage
                | InternalCircuitIndex::PointsRegistryWxStage
                | InternalCircuitIndex::PointsAbStage
                | InternalCircuitIndex::PointsFStage
                | InternalCircuitIndex::PointsWalkStage
                | InternalCircuitIndex::InnerErrorFinalStaged
                | InternalCircuitIndex::OuterErrorFinalStaged
                | InternalCircuitIndex::EvalFinalStaged
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
    print_stage!(PointsChildren);
    print_stage!(PointsRegistryWx);
    print_stage!(PointsAb);
    print_stage!(PointsF);
    print_stage!(PointsWalk);
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
        nested::InternalCircuitIndex::EndoscalingStep(step) => {
            counts(MultiStage::new(nested::EndoscalingStep::<
                EqAffine,
                R,
                crate::profile::Standard,
            >::new(step as usize)))
        }
        nested::InternalCircuitIndex::Export => {
            counts(MultiStage::new(nested::circuits::export::Circuit::<
                EqAffine,
                R,
                crate::profile::Standard,
            >::new()))
        }
        nested::InternalCircuitIndex::Collapse => {
            counts(MultiStage::new(nested::circuits::collapse::Circuit::<
                EqAffine,
                R,
                crate::profile::Standard,
            >::new()))
        }
        nested::InternalCircuitIndex::ComputeV => {
            counts(MultiStage::new(nested::circuits::compute_v::Circuit::<
                EqAffine,
                R,
                crate::profile::Standard,
            >::new()))
        }
        nested::InternalCircuitIndex::Loading => {
            counts(MultiStage::new(nested::circuits::loading::Circuit::<
                EqAffine,
                R,
                crate::profile::Standard,
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
    // Every nested endoscaling step walks four points and has the same layout.
    let steps = crate::internal::endoscalar::num_steps(
        nested::ENDOSCALINGS_PER_STEP,
        nested::NUM_ENDOSCALING_POINTS,
    );
    let mut expected = alloc::vec::Vec::new();
    for step in 0..steps {
        let counts = (2038, 3677);
        expected.push((nested::InternalCircuitIndex::EndoscalingStep(step as u32), counts));
    }
    expected.push((nested::InternalCircuitIndex::Export, (1077, 1471)));
    expected.push((nested::InternalCircuitIndex::Collapse, (822, 679)));
    expected.push((nested::InternalCircuitIndex::ComputeV, (1404, 1833)));
    expected.push((nested::InternalCircuitIndex::Loading, (486, 219)));

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

    check_stage!(endoscalar::EndoscalarStage, skip = 1, num = 64);
    check_stage!(nested::PointsStage<EqAffine, crate::profile::Standard>, skip = 65, num = 136);
    check_stage!(stages::preamble::Stage<EqAffine, R, crate::profile::Standard>, skip = 201, num = 110);
    check_stage!(stages::s_prime::Stage<EqAffine, R, crate::profile::Standard>, skip = 311, num = 3);
    check_stage!(stages::inner_error::Stage<EqAffine, R, crate::profile::Standard>, skip = 314, num = 37);
    check_stage!(stages::outer_error::Stage<EqAffine, R, crate::profile::Standard>, skip = 351, num = 11);
    check_stage!(stages::ab::Stage<EqAffine, R, crate::profile::Standard>, skip = 362, num = 3);
    check_stage!(stages::query::Stage<EqAffine, R, crate::profile::Standard>, skip = 365, num = 70);
    check_stage!(stages::f::Stage<EqAffine, R, crate::profile::Standard>, skip = 435, num = 2);
    check_stage!(stages::eval::Stage<EqAffine, R, crate::profile::Standard>, skip = 437, num = 49);
    check_stage!(stages::challenges::Stage<EqAffine, R, crate::profile::Standard>, skip = 486, num = 10);
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
    print_stage!("points", nested::PointsStage<EqAffine, crate::profile::Standard>);
    print_stage!("preamble", stages::preamble::Stage<EqAffine, R, crate::profile::Standard>);
    print_stage!("s_prime", stages::s_prime::Stage<EqAffine, R, crate::profile::Standard>);
    print_stage!("inner_error", stages::inner_error::Stage<EqAffine, R, crate::profile::Standard>);
    print_stage!("outer_error", stages::outer_error::Stage<EqAffine, R, crate::profile::Standard>);
    print_stage!("ab", stages::ab::Stage<EqAffine, R, crate::profile::Standard>);
    print_stage!("query", stages::query::Stage<EqAffine, R, crate::profile::Standard>);
    print_stage!("f", stages::f::Stage<EqAffine, R, crate::profile::Standard>);
    print_stage!("eval", stages::eval::Stage<EqAffine, R, crate::profile::Standard>);
    print_stage!("challenges", stages::challenges::Stage<EqAffine, R, crate::profile::Standard>);
}

/// Checks that only step slots can satisfy an application instance, in the
/// standard profile and in profiles with extension circuits.
///
/// The application `circuit_id` is only checked for registry-domain
/// membership, so a prover may point it at any native slot. Every slot other
/// than a step must fail an application instance for every trace. Stage masks
/// and unassigned slots fail on the constant term: their wiring polynomial has
/// no `ONE` row. Internal circuits fail on the linear term: their last public
/// output is the zero suffix appended by the unified output builder, and by
/// the circuit slot for an extension circuit, so that row has no wires and
/// contributes zero for every trace, while an application instance's linear
/// coefficient is its output header suffix, which is never zero.
#[test]
fn test_non_step_slots_reject_application_instances() {
    use alloc::{format, string::String, vec::Vec};

    use ragu_circuits::registry::CircuitIndex;
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use udon::field::Field;

    use crate::profile::{
        Profile, Profiled, ProfiledCycle,
        testing::{Crossing, CrossingBack, CrossingContext, Proving},
    };

    /// The non-step slots of `app`'s native registry that can satisfy an
    /// application instance.
    fn unprotected<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize>(
        app: &Application<'_, C, R, HEADER_SIZE>,
    ) -> Vec<String> {
        let registry = &app.native_registry;
        let x = C::CircuitField::random(|bytes| StdRng::seed_from_u64(0).fill_bytes(bytes));
        let all = InternalCircuitIndex::all::<C::Profile>();
        let steps = all.len()..registry.num_circuits();
        (0..registry.num_circuits().next_power_of_two())
            .filter(|slot| !steps.contains(slot))
            .filter(|&slot| {
                let sx = registry.wx(CircuitIndex::new(slot).omega_j(), x);
                let mut coeffs = sx.iter_coeffs();
                let constant = coeffs.next().unwrap();
                let linear = coeffs.next().unwrap();
                constant != C::CircuitField::ZERO && linear != C::CircuitField::ZERO
            })
            .map(|slot| match all.get(slot) {
                Some(id) => format!("{id:?}"),
                None => format!("slot {slot}"),
            })
            .collect()
    }

    fn check<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize>(
        app: &Application<'_, C, R, HEADER_SIZE>,
    ) {
        let unprotected = unprotected(app);
        assert!(
            unprotected.is_empty(),
            "non-step slots of {} that can satisfy an application instance: {unprotected:?}",
            C::Profile::NAME
        );
    }

    let params = crate::pasta::baked();
    check(
        &ApplicationBuilder::<Pasta, R, HEADER_SIZE>::new()
            .finalize(params)
            .unwrap(),
    );

    // Profiles with extension circuits, at the rank where they fit.
    type Wide = ragu_circuits::polynomials::R<14>;
    let params = crate::pasta::baked_aggregator();
    check(
        &ApplicationBuilder::<Profiled<Pasta, Proving>, Wide, 4>::new()
            .finalize(params)
            .unwrap(),
    );
    let context = || CrossingContext {
        params,
        native: [true; 4],
        nested: [true; 4],
    };
    check(
        &ApplicationBuilder::<Profiled<Pasta, Crossing>, Wide, 4>::new()
            .finalize_with(params, context())
            .unwrap(),
    );
    check(
        &ApplicationBuilder::<Profiled<Pasta, CrossingBack>, Wide, 4>::new()
            .finalize_with(params, context())
            .unwrap(),
    );
}

#[test]
fn supplied_tags_reach_both_registries() -> Result<()> {
    let tags = RegistryTags::<Pasta>::from_beacon(&[0x42; 32], &[0x24; 20]);
    let native = tags.native.value();
    let nested = tags.nested.value();
    let app = ApplicationBuilder::<Pasta, R, 4>::new()
        .with_registry_tags(tags, &[0x24; 20])?
        .finalize(crate::pasta::baked())?;
    assert_eq!(app.native_registry.tag(), native);
    assert_eq!(app.nested_registry.tag(), nested);
    Ok(())
}

/// Verifies the native registry uses the fixed tag enabled by the testing feature.
#[test]
fn test_native_registry_tag() {
    let pasta = crate::pasta::baked();

    let app = ApplicationBuilder::<Pasta, R, HEADER_SIZE>::new()
        .register_dummy_circuits(NUM_APP_STEPS)
        .unwrap()
        .finalize(pasta)
        .unwrap();

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

    let app = ApplicationBuilder::<Pasta, R, HEADER_SIZE>::new()
        .register_dummy_circuits(NUM_APP_STEPS)
        .unwrap()
        .finalize(pasta)
        .unwrap();

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

    let app = ApplicationBuilder::<Pasta, R, HEADER_SIZE>::new()
        .register_dummy_circuits(NUM_APP_STEPS)
        .unwrap()
        .finalize(pasta)
        .unwrap();

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
    let _values = InternalCircuitValues::<_, crate::profile::Standard>::from_fn(|id| {
        collected.push(id);
    });
    assert_eq!(collected.as_slice(), InternalCircuitIndex::ALL);
}

#[test]
fn test_rx_index_all_exhaustive() {
    let mut collected = alloc::vec::Vec::new();
    let _values = RxValues::<_, crate::profile::Standard>::from_fn(|id| {
        collected.push(id);
    });
    assert_eq!(collected.as_slice(), RxIndex::ALL);
}

/// The actual container fields reject every length other than their profile's.
#[test]
fn test_values_shapes_follow_the_profile() {
    use alloc::vec;

    use ragu_primitives::vec::{FixedVec, Len};

    use crate::profile::{Standard, testing::Wider};

    fn rejects_other_lengths<L: Len>(values: &FixedVec<(), L>) {
        for length in [values.len().saturating_sub(1), values.len() + 1] {
            if length != values.len() {
                assert!(matches!(FixedVec::<(), L>::new(vec![(); length]),
                    Err(Error::VectorLengthMismatch { expected, actual })
                    if expected == values.len() && actual == length));
            }
        }
    }
    fn check<P: crate::profile::Profile>() {
        let internal = InternalCircuitValues::<_, P>::from_fn(|_| ());
        rejects_other_lengths(&internal.endoscaling_step_circuits);
        rejects_other_lengths(&internal.extension_circuits);
        rejects_other_lengths(&internal.extension_bondings);
        let rx = RxValues::<_, P>::from_fn(|_| ());
        rejects_other_lengths(&rx.endoscaling_steps);
        rejects_other_lengths(&rx.extension_circuits);
        rejects_other_lengths(&rx.extension_stages);
    }
    check::<Standard>();
    check::<Wider>();
}

/// The generic lists resize the constant ones, so in the standard profile
/// they are the constant ones.
#[test]
fn test_standard_lists_are_the_constants() {
    use crate::profile::Standard;
    assert_eq!(
        InternalCircuitIndex::all::<Standard>(),
        InternalCircuitIndex::ALL
    );
    assert_eq!(RxIndex::all::<Standard>(), RxIndex::ALL);
    assert_eq!(
        nested::InternalCircuitIndex::all::<Standard>(),
        nested::InternalCircuitIndex::ALL
    );
    assert_eq!(nested::RxIndex::all::<Standard>(), nested::RxIndex::ALL);
}

/// An extension circuit's claim takes its rx and the stages it loads per
/// proof, an extension stage's bonding its rx across proofs, and a final
/// mask's the circuits it names, with the circuits' $k(y)$ one but the
/// statement and binding circuits', which take their own values at their
/// circuits on either side; and the inner collapse claim loads the binding
/// stage for a profile whose native extension binds.
#[test]
fn test_extension_claims_follow_the_declaration() {
    use alloc::vec::Vec;

    use ragu_circuits::registry::CircuitIndex;
    use ragu_primitives::vec::Len;

    use crate::{
        internal::{
            claims::Source,
            native::{
                RxComponent::{self, Rx},
                RxIndex::{
                    ExtensionCircuit, ExtensionStage, InnerCollapse, InnerError, OuterError,
                    PointsBinding, Preamble,
                },
                claims::{KySource, Processor, build, ky_values},
            },
        },
        profile::{
            Profile,
            testing::{Crossing, CrossingBack, Stated, Wider},
        },
    };

    /// Two proofs' components, each tagged with its proof.
    struct TwoProofs;

    impl Source for TwoProofs {
        type RxComponent = RxComponent;
        type Rx = (usize, RxComponent);
        type AppCircuitId = CircuitIndex;

        fn rx(&self, component: RxComponent) -> impl Iterator<Item = Self::Rx> {
            [(0, component), (1, component)].into_iter()
        }

        fn app_circuits(&self) -> impl Iterator<Item = CircuitIndex> {
            [CircuitIndex::new(0), CircuitIndex::new(1)].into_iter()
        }
    }

    type Claim = (InternalCircuitIndex, Vec<(usize, RxComponent)>);

    #[derive(Default)]
    struct Recorder {
        circuits: Vec<Claim>,
        bondings: Vec<Claim>,
    }

    impl<P: Profile> Processor<P, (usize, RxComponent), CircuitIndex> for Recorder {
        fn raw_claim(&mut self, _: (usize, RxComponent), _: (usize, RxComponent)) {}

        fn circuit_claim(&mut self, _: CircuitIndex, _: (usize, RxComponent)) {}

        fn internal_circuit_claim(
            &mut self,
            id: InternalCircuitIndex,
            rxs: impl Iterator<Item = (usize, RxComponent)>,
        ) {
            self.circuits.push((id, rxs.collect()));
        }

        fn grouped_bonding_claim(
            &mut self,
            id: InternalCircuitIndex,
            groups: impl Iterator<Item = impl Iterator<Item = (usize, RxComponent)>>,
        ) -> Result<()> {
            self.bondings.push((id, groups.flatten().collect()));
            Ok(())
        }
    }

    let mut recorder = Recorder::default();
    build::<Wider, _, _>(&TwoProofs, &mut recorder).unwrap();

    let extension = Wider::native_extension();
    let circuits = &recorder.circuits;
    let tail = circuits.len() - 2 * extension.circuits.len();
    assert!(
        matches!(
            circuits[tail - 1].0,
            InternalCircuitIndex::EndoscalingStep(_)
        ),
        "the extension circuits follow the walk"
    );
    for (k, loads) in extension.circuits.iter().enumerate() {
        for proof in 0..2 {
            let (id, rxs) = &circuits[tail + 2 * k + proof];
            assert_eq!(*id, InternalCircuitIndex::ExtensionCircuit(k as u32));
            let expected: Vec<_> = [Rx(ExtensionCircuit(k as u32))]
                .into_iter()
                .chain(loads.iter().map(|&stage| Rx(ExtensionStage(stage))))
                .map(|component| (proof, component))
                .collect();
            assert_eq!(*rxs, expected);
        }
    }

    let bondings = &recorder.bondings;
    let tail = bondings.len() - extension.bondings();
    for stage in 0..extension.stages {
        let (id, rxs) = &bondings[tail + stage];
        assert_eq!(*id, InternalCircuitIndex::ExtensionBonding(stage as u32));
        let expected = [
            (0, Rx(ExtensionStage(stage as u32))),
            (1, Rx(ExtensionStage(stage as u32))),
        ];
        assert_eq!(*rxs, expected);
    }
    for (mask, named) in extension.final_masks.iter().enumerate() {
        let (id, rxs) = &bondings[tail + extension.stages + mask];
        assert_eq!(
            *id,
            InternalCircuitIndex::ExtensionBonding((extension.stages + mask) as u32)
        );
        let expected: Vec<_> = named
            .iter()
            .flat_map(|&k| [(0, Rx(ExtensionCircuit(k))), (1, Rx(ExtensionCircuit(k)))])
            .collect();
        assert_eq!(*rxs, expected);
    }

    /// $k(y)$ values that tell the sources apart.
    struct Tagged;

    impl KySource for Tagged {
        type Ky = u32;

        fn raw_c(&self) -> impl Iterator<Item = u32> {
            [10, 11].into_iter()
        }

        fn application_ky(&self) -> impl Iterator<Item = u32> {
            [20, 21].into_iter()
        }

        fn unified_bridge_ky(&self) -> impl Iterator<Item = u32> {
            [30, 31].into_iter()
        }

        fn unified_ky(&self) -> impl Iterator<Item = u32> + Clone {
            [40, 41].into_iter()
        }

        fn ones(&self) -> impl Iterator<Item = u32> + Clone {
            [1, 1].into_iter()
        }

        fn statement_ky(&self) -> impl Iterator<Item = u32> + Clone {
            [60, 61].into_iter()
        }

        fn binding_ky(&self) -> impl Iterator<Item = u32> + Clone {
            [70, 71].into_iter()
        }

        fn zero(&self) -> u32 {
            0
        }
    }

    let targets: Vec<u32> = ky_values::<Wider, _>(&Tagged)
        .take(recorder.circuits.len() + 6)
        .collect();
    let ones = targets.iter().filter(|&&ky| ky == 1).count();
    let steps = native::NumSteps::<Wider>::len();
    assert_eq!(ones, 2 * (steps + extension.circuits.len()));
    let first_one = targets.iter().position(|&ky| ky == 1).unwrap();
    assert!(
        targets[first_one..first_one + ones]
            .iter()
            .all(|&ky| ky == 1)
    );
    assert!(targets[first_one + ones..].iter().all(|&ky| ky == 0));

    // The statement and binding circuits take their own values at their
    // circuits, after the walk's ones and before the stages' zeros.
    fn native_targets<P: Profile>() -> Vec<u32> {
        let steps = native::NumSteps::<P>::len();
        let circuits = P::native_extension().circuits.len();
        let targets: Vec<u32> = ky_values::<P, _>(&Tagged)
            .take(2 * InternalCircuitIndex::num::<P>() + 8)
            .collect();
        let walk = targets.iter().position(|&ky| ky == 1).unwrap();
        let extension = walk + 2 * steps;
        assert!(targets[walk..extension].iter().all(|&ky| ky == 1));
        assert!(
            targets[extension + 2 * circuits..]
                .iter()
                .all(|&ky| ky == 0)
        );
        targets[extension..extension + 2 * circuits].to_vec()
    }
    assert_eq!(native_targets::<Wider>(), [1, 1, 1, 1]);
    assert_eq!(native_targets::<Stated>(), [1, 1, 60, 61]);
    assert_eq!(native_targets::<Crossing>(), [70, 71]);
    assert_eq!(native_targets::<CrossingBack>(), [1, 1]);

    /// Nested $k(y)$ values that tell the sources apart.
    struct NestedTagged;

    impl nested::claims::KySource for NestedTagged {
        type Ky = u32;

        fn raw_c(&self) -> impl Iterator<Item = u32> {
            [10, 11].into_iter()
        }

        fn ones(&self) -> impl Iterator<Item = u32> + Clone {
            [1, 1].into_iter()
        }

        fn unified_ky(&self) -> impl Iterator<Item = u32> + Clone {
            [40, 41].into_iter()
        }

        fn binding_ky(&self) -> impl Iterator<Item = u32> + Clone {
            [70, 71].into_iter()
        }

        fn zero(&self) -> u32 {
            0
        }
    }

    fn nested_targets<P: Profile>() -> Vec<u32> {
        let steps = nested::NumSteps::<P>::len();
        let circuits = P::nested_extension().circuits.len();
        let extension = 2 + 2 * steps + 2 * nested::NUM_INSTANCE_CIRCUITS;
        let targets: Vec<u32> = nested::claims::ky_values::<P, _>(&NestedTagged)
            .take(extension + 2 * circuits + 8)
            .collect();
        assert!(targets[2..2 + 2 * steps].iter().all(|&ky| ky == 1));
        assert!(
            targets[extension + 2 * circuits..]
                .iter()
                .all(|&ky| ky == 0)
        );
        targets[extension..extension + 2 * circuits].to_vec()
    }
    assert_eq!(nested_targets::<Wider>(), [1, 1]);
    assert_eq!(nested_targets::<Crossing>(), [1, 1]);
    assert_eq!(nested_targets::<CrossingBack>(), [70, 71]);

    // The inner collapse claim loads the binding stage for a profile whose
    // native extension binds, and not otherwise.
    let collapse = |circuits: &[Claim]| -> Vec<Vec<(usize, RxComponent)>> {
        circuits
            .iter()
            .filter(|(id, _)| *id == InternalCircuitIndex::InnerCollapseCircuit)
            .map(|(_, rxs)| rxs.clone())
            .collect()
    };
    for (proof, rxs) in collapse(&recorder.circuits).into_iter().enumerate() {
        assert_eq!(
            rxs,
            [
                Rx(InnerCollapse),
                Rx(Preamble),
                Rx(InnerError),
                Rx(OuterError)
            ]
            .map(|component| (proof, component))
        );
    }
    let mut bound = Recorder::default();
    build::<Crossing, _, _>(&TwoProofs, &mut bound).unwrap();
    for (proof, rxs) in collapse(&bound.circuits).into_iter().enumerate() {
        assert_eq!(
            rxs,
            [
                Rx(InnerCollapse),
                Rx(PointsBinding),
                Rx(Preamble),
                Rx(InnerError),
                Rx(OuterError)
            ]
            .map(|component| (proof, component))
        );
    }
}

/// The extension hooks fit within the gate budget. Finalization then
/// reports that this registration-only fixture has no extension prover.
#[test]
fn test_extension_hooks_register_without_a_prover() {
    use alloc::string::ToString;

    use ragu_circuits::registry::RegistryBuilder;

    use crate::profile::{BondingSlot, CircuitSlot, Profile, Profiled, testing::Hooked};

    type C = Profiled<Pasta, Hooked>;
    let params = crate::pasta::baked();

    let registry = RegistryBuilder::<Fp, R>::new();
    let registry = Hooked::register_native_circuit::<Pasta, R, HEADER_SIZE>(
        0,
        CircuitSlot::new(registry),
        params,
    )
    .unwrap()
    .into_registry();
    assert_eq!(registry.num_internal_circuits(), 1);
    let registry = Hooked::register_native_bonding::<Pasta, R, HEADER_SIZE>(
        0,
        BondingSlot::new(registry),
        params,
    )
    .unwrap()
    .into_registry();
    let registry = Hooked::register_native_bonding::<Pasta, R, HEADER_SIZE>(
        1,
        BondingSlot::new(registry),
        params,
    )
    .unwrap()
    .into_registry();
    assert_eq!(registry.num_internal_circuits(), 3);

    let registry = RegistryBuilder::<Fq, R>::new();
    let registry =
        Hooked::register_nested_circuit::<Pasta, R>(0, CircuitSlot::new(registry), params)
            .unwrap()
            .into_registry();
    let registry =
        Hooked::register_nested_bonding::<Pasta, R>(0, BondingSlot::new(registry), params)
            .unwrap()
            .into_registry();
    let registry =
        Hooked::register_nested_bonding::<Pasta, R>(1, BondingSlot::new(registry), params)
            .unwrap()
            .into_registry();
    assert_eq!(registry.num_internal_circuits(), 3);

    let result = ApplicationBuilder::<C, R, HEADER_SIZE>::new().finalize(params);
    assert!(
        matches!(result, Err(Error::Initialization(source))
            if source.to_string() == "the profile's native extension has no prover"),
        "registration should fit before the fixture's missing prover is reported"
    );
}

/// The fold's groups are the standard profile's for the standard profile,
/// pinned, and grow with a profile's claims so that every claim has a slot.
#[test]
fn test_fold_groups_follow_the_profile() {
    use ragu_primitives::vec::Len;

    use crate::{
        internal::fold_revdot::Parameters,
        profile::{Standard, testing::Wider},
    };

    assert_eq!(native::num_claims::<Standard>(), 89);
    assert_eq!(nested::num_claims::<Standard>(), 76);
    assert_eq!(
        native::NumFoldGroups::<Standard>::len(),
        native::NUM_FOLD_GROUPS
    );
    assert_eq!(
        nested::NumFoldGroups::<Standard>::len(),
        nested::NUM_FOLD_GROUPS
    );

    fn capacity<FP: Parameters>() -> usize {
        FP::NumGroups::len() * FP::GroupSize::len()
    }
    assert!(capacity::<native::RevdotParameters<Standard>>() >= native::num_claims::<Standard>());
    assert!(capacity::<nested::RevdotParameters<Standard>>() >= nested::num_claims::<Standard>());

    // Wider adds two native circuits and four bondings, one nested circuit
    // and two bondings, and lengthens both walks by a few steps.
    assert!(native::num_claims::<Wider>() > native::num_claims::<Standard>() + 7);
    assert!(nested::num_claims::<Wider>() > nested::num_claims::<Standard>() + 4);
    assert!(capacity::<native::RevdotParameters<Wider>>() >= native::num_claims::<Wider>());
    assert!(capacity::<nested::RevdotParameters<Wider>>() >= nested::num_claims::<Wider>());
    assert!(nested::NumFoldGroups::<Wider>::len() > nested::NUM_FOLD_GROUPS);
}

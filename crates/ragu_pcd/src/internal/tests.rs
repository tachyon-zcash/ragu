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
use crate::{
    step::{Encoded, Index, Step},
    *,
};
pub type R = ragu_circuits::polynomials::ProductionRank;

use ragu_circuits::polynomials::Rank;
use ragu_core::{
    drivers::{
        Driver, DriverValue,
        emulator::{Emulator, Wireless},
    },
    gadgets::{Bound, Gadget, Kind},
    maybe::{Empty, Maybe},
};
use ragu_primitives::{
    Element,
    vec::{CollectFixed, ConstLen, FixedVec},
};
use udon::field::Field;

/// A fragment that exports a fixed gadget whose values must all be zero.
pub(crate) struct SharedInputs<const INDEX: usize, const SIZE: usize>;

impl<const INDEX: usize, const SIZE: usize> Step<Pasta> for SharedInputs<INDEX, SIZE> {
    const INDEX: Index = Index::new(INDEX);
    type Shared = Kind![Fp; FixedVec<Element<'_, _>, ConstLen<SIZE>>];
    type Witness<'source> = [Fp; SIZE];
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = ();

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
        ),
        Bound<'dr, D, Self::Shared>,
        DriverValue<D, ()>,
        DriverValue<D, ()>,
    )> {
        let shared = (0..SIZE)
            .map(|i| {
                let input = Element::alloc(dr, &mut (), witness.as_ref().map(|w| w[i]))?;
                input.enforce_zero(dr)?;
                Ok(input)
            })
            .try_collect_fixed()?;
        Ok((
            (
                Encoded::from_gadget(()),
                Encoded::from_gadget(()),
                Encoded::from_gadget(()),
            ),
            shared,
            D::unit(),
            D::unit(),
        ))
    }
}

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
type OuterError = outer_error::Stage<Pasta, R, HEADER_SIZE, RevdotParameters>;
type InnerError = inner_error::Stage<Pasta, R, HEADER_SIZE, RevdotParameters>;
type Query = query::Stage<Pasta, R, HEADER_SIZE>;
type Eval = eval::Stage<Pasta, R, HEADER_SIZE>;
type NestedCurve = <Pasta as ragu_core::Cycle>::NestedCurve;
type PointsBinding = native::stages::points::BindingStage<NestedCurve>;
type PointsChildren = native::stages::points::ChildrenStage<NestedCurve>;
type PointsRegistryWx = native::stages::points::RegistryWxStage<NestedCurve>;
type PointsAb = native::stages::points::AbStage<NestedCurve>;
type PointsF = native::stages::points::FStage<NestedCurve>;
type PointsWalk = native::stages::points::WalkStage<NestedCurve>;

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
            counts(native::circuits::endoscaling_step::Circuit::<Pasta, R>::new(step as usize))
        }
        _ => panic!("constraint counts only apply to internal circuits"),
    }
}

fn internal_circuit_counts(variant: InternalCircuitIndex) -> (usize, usize) {
    let pasta = crate::pasta::baked();
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
            crate::with_binder!(k, Pasta, R, HEADER_SIZE, crate::pasta::baked(), |circuit| {
                synthesis_counts(circuit)
            })
        }
        InternalCircuitIndex::BindBetaCircuit => {
            synthesis_counts(native::circuits::bind_beta::Circuit::<
                Pasta,
                R,
                HEADER_SIZE,
                RevdotParameters,
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

    check_constraints!(Hashes1Circuit,              mul = 2019, lin = 3149);
    check_constraints!(Hashes2Circuit,              mul = 2045, lin = 2986);
    check_constraints!(InnerCollapseCircuit,        mul = 1922, lin = 1953);
    check_constraints!(OuterCollapseCircuit,        mul = 1597, lin = 2089);
    check_constraints!(ComputeVCircuit,             mul = 1879, lin = 2763);
    check_constraints!(BindChallengesCircuit(0),    mul = 1987, lin = 2956);
    check_constraints!(BindChallengesCircuit(1),    mul = 1992, lin = 2966);
    check_constraints!(BindChallengesCircuit(2),    mul = 1992, lin = 2966);
    check_constraints!(BindChallengesCircuit(3),    mul = 1992, lin = 2966);
    check_constraints!(BindChallengesCircuit(4),    mul = 2003, lin = 2988);
    check_constraints!(BindBetaCircuit,             mul = 2030, lin = 3016);
    check_constraints!(BindEndoscalarCircuit,       mul = 788,  lin = 1458);
    // The nested batch has one point more than a multiple of four, so every
    // native endoscaling step walks four points and lays out the same.
    for step in 0..native::NUM_ENDOSCALING_STEPS as u32 {
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
    check_stage!(Preamble,         skip =  27, num = 350);
    check_stage!(OuterError,       skip = 377, num = 186);
    check_stage!(InnerError,       skip = 563, num = 399);
    check_stage!(Query,            skip = 377, num =  85);
    check_stage!(Eval,             skip = 462, num =  62);
    check_stage!(PointsChildren,   skip =  27, num =  68);
    check_stage!(PointsRegistryWx, skip =  95, num =   2);
    check_stage!(PointsAb,         skip =  97, num =   3);
    check_stage!(PointsF,          skip = 100, num =   2);
    check_stage!(PointsWalk,       skip = 102, num =  89);
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
                | InternalCircuitIndex::ApplicationStage
                | InternalCircuitIndex::ApplicationFinalStaged
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
        nested::InternalCircuitIndex::EndoscalingStep(step) => counts(MultiStage::new(
            nested::EndoscalingStep::<EqAffine, R>::new(step as usize),
        )),
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
    // The native batch is one point more than a multiple of four, so every
    // nested endoscaling step walks four points and lays out the same, to
    // the gate budget exactly. The pins below are per variant.
    let steps = crate::internal::endoscalar::num_steps::<{ nested::ENDOSCALINGS_PER_STEP }>(
        nested::NUM_ENDOSCALING_POINTS,
    );
    let mut expected = alloc::vec::Vec::new();
    for step in 0..steps {
        expected.push((nested::InternalCircuitIndex::EndoscalingStep(step as u32), (2048, 3677)));
    }
    expected.push((nested::InternalCircuitIndex::Export,   (1411, 1541)));
    expected.push((nested::InternalCircuitIndex::Collapse, (1636, 1701)));
    expected.push((nested::InternalCircuitIndex::ComputeV, (1684, 1785)));
    expected.push((nested::InternalCircuitIndex::Loading,  (788,  235)));

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
    check_stage!(nested::PointsStage<EqAffine>,                        skip =  65, num = 146);
    check_stage!(stages::preamble::Stage<EqAffine, R>,                 skip = 211, num = 118);
    check_stage!(stages::s_prime::Stage<EqAffine, R>,                  skip = 329, num =   3);
    check_stage!(stages::inner_error::Stage<EqAffine, R>,              skip = 332, num = 254);
    check_stage!(stages::outer_error::Stage<EqAffine, R>,              skip = 586, num =  73);
    check_stage!(stages::ab::Stage<EqAffine, R>,                       skip = 659, num =   3);
    check_stage!(stages::query::Stage<EqAffine, R>,                    skip = 662, num =  73);
    check_stage!(stages::f::Stage<EqAffine, R>,                        skip = 735, num =   2);
    check_stage!(stages::eval::Stage<EqAffine, R>,                     skip = 737, num =  51);
    check_stage!(stages::challenges::Stage<EqAffine, R>,               skip = 788, num =  12);
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
    print_stage!("points", nested::PointsStage<EqAffine>);
    print_stage!("preamble", stages::preamble::Stage<EqAffine, R>);
    print_stage!("s_prime", stages::s_prime::Stage<EqAffine, R>);
    print_stage!("inner_error", stages::inner_error::Stage<EqAffine, R>);
    print_stage!("outer_error", stages::outer_error::Stage<EqAffine, R>);
    print_stage!("ab", stages::ab::Stage<EqAffine, R>);
    print_stage!("query", stages::query::Stage<EqAffine, R>);
    print_stage!("f", stages::f::Stage<EqAffine, R>);
    print_stage!("eval", stages::eval::Stage<EqAffine, R>);
    print_stage!("challenges", stages::challenges::Stage<EqAffine, R>);
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
///
/// The application shared stage's masks are among those slots, and their
/// shape follows the stage size, so the sweep runs with an empty stage and
/// with one of a few elements.
#[test]
fn test_non_step_slots_reject_application_instances() {
    non_step_slots_reject_application_instances::<0>();
    non_step_slots_reject_application_instances::<3>();
}

fn non_step_slots_reject_application_instances<const SIZE: usize>() {
    use alloc::{format, string::String, vec::Vec};

    use ragu_circuits::registry::CircuitIndex;
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use udon::field::Field;

    let app = ApplicationBuilder::<Pasta, R, HEADER_SIZE>::new()
        .register_bundle((SharedInputs::<0, SIZE>, SharedInputs::<1, SIZE>))
        .unwrap()
        .finalize(crate::pasta::baked())
        .unwrap();
    let registry = &app.native_registry;
    let x = Fp::random(|bytes| StdRng::seed_from_u64(0).fill_bytes(bytes));

    let steps = InternalCircuitIndex::NUM..registry.num_circuits();
    let unprotected: Vec<String> = (0..registry.num_circuits().next_power_of_two())
        .filter(|slot| !steps.contains(slot))
        .filter(|&slot| {
            let sx = registry.wx(CircuitIndex::new(slot).omega_j(), x);
            let mut coeffs = sx.iter_coeffs();
            let constant = coeffs.next().unwrap();
            let linear = coeffs.next().unwrap();
            constant != Fp::ZERO && linear != Fp::ZERO
        })
        .map(|slot| match InternalCircuitIndex::ALL.get(slot) {
            Some(id) => format!("{id:?}"),
            None => format!("slot {slot}"),
        })
        .collect();

    assert!(
        unprotected.is_empty(),
        "non-step slots that can satisfy an application instance with a shared stage of \
         {SIZE}: {unprotected:?}"
    );
}

#[test]
fn supplied_tags_reach_both_registries() -> Result<()> {
    let tags = RegistryTags::<Pasta>::from_beacon(&[0x42; 32], &[0x24; 20]);
    let native = tags.native.value();
    let nested = tags.nested.value();
    let app = ApplicationBuilder::<Pasta, R, 4>::new()
        .with_registry_tags(tags)
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

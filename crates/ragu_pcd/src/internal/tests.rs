use native::{
    InternalCircuitIndex, InternalCircuitValues, RevdotParameters, RxIndex, RxValues,
    stages::{eval, inner_error, outer_error, preamble, query},
};
use ragu_circuits::{
    Circuit,
    staging::{MultiStage, MultiStageCircuit, Stage, StageExt},
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

#[cfg(feature = "unstable-fuzzing")]
#[path = "../../tests/hoisted_products.rs"]
mod hoisted_products;

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
        InternalCircuitIndex::CollapseCircuit => counts(native::circuits::collapse::Circuit::<
            Pasta,
            R,
            HEADER_SIZE,
            RevdotParameters<crate::profile::Standard>,
        >::new()),
        InternalCircuitIndex::ComputeVCircuit => {
            counts(native::circuits::compute_v::Circuit::<Pasta, R, HEADER_SIZE>::new())
        }
        InternalCircuitIndex::BindChallengesCircuit(k) => {
            crate::with_binder!(k, Pasta, R, HEADER_SIZE, pasta, |circuit| counts(circuit))
        }
        InternalCircuitIndex::BindBetaCircuit => {
            counts(native::circuits::bind_beta::Circuit::<Pasta, R, HEADER_SIZE>::new(pasta))
        }
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
        InternalCircuitIndex::CollapseCircuit => {
            synthesis_counts(native::circuits::collapse::Circuit::<
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
        InternalCircuitIndex::BindBetaCircuit => synthesis_counts(
            native::circuits::bind_beta::Circuit::<Pasta, R, HEADER_SIZE>::new(
                crate::pasta::baked(),
            ),
        ),
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

    check_constraints!(Hashes1Circuit,              mul = 1818, lin = 3085);
    check_constraints!(Hashes2Circuit,              mul = 1875, lin = 2984);
    check_constraints!(CollapseCircuit,             mul = 1364, lin = 1893);
    check_constraints!(ComputeVCircuit,             mul = 1853, lin = 2749);
    check_constraints!(BindChallengesCircuit(0),    mul = 2017, lin = 3054);
    check_constraints!(BindChallengesCircuit(1),    mul = 2022, lin = 3064);
    check_constraints!(BindChallengesCircuit(2),    mul = 2022, lin = 3064);
    check_constraints!(BindChallengesCircuit(3),    mul = 2033, lin = 3086);
    check_constraints!(BindBetaCircuit,             mul = 1891, lin = 3114);
    check_constraints!(BindEndoscalarCircuit,       mul = 903,  lin = 1697);
    // Every native endoscaling step walks four points and lays out the same.
    for step in 0..native::NUM_ENDOSCALING_STEPS as u32 {
        check_constraints!(EndoscalingStep(step),   mul = 1985, lin = 3502);
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
    check_stage!(Query, skip = 374, num = 75);
    check_stage!(Eval, skip = 449, num = 55);
    check_stage!(PointsChildren, skip = 27, num = 60);
    check_stage!(PointsRegistryWx, skip = 87, num = 2);
    check_stage!(PointsAb, skip = 89, num = 3);
    check_stage!(PointsF, skip = 92, num = 2);
    check_stage!(PointsWalk, skip = 94, num = 142);
}

/// Every native internal circuit's claim in [`native::claims`] composes its
/// trace with the stages it reads, listed by hand, and those stages must
/// lie on the chain the circuit's `Last` stage closes: a stage off that
/// chain lands its coefficients on gates the circuit uses for its own
/// constraints, and every honest proof fails to verify. This derives each
/// circuit's chain from the stages' declared parents, checked against their
/// gate layout, and holds the claim entries to it.
#[test]
fn claimed_stages_lie_on_each_circuits_chain() {
    use alloc::{vec, vec::Vec};
    use core::iter::once;

    use InternalCircuitIndex::*;
    use native::{RxComponent, circuits, claims::Processor};

    use crate::internal::claims::Source;

    /// Yields one marker per component, as a single proof would.
    struct Marks;

    impl Source for Marks {
        type RxComponent = RxComponent;
        type Rx = RxComponent;
        type AppCircuitId = ();

        fn rx(&self, component: RxComponent) -> impl Iterator<Item = RxComponent> {
            once(component)
        }

        fn app_circuits(&self) -> impl Iterator<Item = ()> {
            once(())
        }
    }

    /// Records every internal circuit claim's components.
    #[derive(Default)]
    struct Record(Vec<(InternalCircuitIndex, Vec<RxComponent>)>);

    impl<P: crate::profile::Profile> Processor<P, RxComponent, ()> for Record {
        fn raw_claim(&mut self, _: RxComponent, _: RxComponent) {}

        fn circuit_claim(&mut self, _: (), _: RxComponent) {}

        fn internal_circuit_claim(
            &mut self,
            id: InternalCircuitIndex,
            rxs: impl Iterator<Item = RxComponent>,
        ) {
            self.0.push((id, rxs.collect()));
        }

        fn grouped_bonding_claim(
            &mut self,
            _: InternalCircuitIndex,
            _: impl Iterator<Item = impl Iterator<Item = RxComponent>>,
        ) -> ragu_core::Result<()> {
            Ok(())
        }
    }

    fn range<S: Stage<Fp, R>>() -> (usize, usize) {
        (
            <S as Stage<Fp, R>>::skip_gates(),
            <S as StageExt<Fp, R>>::num_gates(),
        )
    }

    /// The gate a circuit's own gates start at: every stage on the chain its
    /// `Last` stage closes occupies gates below it.
    fn staged_gates<S: MultiStageCircuit<Fp, R>>(_: &MultiStage<Fp, R, S>) -> usize {
        <S::Last as Stage<Fp, R>>::skip_gates() + <S::Last as StageExt<Fp, R>>::num_gates()
    }

    /// A stage's gate range, or `None` for a circuit's own polynomial.
    fn stage_range(index: RxIndex) -> Option<(usize, usize)> {
        Some(match index {
            RxIndex::Preamble => range::<Preamble>(),
            RxIndex::InnerError => range::<InnerError>(),
            RxIndex::OuterError => range::<OuterError>(),
            RxIndex::Query => range::<Query>(),
            RxIndex::Eval => range::<Eval>(),
            RxIndex::PointsBinding => range::<PointsBinding>(),
            RxIndex::PointsChildren => range::<PointsChildren>(),
            RxIndex::PointsRegistryWx => range::<PointsRegistryWx>(),
            RxIndex::PointsAb => range::<PointsAb>(),
            RxIndex::PointsF => range::<PointsF>(),
            RxIndex::PointsWalk => range::<PointsWalk>(),
            _ => return None,
        })
    }

    // The native stage tree, as each stage's declared parent; a stage
    // starts where its parent ends, which pins the declaration to the real
    // layout.
    let parents = [
        (RxIndex::PointsBinding, None),
        (RxIndex::Preamble, Some(RxIndex::PointsBinding)),
        (RxIndex::OuterError, Some(RxIndex::Preamble)),
        (RxIndex::InnerError, Some(RxIndex::OuterError)),
        (RxIndex::Query, Some(RxIndex::Preamble)),
        (RxIndex::Eval, Some(RxIndex::Query)),
        (RxIndex::PointsChildren, Some(RxIndex::PointsBinding)),
        (RxIndex::PointsRegistryWx, Some(RxIndex::PointsChildren)),
        (RxIndex::PointsAb, Some(RxIndex::PointsRegistryWx)),
        (RxIndex::PointsF, Some(RxIndex::PointsAb)),
        (RxIndex::PointsWalk, Some(RxIndex::PointsF)),
    ];
    for (stage, parent) in parents {
        let starts_at = parent.map_or(1, |parent| {
            let (skip, num) = stage_range(parent).unwrap();
            skip + num
        });
        assert_eq!(
            stage_range(stage).unwrap().0,
            starts_at,
            "{stage:?} does not extend {parent:?}"
        );
    }
    let chain_of = |last: RxIndex| -> Vec<RxIndex> {
        let mut chain = vec![last];
        let mut stage = last;
        while let Some((_, Some(parent))) = parents.iter().find(|(s, _)| *s == stage) {
            chain.push(*parent);
            stage = *parent;
        }
        chain.reverse();
        chain
    };

    // Each circuit's last stage, held to the circuit's own account of where
    // its stages end.
    let pasta = crate::pasta::baked();
    let (_, log2_circuits) =
        native::total_circuit_counts::<crate::profile::Standard>(NUM_APP_STEPS);
    let last_stage = |variant: InternalCircuitIndex| -> RxIndex {
        let (last, staged_gates) = match variant {
            Hashes1Circuit => (
                RxIndex::OuterError,
                staged_gates(&circuits::hashes_1::Circuit::<
                    Pasta,
                    R,
                    HEADER_SIZE,
                    RevdotParameters<crate::profile::Standard>,
                >::new(pasta, log2_circuits)),
            ),
            Hashes2Circuit => (
                RxIndex::OuterError,
                staged_gates(&circuits::hashes_2::Circuit::<
                    Pasta,
                    R,
                    HEADER_SIZE,
                    RevdotParameters<crate::profile::Standard>,
                >::new(pasta)),
            ),
            CollapseCircuit => (
                RxIndex::InnerError,
                staged_gates(&circuits::collapse::Circuit::<
                    Pasta,
                    R,
                    HEADER_SIZE,
                    RevdotParameters<crate::profile::Standard>,
                >::new()),
            ),
            ComputeVCircuit => (
                RxIndex::Eval,
                staged_gates(&circuits::compute_v::Circuit::<Pasta, R, HEADER_SIZE>::new()),
            ),
            BindChallengesCircuit(k) => (
                RxIndex::Eval,
                crate::with_binder!(k, Pasta, R, HEADER_SIZE, pasta, |circuit| staged_gates(
                    &circuit
                )),
            ),
            BindBetaCircuit => (
                RxIndex::Preamble,
                staged_gates(&circuits::bind_beta::Circuit::<Pasta, R, HEADER_SIZE>::new(
                    pasta,
                )),
            ),
            BindEndoscalarCircuit => (
                RxIndex::PointsWalk,
                staged_gates(&circuits::bind_endoscalar::Circuit::<Pasta, R>::new()),
            ),
            EndoscalingStep(step) => (
                RxIndex::PointsWalk,
                staged_gates(&circuits::endoscaling_step::Circuit::<Pasta, R>::new(
                    step as usize,
                )),
            ),
            other => panic!("{other:?} is not a circuit"),
        };
        let (skip, num) = stage_range(last).unwrap();
        assert_eq!(
            skip + num,
            staged_gates,
            "{variant:?}: {last:?} is not the circuit's last stage"
        );
        last
    };

    let mut record = Record::default();
    native::claims::build::<crate::profile::Standard, _, _>(&Marks, &mut record).unwrap();

    let claimed: Vec<_> = record.0.iter().map(|(id, _)| *id).collect();
    let circuits: Vec<_> = InternalCircuitIndex::ALL
        .into_iter()
        .filter(|id| {
            matches!(
                id,
                Hashes1Circuit
                    | Hashes2Circuit
                    | CollapseCircuit
                    | ComputeVCircuit
                    | BindChallengesCircuit(_)
                    | BindBetaCircuit
                    | BindEndoscalarCircuit
                    | EndoscalingStep(_)
            )
        })
        .collect();
    assert_eq!(claimed, circuits, "every circuit claims once, in order");

    for (id, components) in &record.0 {
        let chain = chain_of(last_stage(*id));
        let mut seen = vec![];
        for component in components {
            let RxComponent::Rx(index) = component else {
                panic!("{id:?}: claim adds the raw {component:?}");
            };
            if stage_range(*index).is_none() {
                continue;
            }
            assert!(
                chain.contains(index),
                "{id:?}: claim adds stage {index:?}, which is not on the chain {chain:?} its last stage closes"
            );
            assert!(!seen.contains(index), "{id:?}: claim adds {index:?} twice");
            seen.push(*index);
        }
    }
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
                | InternalCircuitIndex::PreambleFinalStaged
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

/// Helper test to print the parameters the book's local degree ledger in
/// `book/src/protocol/extensions/endoscalar.md` is derived from.
/// Both point counts include the initial F point, so the fold's degree is
/// one less than the printed count.
/// Run with: `cargo test -p ragu_pcd --release print_ledger -- --nocapture`
#[test]
fn print_ledger_parameters() {
    use std::println;

    use ragu_primitives::vec::Len;

    use crate::profile::Standard;

    println!("\n// Ledger parameters for book/src/protocol/extensions/endoscalar.md:");
    println!(
        "native revdot: M = {}, N = {}",
        native::FOLD_GROUP_SIZE,
        native::NUM_FOLD_GROUPS
    );
    println!(
        "nested revdot: M = {}, N = {}",
        nested::FOLD_GROUP_SIZE,
        nested::NUM_FOLD_GROUPS
    );
    println!("nested rx polynomials: {}", nested::RxIndex::NUM);
    println!(
        "nested internal circuits: {}",
        nested::InternalCircuitIndex::NUM
    );
    println!(
        "nested PCS queries T: {}",
        nested::pcs::STATIC_F_QUERIES.len()
            + 2 * nested::RxIndex::NUM
            + nested::InternalCircuitIndex::NUM
    );
    println!(
        "native walk points: {}",
        native::NumPoints::<Standard>::len()
    );
    println!(
        "nested walk points: {}",
        nested::NumPoints::<Standard>::len()
    );
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
        expected.push((nested::InternalCircuitIndex::EndoscalingStep(step as u32), (2000, 3501)));
    }
    expected.push((nested::InternalCircuitIndex::Collapse, (1493, 2338)));
    expected.push((nested::InternalCircuitIndex::ComputeV, (1397, 1737)));
    expected.push((nested::InternalCircuitIndex::Loading,  (527,  211)));

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

    check_stage!(endoscalar::EndoscalarStage, skip = 1, num = 119);
    check_stage!(nested::PointsStage<EqAffine, crate::profile::Standard>, skip = 120, num = 131);
    check_stage!(stages::preamble::Stage<EqAffine, R, crate::profile::Standard>, skip = 251, num = 106);
    check_stage!(stages::s_prime::Stage<EqAffine, R, crate::profile::Standard>, skip = 357, num = 3);
    check_stage!(stages::inner_error::Stage<EqAffine, R, crate::profile::Standard>, skip = 360, num = 37);
    check_stage!(stages::outer_error::Stage<EqAffine, R, crate::profile::Standard>, skip = 397, num = 11);
    check_stage!(stages::ab::Stage<EqAffine, R, crate::profile::Standard>, skip = 408, num = 3);
    check_stage!(stages::query::Stage<EqAffine, R, crate::profile::Standard>, skip = 411, num = 67);
    check_stage!(stages::f::Stage<EqAffine, R, crate::profile::Standard>, skip = 478, num = 2);
    check_stage!(stages::eval::Stage<EqAffine, R, crate::profile::Standard>, skip = 480, num = 47);
    check_stage!(stages::challenges::Stage<EqAffine, R, crate::profile::Standard>, skip = 527, num = 10);
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

/// Asserts that only step slots of `app`'s native registry can satisfy an
/// application instance.
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
pub(crate) fn assert_only_steps_satisfy_application_instances<
    C: crate::profile::ProfiledCycle,
    R: Rank,
    const HEADER_SIZE: usize,
>(
    app: &Application<'_, C, R, HEADER_SIZE>,
) {
    use alloc::{format, string::String, vec::Vec};

    use ragu_circuits::registry::CircuitIndex;
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use udon::field::Field;

    use crate::profile::Profile;

    let registry = &app.native_registry;
    let x = C::CircuitField::random(|bytes| StdRng::seed_from_u64(0).fill_bytes(bytes));
    let all = InternalCircuitIndex::all::<C::Profile>();
    let steps = all.len()..registry.num_circuits();
    let unprotected: Vec<String> = (0..registry.num_circuits().next_power_of_two())
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
        .collect();
    assert!(
        unprotected.is_empty(),
        "non-step slots of {} that can satisfy an application instance: {unprotected:?}",
        C::Profile::NAME
    );
}

/// Only step slots satisfy an application instance, in the standard profile
/// and in profiles with extension circuits; see
/// [`assert_only_steps_satisfy_application_instances`].
#[test]
fn test_non_step_slots_reject_application_instances() {
    use crate::profile::{
        Profiled,
        testing::{Crossing, CrossingBack, CrossingContext, Proving},
    };

    let params = crate::pasta::baked();
    assert_only_steps_satisfy_application_instances(
        &ApplicationBuilder::<Pasta, R, HEADER_SIZE>::new()
            .finalize(params)
            .unwrap(),
    );

    // Profiles with extension circuits, at the rank where they fit.
    type Wide = ragu_circuits::polynomials::R<14>;
    let params = crate::pasta::baked_aggregator();
    assert_only_steps_satisfy_application_instances(
        &ApplicationBuilder::<Profiled<Pasta, Proving>, Wide, 4>::new()
            .finalize(params)
            .unwrap(),
    );
    let context = || CrossingContext {
        params,
        native: [true; 4],
        nested: [true; 4],
    };
    assert_only_steps_satisfy_application_instances(
        &ApplicationBuilder::<Profiled<Pasta, Crossing>, Wide, 4>::new()
            .finalize_with(params, context())
            .unwrap(),
    );
    assert_only_steps_satisfy_application_instances(
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
/// circuits on either side; and the collapse claim loads the binding
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
                    Collapse, ExtensionCircuit, ExtensionStage, InnerError, OuterError,
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

    // The collapse claim loads the binding stage for a profile whose
    // native extension binds, and not otherwise.
    let collapse = |circuits: &[Claim]| -> Vec<Vec<(usize, RxComponent)>> {
        circuits
            .iter()
            .filter(|(id, _)| *id == InternalCircuitIndex::CollapseCircuit)
            .map(|(_, rxs)| rxs.clone())
            .collect()
    };
    for (proof, rxs) in collapse(&recorder.circuits).into_iter().enumerate() {
        assert_eq!(
            rxs,
            [Rx(Collapse), Rx(Preamble), Rx(InnerError), Rx(OuterError)]
                .map(|component| (proof, component))
        );
    }
    let mut bound = Recorder::default();
    build::<Crossing, _, _>(&TwoProofs, &mut bound).unwrap();
    for (proof, rxs) in collapse(&bound.circuits).into_iter().enumerate() {
        assert_eq!(
            rxs,
            [
                Rx(Collapse),
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

    use crate::profile::{
        BondingSlot, CircuitSlot, NO_NATIVE_EXTENSION_PROVER, Profile, Profiled, testing::Hooked,
    };

    type H = Hooked;
    type C = Profiled<Pasta, H>;
    let params = crate::pasta::baked();

    let registry = RegistryBuilder::<Fp, R>::new();
    let registry =
        H::register_native_circuit::<Pasta, R, HEADER_SIZE>(0, CircuitSlot::new(registry), params)
            .unwrap()
            .into_registry();
    assert_eq!(registry.num_internal_circuits(), 1);
    let registry =
        H::register_native_bonding::<Pasta, R, HEADER_SIZE>(0, BondingSlot::new(registry), params)
            .unwrap()
            .into_registry();
    let registry =
        H::register_native_bonding::<Pasta, R, HEADER_SIZE>(1, BondingSlot::new(registry), params)
            .unwrap()
            .into_registry();
    assert_eq!(registry.num_internal_circuits(), 3);

    let registry = RegistryBuilder::<Fq, R>::new();
    let registry = H::register_nested_circuit::<Pasta, R>(0, CircuitSlot::new(registry), params)
        .unwrap()
        .into_registry();
    let registry = H::register_nested_bonding::<Pasta, R>(0, BondingSlot::new(registry), params)
        .unwrap()
        .into_registry();
    let registry = H::register_nested_bonding::<Pasta, R>(1, BondingSlot::new(registry), params)
        .unwrap()
        .into_registry();
    assert_eq!(registry.num_internal_circuits(), 3);

    // The 143-bit challenge binders leave the last binder fifteen gates under
    // the bound at the standard header, and the fixture's extension stage
    // costs it thirteen more; a smaller header makes room to reach the
    // missing-prover check this test is about.
    const FITTING_HEADER_SIZE: usize = HEADER_SIZE - 8;
    let result = ApplicationBuilder::<C, R, FITTING_HEADER_SIZE>::new().finalize(params);
    assert!(
        matches!(result, Err(Error::Initialization(source))
            if source.to_string() == NO_NATIVE_EXTENSION_PROVER),
        "registration should fit before the fixture's missing prover is reported"
    );
}

/// A third native extension circuit overflows the gate budget, since the
/// fuse's own circuits grow with every polynomial a proof carries.
#[test]
fn test_extension_overflowing_the_fuse_is_rejected() {
    use crate::profile::{Profiled, testing::Hooked};

    type C = Profiled<Pasta, Hooked<3>>;
    let result = ApplicationBuilder::<C, R, HEADER_SIZE>::new().finalize(crate::pasta::baked());
    assert!(
        matches!(result, Err(Error::GateBoundExceeded { .. })),
        "the fuse should exceed its gate budget before any prover runs"
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

    assert_eq!(native::num_claims::<Standard>(), 86);
    assert_eq!(nested::num_claims::<Standard>(), 72);
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

/// The gates of every fuse circuit of profile `P` over cycle `C` at rank
/// `R` with `H`-element headers, by side, each with its index's name: the
/// extension's circuits and the bondings aside.
macro_rules! fuse_gates {
    ($C:ty, $R:ty, $H:expr, $P:ty) => {{
        use ragu_circuits::staging::MultiStage;

        use crate::internal::{
            native::{self, InternalCircuitIndex as Native},
            nested::{self, InternalCircuitIndex as Nested},
        };
        type Host = <$C as ragu_core::Cycle>::HostCurve;
        fn gates<F: Field>(circuit: &impl Circuit<F>) -> usize {
            ragu_circuits::testing::synthesis_counts(circuit)
                .unwrap()
                .num_gates
        }
        let pasta = crate::pasta::baked_aggregator();
        let (_, log2_circuits) = native::total_circuit_counts::<$P>(NUM_APP_STEPS);
        let mut native_gates: alloc::vec::Vec<(alloc::string::String, usize)> =
            alloc::vec::Vec::new();
        for variant in Native::all::<$P>() {
            let gates = match variant {
                Native::Hashes1Circuit => gates(&native::circuits::hashes_1::Circuit::<
                    $C,
                    $R,
                    $H,
                    RevdotParameters<$P>,
                >::new(pasta, log2_circuits)),
                Native::Hashes2Circuit => gates(&native::circuits::hashes_2::Circuit::<
                    $C,
                    $R,
                    $H,
                    RevdotParameters<$P>,
                >::new(pasta)),
                Native::CollapseCircuit => gates(&native::circuits::collapse::Circuit::<
                    $C,
                    $R,
                    $H,
                    RevdotParameters<$P>,
                >::new()),
                Native::ComputeVCircuit => {
                    gates(&native::circuits::compute_v::Circuit::<$C, $R, $H>::new())
                }
                Native::BindChallengesCircuit(k) => {
                    crate::with_binder!(k, $C, $R, $H, pasta, |circuit| gates(&circuit))
                }
                Native::BindBetaCircuit => gates(
                    &native::circuits::bind_beta::Circuit::<$C, $R, $H>::new(pasta),
                ),
                Native::BindEndoscalarCircuit => {
                    gates(&native::circuits::bind_endoscalar::Circuit::<$C, $R>::new())
                }
                Native::EndoscalingStep(step) => gates(
                    &native::circuits::endoscaling_step::Circuit::<$C, $R>::new(step as usize),
                ),
                _ => continue,
            };
            native_gates.push((alloc::format!("{variant:?}"), gates));
        }
        let mut nested_gates: alloc::vec::Vec<(alloc::string::String, usize)> =
            alloc::vec::Vec::new();
        for variant in Nested::all::<$P>() {
            let gates = match variant {
                Nested::EndoscalingStep(step) => gates(&MultiStage::new(
                    nested::EndoscalingStep::<Host, $R, $P>::new(step as usize),
                )),
                Nested::Collapse => gates(&MultiStage::new(nested::circuits::collapse::Circuit::<
                    Host,
                    $R,
                    $P,
                >::new())),
                Nested::ComputeV => {
                    gates(&MultiStage::new(nested::circuits::compute_v::Circuit::<
                        Host,
                        $R,
                        $P,
                    >::new()))
                }
                Nested::Loading => gates(&MultiStage::new(nested::circuits::loading::Circuit::<
                    Host,
                    $R,
                    $P,
                >::new())),
                _ => continue,
            };
            nested_gates.push((alloc::format!("{variant:?}"), gates));
        }
        (native_gates, nested_gates)
    }};
}

/// Reports `gates`, every circuit but the endoscaling steps and the
/// largest step, against `budget`, and returns the circuits over it.
fn report_fuse_gates(
    side: &str,
    gates: &[(alloc::string::String, usize)],
    budget: usize,
) -> alloc::vec::Vec<(alloc::string::String, usize)> {
    let steps = gates
        .iter()
        .filter(|(name, _)| name.starts_with("EndoscalingStep"));
    let largest_step = steps.max_by_key(|(_, gates)| *gates);
    std::println!("{side}: {} circuits of {budget} gates", gates.len());
    for (name, gates) in gates
        .iter()
        .filter(|(name, _)| !name.starts_with("EndoscalingStep"))
        .chain(largest_step)
    {
        std::println!("  {name}: {gates}");
    }
    gates
        .iter()
        .filter(|(_, gates)| *gates > budget)
        .cloned()
        .collect()
}

/// Every fuse circuit of the aggregator profile fits the aggregator rank's
/// budget with the decompression extension's polynomials, for the test
/// header size and for this module's.
#[test]
fn test_aggregator_fuse_fits_the_budget() {
    use ragu_circuits::polynomials::AggregatorRank;

    use crate::profile::{Aggregator, Profiled};

    let budget = AggregatorRank::n();
    let mut over = alloc::vec::Vec::new();
    {
        type C = Profiled<Pasta, Aggregator<4>>;
        let (native, nested) = fuse_gates!(C, AggregatorRank, 4, Aggregator<4>);
        over.extend(report_fuse_gates("native, header size 4", &native, budget));
        over.extend(report_fuse_gates("nested, header size 4", &nested, budget));
    }
    {
        type C = Profiled<Pasta, Aggregator<HEADER_SIZE>>;
        let (native, nested) = fuse_gates!(C, AggregatorRank, HEADER_SIZE, Aggregator<HEADER_SIZE>);
        over.extend(report_fuse_gates(
            "native, header size 103",
            &native,
            budget,
        ));
        over.extend(report_fuse_gates(
            "nested, header size 103",
            &nested,
            budget,
        ));
    }
    assert!(over.is_empty(), "over the budget: {over:?}");
}

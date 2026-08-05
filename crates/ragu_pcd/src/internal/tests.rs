use native::{InternalCircuitIndex, InternalCircuitValues, RxIndex, RxValues};
use ragu_circuits::staging::Stage;
use ragu_pasta::{Pasta, fp, fq};

use super::*;
use crate::*;
pub type R = ragu_circuits::polynomials::ProductionRank;

use ragu_arithmetic::ff::PrimeField;
use ragu_circuits::polynomials::{Rank, sparse};
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

/// Kept small so the hook regions, not the header, set the gate counts.
const NONZERO_LAYOUT_HEADER_SIZE: usize = 4;

/// Small, to keep this file's runtime down.
const NUM_NONZERO_LAYOUT_APP_STEPS: usize = 6;

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

/// The same pins at a nonzero layout (two polynomials, three queries, one
/// challenge); a change confined to the hook regions cannot move the
/// zero-layout pins in [`test_internal_circuit_constraint_counts`].
#[rustfmt::skip]
#[test]
fn test_nonzero_layout_internal_circuit_constraint_counts() {
    let pasta = Pasta::baked();

    let app = dummy_app::<NONZERO_LAYOUT_HEADER_SIZE, 2, 3, 1>(pasta, NUM_NONZERO_LAYOUT_APP_STEPS);

    // All six span the preamble stage, so all six include the handle region's
    // wires (`HANDLE_WIRES` per witnessed polynomial per child);
    // `OuterCollapse`'s `application_ky` Horner additionally folds them.
    check_constraints!(app, Hashes1Circuit,          mul = 1148, lin = 1834);
    check_constraints!(app, Hashes2Circuit,          mul = 1712, lin = 2951);
    check_constraints!(app, InnerCollapseCircuit,    mul = 1589, lin = 1918);
    check_constraints!(app, OuterCollapseCircuit,    mul =  787, lin = 1098);
    // The two that read the hook regions, and the reason this shape is pinned
    // at all. `ComputeV` carries the per-query one-hot resolution against the
    // carried commitments, so it moves whenever that does; an application that derives
    // a challenge gives `ChallengeBinding` one to bind.
    check_constraints!(app, ComputeVCircuit,         mul = 1069, lin = 1977);
    check_constraints!(app, ChallengeBindingCircuit, mul =  855, lin = 1225);
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
    print(
        &dummy_app::<NONZERO_LAYOUT_HEADER_SIZE, 2, 3, 1>(pasta, NUM_NONZERO_LAYOUT_APP_STEPS)
            .native_registry,
        "test_nonzero_layout_internal_circuit_constraint_counts",
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

/// The nested stage types `test_nested_stage_parameters` pins, at eight
/// polynomials.
mod pinned_nested_chain {
    use ragu_primitives::vec::ConstLen;

    use super::R;
    use crate::internal::{
        endoscalar,
        nested::{EndoscalingPoints, stages},
    };

    type Host = <ragu_pasta::Pasta as ragu_arithmetic::Cycle>::HostCurve;
    type L = ConstLen<8>;

    pub type Endoscalar = endoscalar::EndoscalarStage;
    pub type Points = endoscalar::PointsStage<Host, EndoscalingPoints<L>>;
    pub type Preamble = stages::preamble::Stage<Host, R, L>;
    pub type SPrime = stages::s_prime::Stage<Host, R, L>;
    pub type InnerError = stages::inner_error::Stage<Host, R, L>;
    pub type OuterError = stages::outer_error::Stage<Host, R, L>;
    pub type Ab = stages::ab::Stage<Host, R, L>;
    pub type Query = stages::query::Stage<Host, R, L>;
    pub type F = stages::f::Stage<Host, R, L>;
    pub type Eval = stages::eval::Stage<Host, R, L>;
}

#[rustfmt::skip]
#[test]
fn test_nested_stage_parameters() {
    use ragu_circuits::staging::{Stage, StageExt};
    use ragu_pasta::Fq;

    // Explicit field: `EndoscalarStage` implements `Stage` over both fields,
    // so an unqualified call is ambiguous.
    macro_rules! check_stage {
        ($stage:ty, skip = $skip:expr, num = $num:expr) => {{
            assert_eq!(
                <$stage as Stage<Fq, R>>::skip_gates(), $skip, "{}: skip", stringify!($stage)
            );
            assert_eq!(
                <$stage as StageExt<Fq, R>>::num_gates(), $num, "{}: num", stringify!($stage)
            );
        }};
    }

    check_stage!(pinned_nested_chain::Endoscalar,  skip =   1, num =  64);
    check_stage!(pinned_nested_chain::Points,      skip =  65, num =  71);
    check_stage!(pinned_nested_chain::Preamble,    skip = 136, num =  51);
    check_stage!(pinned_nested_chain::SPrime,      skip = 187, num =   3);
    check_stage!(pinned_nested_chain::InnerError,  skip = 190, num =   2);
    check_stage!(pinned_nested_chain::OuterError,  skip = 192, num =   1);
    check_stage!(pinned_nested_chain::Ab,          skip = 193, num =   2);
    check_stage!(pinned_nested_chain::Query,       skip = 195, num =   2);
    check_stage!(pinned_nested_chain::F,           skip = 197, num =   1);
    check_stage!(pinned_nested_chain::Eval,        skip = 198, num =   9);
}

/// Run with: `cargo test -p ragu_pcd --release print_nested_stage -- --nocapture`
#[test]
fn print_nested_stage_parameters() {
    use std::println;

    use ragu_circuits::staging::StageExt as _;

    fn line<S: ragu_circuits::staging::Stage<ragu_pasta::Fq, R>>(name: &str) {
        println!(
            "    check_stage!(pinned_nested_chain::{:<12} skip = {:>3}, num = {:>3});",
            alloc::format!("{name},"),
            S::skip_gates(),
            S::num_gates()
        );
    }

    println!("\n// Copy-paste the following into test_nested_stage_parameters:");
    line::<pinned_nested_chain::Endoscalar>("Endoscalar");
    line::<pinned_nested_chain::Points>("Points");
    line::<pinned_nested_chain::Preamble>("Preamble");
    line::<pinned_nested_chain::SPrime>("SPrime");
    line::<pinned_nested_chain::InnerError>("InnerError");
    line::<pinned_nested_chain::OuterError>("OuterError");
    line::<pinned_nested_chain::Ab>("Ab");
    line::<pinned_nested_chain::Query>("Query");
    line::<pinned_nested_chain::F>("F");
    line::<pinned_nested_chain::Eval>("Eval");
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

/// Pins both registry digests at a nonzero layout (two polynomials, three
/// queries, one challenge). The zero-layout digest pins cannot see a change
/// confined to the hook regions.
#[test]
fn test_nonzero_layout_registry_digests() {
    let pasta = Pasta::baked();

    let app = dummy_app::<NONZERO_LAYOUT_HEADER_SIZE, 2, 3, 1>(pasta, NUM_NONZERO_LAYOUT_APP_STEPS);

    // Covers the hook regions: the handle instance wires, the eval stage's
    // per-polynomial evaluations, `compute_v`'s one-hot resolution, and the
    // domain tag `challenge_binding` absorbs ahead of each derivation.
    //
    // Includes a challenge derivation's sentinel padding, which is constant
    // rather than allocated; the zero-layout digest has no derivation to cover.
    assert_eq!(
        app.native_registry.digest(),
        fp!(0x13d763cc15fbb0b77fe5ea621f8ca490a058cdea94008374e0606fbdd08eebe0),
        "Native registry digest changed unexpectedly at a nonzero layout!"
    );
    // Covers the nested side: stashed witness-poly commitments, the eval
    // stage's per-polynomial bridges, and the endoscaling growth.
    assert_eq!(
        app.nested_registry.digest(),
        fq!(0x311e83c4ae2b7f40abfb322c76f1b1d58e4da4c804360eeeb1664849dbf9574a),
        "Nested registry digest changed unexpectedly at a nonzero layout!"
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
    let nonzero_layout =
        dummy_app::<NONZERO_LAYOUT_HEADER_SIZE, 2, 3, 1>(pasta, NUM_NONZERO_LAYOUT_APP_STEPS);

    println!("\n// Copy-paste the following into the registry digest tests:");
    println!(
        "    // test_native_registry_digest\n    let expected = fp!(0x{});",
        hex(zero_layout.native_registry.digest())
    );
    println!(
        "    // test_nested_registry_digest\n    let expected = fq!(0x{});",
        hex(zero_layout.nested_registry.digest())
    );
    println!(
        "    // test_nonzero_layout_registry_digests\n    fp!(0x{}),\n    fq!(0x{}),",
        hex(nonzero_layout.native_registry.digest()),
        hex(nonzero_layout.nested_registry.digest())
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

/// Two applications identical but for the layout they declare: every internal
/// circuit the heavy one registers is strictly larger. The layout is the
/// application's own declaration, not a framework constant.
mod layout_is_per_application {
    use ragu_arithmetic::ff::Field;
    use ragu_core::{
        drivers::{Driver, DriverValue},
        gadgets::{Bound, Kind},
        maybe::Maybe,
    };
    use ragu_pasta::{Fp, Pasta};
    use ragu_primitives::{
        Element,
        allocator::{Allocator, Standard},
    };

    use super::*;
    use crate::{
        framework_hooks::{HookConfig, HookLayout},
        header::{Header, Suffix},
        step::{Encoded, Index, Step, StepCtx},
    };

    const HS: usize = 4;

    struct H;

    impl Header<Fp> for H {
        const SUFFIX: Suffix = Suffix::new(50);
        type Data = Fp;
        type Output = Kind![Fp; Element<'_, _>];

        fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
            dr: &mut D,
            allocator: &mut A,
            witness: DriverValue<D, Self::Data>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            Element::alloc(dr, allocator, witness)
        }
    }

    /// A step that uses no framework hooks at all.
    struct Light;

    /// A step that witnesses two polynomials, opens one of them twice, and
    /// derives a challenge.
    struct Heavy;

    impl Step<Pasta> for Light {
        const INDEX: Index = Index::new(0);
        type Witness<'source> = ();
        type Aux<'source> = ();
        type Left = H;
        type Right = H;
        type Output = H;

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const N: usize>(
            &self,
            ctx: &mut StepCtx<'_, 'dr, D, Pasta>,
            _: DriverValue<D, ()>,
            left: DriverValue<D, Fp>,
            right: DriverValue<D, Fp>,
        ) -> Result<(
            (
                Encoded<'dr, D, Self::Left, N>,
                Encoded<'dr, D, Self::Right, N>,
                Encoded<'dr, D, Self::Output, N>,
            ),
            DriverValue<D, Fp>,
            DriverValue<D, ()>,
        )> {
            let allocator = &mut Standard::new();
            let l = Element::alloc(ctx.dr, allocator, left)?;
            let r = Element::alloc(ctx.dr, allocator, right)?;

            let out = l.add(ctx.dr, &r);
            let out_val = Maybe::map(out.value(), |v| *v);
            Ok((
                (
                    Encoded::from_gadget(l),
                    Encoded::from_gadget(r),
                    Encoded::from_gadget(out),
                ),
                out_val,
                D::unit(),
            ))
        }
    }

    impl Step<Pasta> for Heavy {
        const INDEX: Index = Index::new(0);
        type Witness<'source> = ();
        type Aux<'source> = ();
        type Left = H;
        type Right = H;
        type Output = H;

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const N: usize>(
            &self,
            ctx: &mut StepCtx<'_, 'dr, D, Pasta>,
            _: DriverValue<D, ()>,
            left: DriverValue<D, Fp>,
            right: DriverValue<D, Fp>,
        ) -> Result<(
            (
                Encoded<'dr, D, Self::Left, N>,
                Encoded<'dr, D, Self::Right, N>,
                Encoded<'dr, D, Self::Output, N>,
            ),
            DriverValue<D, Fp>,
            DriverValue<D, ()>,
        )> {
            let allocator = &mut Standard::new();
            let l = Element::alloc(ctx.dr, allocator, left)?;
            let r = Element::alloc(ctx.dr, allocator, right)?;

            // Only ever registered, never proved: the hook calls matter, not
            // the values they carry.
            let polynomial = D::try_just(|| {
                Err::<sparse::Polynomial<Fp, R>, _>(Error::InvalidWitness(
                    "this test never builds a proof".into(),
                ))
            })?;
            // Order is call order: `first` is witnessed before `second`.
            let first = ctx.witness_polynomial(Maybe::clone(&polynomial))?;
            let second = ctx.witness_polynomial(polynomial)?;
            let zero = Element::alloc(ctx.dr, &mut Standard::new(), D::just(|| Fp::ZERO))?;
            // Three claims over two polynomials.
            ctx.enforce_poly_query(&first, zero.clone(), zero.clone())?;
            ctx.enforce_poly_query(&first, zero.clone(), zero.clone())?;
            ctx.enforce_poly_query(&second, zero.clone(), zero)?;
            ctx.derive_challenge(&first)?;

            let out = l.add(ctx.dr, &r);
            let out_val = Maybe::map(out.value(), |v| *v);
            Ok((
                (
                    Encoded::from_gadget(l),
                    Encoded::from_gadget(r),
                    Encoded::from_gadget(out),
                ),
                out_val,
                D::unit(),
            ))
        }
    }

    fn gates<J: HookConfig>(
        app: &Application<'_, Pasta, R, HS, J>,
        id: InternalCircuitIndex,
    ) -> usize {
        app.native_registry.constraint_counts(id.circuit_index()).0
    }

    #[test]
    fn a_light_application_pays_less_than_a_heavy_one() {
        let pasta = Pasta::baked();
        let light = ApplicationBuilder::<Pasta, R, HS, NoHooks>::new(pasta)
            .register(Light)
            .unwrap()
            .finalize()
            .unwrap();
        let heavy = ApplicationBuilder::<Pasta, R, HS, AppHooks<2, 3, 1, HANDLE_WIRES>>::new(pasta)
            .register(Heavy)
            .unwrap()
            .finalize()
            .unwrap();

        // The four numbers are distinct, so a `layout()` that crossed two axes
        // fails here rather than downstream. The width is `HANDLE_WIRES`
        // because `Heavy`'s challenge absorbs a handle.
        assert_eq!(
            light.hook_layout(),
            HookLayout {
                challenge_calls: 0,
                challenge_width: 0,
                witness_polys: 0,
                poly_queries: 0,
            }
        );
        assert_eq!(
            heavy.hook_layout(),
            HookLayout {
                challenge_calls: 1,
                challenge_width: HANDLE_WIRES,
                witness_polys: 2,
                poly_queries: 3,
            }
        );

        for id in [
            InternalCircuitIndex::Hashes1Circuit,
            InternalCircuitIndex::OuterCollapseCircuit,
            InternalCircuitIndex::ComputeVCircuit,
            InternalCircuitIndex::ChallengeBindingCircuit,
        ] {
            assert!(
                gates(&light, id) < gates(&heavy, id),
                "{id:?}: light {} is not smaller than heavy {}",
                gates(&light, id),
                gates(&heavy, id),
            );
        }

        // The *2 margin: a step that derives no challenge pays nothing to bind one.
        assert!(
            gates(&light, InternalCircuitIndex::ChallengeBindingCircuit) * 2
                < gates(&heavy, InternalCircuitIndex::ChallengeBindingCircuit),
            "light {} vs heavy {}",
            gates(&light, InternalCircuitIndex::ChallengeBindingCircuit),
            gates(&heavy, InternalCircuitIndex::ChallengeBindingCircuit),
        );
    }
}

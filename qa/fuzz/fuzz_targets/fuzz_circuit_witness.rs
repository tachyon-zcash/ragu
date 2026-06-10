//! Fuzz `Circuit::witness` pipeline correctness against a native oracle.
//!
//! Drives two reference circuits — `SquareCircuit { times }` and
//! `MySimpleCircuit` — with fuzzer-chosen witnesses, and checks pairwise
//! consistency across three pipelines:
//!
//! 1. **Native spec**: a plain Rust function computing each circuit's
//!    output directly from the witness, no driver involved.
//! 2. **Simulator synthesis**: `circuit.witness(&mut Simulator, w)`; the
//!    `Simulator` driver enforces every gate identity inline, then exposes
//!    each output `Element`'s witness value.
//! 3. **Trace + assembly**: `circuit.trace(w)` produces a `Trace`, then
//!    `Registry::assemble_with_alpha` writes it to a sparse polynomial.
//!
//! ## Invariants enforced
//!
//! - **Synthesis correctness**: the Simulator output values equal the
//!    native spec. Catches bugs in any `Circuit::witness` impl that
//!    produces a non-spec output from a satisfying witness, and catches
//!    gadget plumbing bugs that would emit a constraint inconsistent
//!    with the witness it returns.
//! - **Trace-pipeline implication**: if `Simulator::simulate` accepted,
//!    `circuit.trace` must also return `Ok`. The reverse direction does
//!    *not* hold — `trace::eval`'s `enforce_zero` and `gate` are pure
//!    recorders, not constraint checkers (see `trace.rs:226-261`), so an
//!    unsatisfying witness produces `Err` from `Simulator` and `Ok` from
//!    `trace::eval` by design. Constraint checking is the Simulator's
//!    job; trace's job is to record values for later assembly into a
//!    polynomial whose algebraic identity is checked downstream.
//! - **`alpha` injection contract**: assembling the same trace twice with
//!    distinct `alpha_a` and `alpha_b` produces two polynomials that
//!    differ in exactly one coefficient position, with the difference
//!    equal to `alpha_a - alpha_b`. `Registry::assemble_with_alpha`
//!    documents that `alpha` is written to `a[0]` and used nowhere else;
//!    this catches any future regression that leaks `alpha` into another
//!    slot (which would break commit-blinding / point-at-infinity
//!    protection).
//!
//! ## Circuit coverage
//!
//! `SquareCircuit` exercises a single gadget (`Element::square`) in a
//! parameterized loop. `MySimpleCircuit` exercises `Element::square`,
//! `Element::mul`, `Element::add`, `Element::sub`, and an explicit
//! `Driver::enforce_zero` constraint over a two-element witness with a
//! two-element output. Together they cover most of `Element`'s arithmetic
//! surface.
//!
//! Circuit menu (each is a `CircuitChoice` arm exercising one gadget
//! family end-to-end through `Circuit::witness`):
//!
//! - **`SquareCircuit`** — `Element::square` loop.
//! - **`MySimpleCircuit`** — `Element::{square, mul, add, sub}` plus an
//!   explicit `Driver::enforce_zero` constraint.
//! - **`BoolCircuit`** — `Boolean::{alloc, and, not, conditional_select}`.
//! - **`PointCircuit`** — `Point::{alloc, endo, negate}` over `EpAffine`,
//!   complementing `fuzz_endoscalar`'s gadget-level coverage with an
//!   end-to-end Circuit-pipeline path.
//! - **`RoutineCircuit`** — `Driver::routine` plus an inline
//!   `Routine::{predict, execute}` split via `Prediction::Unknown(aux)`
//!   (the `ScaleByThree` routine).
//! - **`KnownRoutineCircuit`** — the `Prediction::Known(output, aux)`
//!   branch of Routine, the path that lets witness drivers short-circuit
//!   `execute` (the `DoubleKnown` routine).
//!
//! Multi-stage circuits (`StageBuilder`, `MultiStage`, `MultiStageCircuit`)
//! are covered by the sibling `fuzz_staging` target, not here. The
//! remaining gaps (exotic point ops `double_and_add_incomplete`, longer
//! routine chains, multi-routine compositions) can be added as further
//! `CircuitChoice` arms when warranted.
//!
//! ## What this does not catch (deferred — issue #709)
//!
//! The full algebraic identity from `tests/mod.rs:158-187` —
//! `a.revdot(b) == circuit.ky(instance, y)` where
//! `b = r + r.dilate(z) + obj.sy(y, &plan) + Rank::tz(z)` — is the
//! strongest oracle for the synthesis layer and the algebraic bridge
//! between this target (witness-driver side) and `fuzz_sxy_agreement`
//! (wiring/constraint side). Its construction requires
//! `WiringObject::sy` and `Rank::tz`, both `pub(crate)` in
//! `ragu_circuits`, so it is deferred to a separate `unstable-fuzzing`-
//! gated target.

#![no_main]

use arbitrary::Arbitrary;
use core::cell::OnceCell;
use ff::Field;
use ff::PrimeField;
use ff::WithSmallOrderMulGroup;
use group::Curve;
use group::CurveAffine as _;
use pasta_curves::arithmetic::CurveAffine;
use libfuzzer_sys::fuzz_target;
use pasta_curves::Fp;
use ragu_arithmetic::Coeff;
use ragu_circuits::{
    Circuit, CircuitExt, WithAux,
    polynomials::TestRank,
    registry::{CircuitIndex, Registry, RegistryBuilder},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue, LinearExpression},
    gadgets::{Bound, Kind},
    maybe::Maybe,
    routines::{Prediction, Routine},
};
use ragu_pasta::{EpAffine, Fq};
use ragu_primitives::{Boolean, Element, Point, Simulator, allocator::Standard};
use ragu_testing::circuits::{MySimpleCircuit, SquareCircuit};
use std::sync::LazyLock;

#[derive(Arbitrary, Debug)]
enum CircuitChoice {
    /// `SquareCircuit { times }` over a single-Fp witness.
    Square {
        times: u8,
        witness_seed: u64,
        use_special: Option<u8>,
    },
    /// `MySimpleCircuit` over a `(Fp, Fp)` witness. The circuit's internal
    /// constraint is `a^5 == b^2`; many randomly chosen `(a, b)` pairs will
    /// not satisfy it (drivers will reject). The `derive_b_from_a` mode
    /// picks `b = sqrt(a^5)` so the witness is always satisfying.
    Simple {
        a_seed: u64,
        b_seed: u64,
        use_special_a: Option<u8>,
        derive_b_from_a: bool,
    },
    /// `BoolCircuit` over a `(bool, bool, Fp, Fp)` witness. Exercises
    /// `Boolean::{alloc, and, not, conditional_select}`.
    Bool {
        b0: bool,
        b1: bool,
        x_seed: u64,
        y_seed: u64,
        use_special_x: Option<u8>,
    },
    /// `PointCircuit` over an `EpAffine` witness derived from a fuzzer-chosen
    /// Fq scalar. Exercises `Point::{alloc, endo, negate}` end-to-end through
    /// `Circuit::witness`.
    Point {
        scalar_seed: u64,
    },
    /// `RoutineCircuit` over a single Fp witness. Exercises
    /// `Driver::routine` and the `Routine::{predict, execute}` split via
    /// the `Prediction::Unknown(aux)` path.
    Routine {
        witness_seed: u64,
        use_special: Option<u8>,
    },
    /// `KnownRoutineCircuit` over a single Fp witness. Exercises the
    /// `Prediction::Known(output, aux)` branch of the Routine trait —
    /// the branch that lets witness drivers short-circuit `execute`.
    /// Catches Routine impls that mis-construct the predicted-output
    /// gadget while still satisfying the synthesis-side aux contract.
    KnownRoutine {
        witness_seed: u64,
        use_special: Option<u8>,
    },
}

#[derive(Arbitrary, Debug)]
struct Input {
    circuit: CircuitChoice,
    alpha_a_seed: u64,
    alpha_b_seed: u64,
}

/// Edge-case field elements that exercise boundary behavior.
fn special_value(idx: u8) -> Fp {
    match idx % 8 {
        0 => Fp::ZERO,
        1 => Fp::ONE,
        2 => -Fp::ONE,
        3 => Fp::TWO_INV,
        4 => Fp::ROOT_OF_UNITY,
        5 => Fp::MULTIPLICATIVE_GENERATOR,
        6 => Fp::from(1u64 << 32),
        _ => Fp::from(u64::MAX),
    }
}

/// Per-`times` registry cache for `SquareCircuit`. Building a registry
/// runs the floor planner over `times` squarings — comfortably more
/// expensive than the per-input checks. Memoizing across inputs turns
/// the hot path into trace + assemble after each distinct `times` is
/// observed once. Mirrors the cache in `fuzz_sxy_agreement.rs:42-69`.
struct SquareRegistryCache {
    slots: [OnceCell<core::result::Result<Registry<'static, Fp, TestRank>, ()>>; 120],
}

// SAFETY: libfuzzer runs the fuzz target on a single thread, so the
// interior-mutable `OnceCell` slots are never accessed concurrently.
// `LazyLock` requires `Sync` to compile.
unsafe impl Sync for SquareRegistryCache {}

static SQUARE_REGISTRY_CACHE: LazyLock<SquareRegistryCache> =
    LazyLock::new(|| SquareRegistryCache {
        slots: [const { OnceCell::new() }; 120],
    });

fn square_registry_for(times: usize) -> Option<&'static Registry<'static, Fp, TestRank>> {
    debug_assert!((1..=120).contains(&times));
    SQUARE_REGISTRY_CACHE.slots[times - 1]
        .get_or_init(|| {
            let circuit = SquareCircuit { times };
            RegistryBuilder::<Fp, TestRank>::new()
                .register_circuit(circuit)
                .and_then(|b| b.finalize())
                .map_err(|_| ())
        })
        .as_ref()
        .ok()
}

/// `MySimpleCircuit` takes no parameters, so a single global memoized
/// registry suffices.
static SIMPLE_REGISTRY: LazyLock<Option<Registry<'static, Fp, TestRank>>> = LazyLock::new(|| {
    RegistryBuilder::<Fp, TestRank>::new()
        .register_circuit(MySimpleCircuit)
        .and_then(|b| b.finalize())
        .ok()
});

static BOOL_REGISTRY: LazyLock<Option<Registry<'static, Fp, TestRank>>> = LazyLock::new(|| {
    RegistryBuilder::<Fp, TestRank>::new()
        .register_circuit(BoolCircuit)
        .and_then(|b| b.finalize())
        .ok()
});

static POINT_REGISTRY: LazyLock<Option<Registry<'static, Fp, TestRank>>> = LazyLock::new(|| {
    RegistryBuilder::<Fp, TestRank>::new()
        .register_circuit(PointCircuit)
        .and_then(|b| b.finalize())
        .ok()
});

static ROUTINE_REGISTRY: LazyLock<Option<Registry<'static, Fp, TestRank>>> = LazyLock::new(|| {
    RegistryBuilder::<Fp, TestRank>::new()
        .register_circuit(RoutineCircuit)
        .and_then(|b| b.finalize())
        .ok()
});

static KNOWN_ROUTINE_REGISTRY: LazyLock<Option<Registry<'static, Fp, TestRank>>> =
    LazyLock::new(|| {
        RegistryBuilder::<Fp, TestRank>::new()
            .register_circuit(KnownRoutineCircuit)
            .and_then(|b| b.finalize())
            .ok()
    });

/// Native spec for `SquareCircuit`: compute `w^(2^times)` by repeated
/// squaring directly in the field.
fn square_native(witness: Fp, times: usize) -> Fp {
    let mut acc = witness;
    for _ in 0..times {
        acc = acc.square();
    }
    acc
}

/// Native spec for `MySimpleCircuit`. Returns:
/// - `Some((c, d))` if the witness satisfies `a^5 == b^2`, with
///    `c = a + b`, `d = a - b`.
/// - `None` if the witness violates the constraint; both `Simulator` and
///    `trace::eval` must reject.
fn simple_native(a: Fp, b: Fp) -> Option<(Fp, Fp)> {
    let a5 = a.pow_vartime([5u64]);
    let b2 = b.square();
    if a5 != b2 {
        return None;
    }
    Some((a + b, a - b))
}

/// Try to compute `b = sqrt(a^5)` so that `(a, b)` is a satisfying witness
/// for `MySimpleCircuit`. Returns `None` if `a^5` is a non-residue.
fn derive_satisfying_b(a: Fp) -> Option<Fp> {
    Option::<Fp>::from(a.pow_vartime([5u64]).sqrt())
}

// ---------------------------------------------------------------------------
// BoolCircuit — exercises `Boolean::alloc`, `Boolean::and`, `Boolean::not`,
// and `Boolean::conditional_select`. Output is the conditional-selected
// element value.
// ---------------------------------------------------------------------------

struct BoolCircuit;

impl Circuit<Fp> for BoolCircuit {
    type Instance<'instance> = Fp;
    type Output = Kind![Fp; Element<'_, _>];
    type Witness<'witness> = (bool, bool, Fp, Fp);
    type Aux<'witness> = ();

    fn instance<'dr, 'instance: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'instance>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let allocator = &mut Standard::new();
        Element::alloc(dr, allocator, instance)
    }

    fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'witness>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'witness>>>> {
        let allocator = &mut Standard::new();
        let b0 = Boolean::alloc(dr, allocator, witness.as_ref().map(|w| w.0))?;
        let b1 = Boolean::alloc(dr, allocator, witness.as_ref().map(|w| w.1))?;
        let x = Element::alloc(dr, allocator, witness.as_ref().map(|w| w.2))?;
        let y = Element::alloc(dr, allocator, witness.as_ref().map(|w| w.3))?;
        let and_b = b0.and(dr, &b1)?;
        // `not(b0)` constraint already pinned to `b0` by the alloc; we
        // invoke it for its synthesis side-effect (exercises the
        // linear-combination path that produces a new wire) and drop
        // the result. The Bound is dropped without being written.
        let _not_b = b0.not(dr);
        let sel = and_b.conditional_select(dr, &x, &y)?;
        Ok(WithAux::new(sel, D::unit()))
    }
}

/// Native spec for `BoolCircuit`: matches the
/// `and_b.conditional_select(x, y)` invocation in `witness`. Per
/// `Boolean::conditional_select(a, b)` — returns `a` when the boolean
/// is false, `b` when true — so the result is `y` iff `b0 && b1`.
fn bool_native(b0: bool, b1: bool, x: Fp, y: Fp) -> Fp {
    if b0 && b1 { y } else { x }
}

// ---------------------------------------------------------------------------
// PointCircuit — exercises the `Point<EpAffine>` gadget end-to-end through
// `Circuit::witness`. `fuzz_endoscalar` exercises the same gadgets at the
// Vec<Op> dispatch level but never through the higher-layer Circuit
// pipeline, so this closes a gap.
// ---------------------------------------------------------------------------

struct PointCircuit;

impl Circuit<Fp> for PointCircuit {
    type Instance<'instance> = EpAffine;
    type Output = Kind![Fp; Point<'_, _, EpAffine>];
    type Witness<'witness> = EpAffine;
    type Aux<'witness> = ();

    fn instance<'dr, 'instance: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'instance>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Point::alloc(dr, instance)
    }

    fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'witness>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'witness>>>> {
        let p = Point::alloc(dr, witness)?;
        let endo_p = p.endo(dr);
        let negated = endo_p.negate(dr);
        Ok(WithAux::new(negated, D::unit()))
    }
}

/// Native spec for `PointCircuit`: apply endo then negate, on the base
/// `EpAffine` value. Returns `None` if the witness or any intermediate
/// would be the point at infinity (which `Point::alloc` rejects).
fn point_native(base: EpAffine) -> Option<EpAffine> {
    let coords = base.coordinates().into_option()?;
    let endo_x = *coords.x() * Fp::ZETA;
    let endo_p = EpAffine::from_xy(endo_x, *coords.y()).into_option()?;
    Some((-endo_p.to_curve()).to_affine())
}

// ---------------------------------------------------------------------------
// RoutineCircuit — exercises `Driver::routine` and the
// `Routine::predict` / `Routine::execute` split. The routine triples its
// input; the circuit invokes it once and returns the tripled element.
// ---------------------------------------------------------------------------

/// Routine that triples its input: `output = 3 * input`. Designed to
/// exercise the full `predict` (native aux computation on a wireless
/// emulator) + `execute` (driver-side constraint emission) split.
#[derive(Clone)]
struct ScaleByThree;

impl Routine<Fp> for ScaleByThree {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = Fp;

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let allocator = &mut Standard::new();
        let output = Element::alloc(dr, allocator, aux)?;
        let three_input = input.scale(dr, Coeff::Arbitrary(Fp::from(3u64)));
        dr.enforce_zero(|lc| lc.add(three_input.wire()).sub(output.wire()))?;
        Ok(output)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp, Wire = ()>>(
        &self,
        _dr: &mut D,
        input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        let aux = input.value().map(|v| *v * Fp::from(3u64));
        Ok(Prediction::Unknown(aux))
    }
}

struct RoutineCircuit;

impl Circuit<Fp> for RoutineCircuit {
    type Instance<'instance> = Fp;
    type Output = Kind![Fp; Element<'_, _>];
    type Witness<'witness> = Fp;
    type Aux<'witness> = ();

    fn instance<'dr, 'instance: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'instance>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let allocator = &mut Standard::new();
        Element::alloc(dr, allocator, instance)
    }

    fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'witness>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'witness>>>>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let x = Element::alloc(dr, allocator, witness)?;
        let result = dr.routine(ScaleByThree, x)?;
        Ok(WithAux::new(result, D::unit()))
    }
}

/// Native spec for `RoutineCircuit`: `output = 3 * witness`.
fn routine_native(witness: Fp) -> Fp {
    witness * Fp::from(3u64)
}

// ---------------------------------------------------------------------------
// KnownRoutineCircuit — exercises the `Prediction::Known(output, aux)`
// branch of the Routine trait. `ScaleByThree` above uses
// `Prediction::Unknown(aux)`; `DoubleKnown` returns
// `Prediction::Known(predicted_output, aux)`, letting witness-extraction
// drivers short-circuit execution if they choose to. Catches Routine
// impls that mis-construct the predicted-output gadget (wrong wire shape
// or wrong predicted value) — bugs that an Unknown-only routine cannot
// surface because witness drivers never see the predicted output there.
// ---------------------------------------------------------------------------

/// Routine that doubles its input. `predict` returns
/// `Prediction::Known(predicted_elem, aux)` so witness drivers can
/// skip `execute`; synthesis drivers (which always call `execute`) use
/// the `aux` value to allocate the output and enforce the relation.
#[derive(Clone)]
struct DoubleKnown;

impl Routine<Fp> for DoubleKnown {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = Fp;

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let allocator = &mut Standard::new();
        let output = Element::alloc(dr, allocator, aux)?;
        // Enforce: 2 * input - output == 0 via Element::double.
        let two_input = input.double(dr);
        dr.enforce_zero(|lc| lc.add(two_input.wire()).sub(output.wire()))?;
        Ok(output)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp, Wire = ()>>(
        &self,
        dr: &mut D,
        input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        let aux = input.value().map(|v| *v * Fp::from(2u64));
        // Allocate the predicted output on the wireless predict driver
        // (Wire = ()). This is what distinguishes Known from Unknown:
        // we hand the witness driver a fully-constructed output gadget,
        // not just an aux value.
        let allocator = &mut Standard::new();
        let predicted_output =
            Element::alloc(dr, allocator, input.value().map(|v| *v * Fp::from(2u64)))?;
        Ok(Prediction::Known(predicted_output, aux))
    }
}

struct KnownRoutineCircuit;

impl Circuit<Fp> for KnownRoutineCircuit {
    type Instance<'instance> = Fp;
    type Output = Kind![Fp; Element<'_, _>];
    type Witness<'witness> = Fp;
    type Aux<'witness> = ();

    fn instance<'dr, 'instance: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'instance>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let allocator = &mut Standard::new();
        Element::alloc(dr, allocator, instance)
    }

    fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'witness>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'witness>>>>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let x = Element::alloc(dr, allocator, witness)?;
        let result = dr.routine(DoubleKnown, x)?;
        Ok(WithAux::new(result, D::unit()))
    }
}

/// Native spec for `KnownRoutineCircuit`: `output = 2 * witness`.
fn known_routine_native(witness: Fp) -> Fp {
    witness * Fp::from(2u64)
}

/// Run the differential alpha-injection check on an assembled trace.
/// Asserts that two assemblies with distinct `alpha`s differ in exactly
/// one coefficient position, by exactly the alpha delta. Returns `()` on
/// success, `None` if either assembly errored (skip the iteration), and
/// panics on a violated invariant.
fn check_alpha_injection(
    registry: &Registry<'_, Fp, TestRank>,
    trace: &ragu_circuits::Trace<Fp>,
    alpha_a: Fp,
    alpha_b: Fp,
) -> Option<()> {
    let idx = CircuitIndex::new(0);
    let poly_a = registry.assemble_with_alpha(trace, idx, alpha_a).ok()?;
    let poly_b = registry.assemble_with_alpha(trace, idx, alpha_b).ok()?;

    let coeffs_a: Vec<Fp> = poly_a.iter_coeffs().collect();
    let coeffs_b: Vec<Fp> = poly_b.iter_coeffs().collect();
    assert_eq!(
        coeffs_a.len(),
        coeffs_b.len(),
        "assemble_with_alpha produced polynomials of different length"
    );

    let mut diff_count = 0usize;
    let mut diff_idx = usize::MAX;
    for i in 0..coeffs_a.len() {
        if coeffs_a[i] != coeffs_b[i] {
            diff_count += 1;
            diff_idx = i;
        }
    }
    assert_eq!(
        diff_count, 1,
        "alpha leaked into {diff_count} coefficient positions (expected 1)"
    );
    assert_eq!(
        coeffs_a[diff_idx] - coeffs_b[diff_idx],
        alpha_a - alpha_b,
        "alpha delta mismatch at coefficient position {diff_idx}"
    );
    Some(())
}

fuzz_target!(|input: Input| {
    if std::env::var("DEBUG_INPUT").is_ok() {
        eprintln!("{:#?}", input);
        return;
    }

    // Decode shared alpha pair. Differential check needs distinct values.
    let alpha_a = Fp::from(input.alpha_a_seed);
    let alpha_b = Fp::from(input.alpha_b_seed);
    let alphas_distinct = input.alpha_a_seed != input.alpha_b_seed && alpha_a != alpha_b;

    match input.circuit {
        CircuitChoice::Square {
            times,
            witness_seed,
            use_special,
        } => {
            let times = ((times as usize) % 120).max(1);
            let witness: Fp = match use_special {
                Some(idx) => special_value(idx),
                None => Fp::from(witness_seed),
            };
            let registry = match square_registry_for(times) {
                Some(r) => r,
                None => return, // rank-bound exceeded for high `times`
            };
            let circuit = SquareCircuit { times };
            let expected = square_native(witness, times);

            let mut sim_value: Option<Fp> = None;
            let sim_result = Simulator::<Fp>::simulate(witness, |dr, w_just| {
                let cw = circuit.witness(dr, w_just)?;
                let elem = cw.into_output();
                sim_value = Some(*elem.value().take());
                Ok(())
            });

            if sim_result.is_err() {
                // `SquareCircuit` has no `enforce_zero` constraints, so
                // any Simulator rejection here would be a plumbing bug;
                // surface it before returning.
                panic!(
                    "Simulator rejected SquareCircuit witness={witness:?} times={times} \
                     — SquareCircuit has no constraints that could fail"
                );
            }

            let sim_value = sim_value.expect("Simulator Ok without writing value");
            assert_eq!(
                sim_value, expected,
                "SquareCircuit: synthesis output != native w^(2^times): \
                 witness={witness:?}, times={times}, sim={sim_value:?}, expected={expected:?}"
            );

            // Simulator accepted, so trace::eval must accept too (one-way
            // implication; see header docstring).
            let trace = match circuit.trace(witness) {
                Ok(t) => t.into_output(),
                Err(_) => panic!(
                    "trace::eval rejected SquareCircuit witness={witness:?} times={times} \
                     but Simulator accepted — driver disagreement"
                ),
            };

            if alphas_distinct {
                check_alpha_injection(registry, &trace, alpha_a, alpha_b);
            }
        }

        CircuitChoice::Simple {
            a_seed,
            b_seed,
            use_special_a,
            derive_b_from_a,
        } => {
            let a: Fp = match use_special_a {
                Some(idx) => special_value(idx),
                None => Fp::from(a_seed),
            };
            let b: Fp = if derive_b_from_a {
                match derive_satisfying_b(a) {
                    Some(v) => v,
                    None => return, // a^5 is a non-residue; skip
                }
            } else {
                Fp::from(b_seed)
            };

            let registry = match SIMPLE_REGISTRY.as_ref() {
                Some(r) => r,
                None => return,
            };
            let circuit = MySimpleCircuit;
            let expected = simple_native(a, b); // None iff a^5 != b^2

            let mut sim_value: Option<(Fp, Fp)> = None;
            let sim_result = Simulator::<Fp>::simulate((a, b), |dr, w_just| {
                let cw = circuit.witness(dr, w_just)?;
                let (c_elem, d_elem) = cw.into_output();
                sim_value = Some((*c_elem.value().take(), *d_elem.value().take()));
                Ok(())
            });

            // Simulator is the constraint checker. Its accept/reject must
            // match the native prediction (`expected.is_some()`).
            match (expected, sim_result.is_ok()) {
                (None, true) => panic!(
                    "MySimpleCircuit: Simulator accepted unsatisfying witness \
                     a={a:?}, b={b:?} (a^5 != b^2)"
                ),
                (Some(_), false) => panic!(
                    "MySimpleCircuit: Simulator rejected satisfying witness \
                     a={a:?}, b={b:?}"
                ),
                _ => {}
            }

            // trace::eval is a pure recorder; it accepts any witness that
            // can be evaluated, satisfying or not. The required implication
            // is one-way: Simulator accept ⇒ trace accept.
            let trace_result = circuit.trace((a, b));
            if sim_result.is_ok() && trace_result.is_err() {
                panic!(
                    "MySimpleCircuit: Simulator accepted but trace::eval rejected \
                     for a={a:?}, b={b:?} — driver disagreement"
                );
            }

            // Output-value check requires a satisfying witness (Simulator
            // accepted). For unsatisfying witnesses we skip the output check
            // but still exercise assembly if trace::eval recorded values.
            if let Some((expected_c, expected_d)) = expected {
                let (sim_c, sim_d) = sim_value.expect("Simulator Ok without writing value");
                assert_eq!(
                    sim_c, expected_c,
                    "MySimpleCircuit: c output != a+b for a={a:?}, b={b:?}"
                );
                assert_eq!(
                    sim_d, expected_d,
                    "MySimpleCircuit: d output != a-b for a={a:?}, b={b:?}"
                );
            }

            // assemble_with_alpha is a property of the assembly function,
            // independent of whether the underlying witness is satisfying,
            // so we run it on any trace::eval success.
            if let Ok(trace) = trace_result {
                let trace = trace.into_output();
                if alphas_distinct {
                    check_alpha_injection(registry, &trace, alpha_a, alpha_b);
                }
            }
        }

        CircuitChoice::Bool {
            b0,
            b1,
            x_seed,
            y_seed,
            use_special_x,
        } => {
            let registry = match BOOL_REGISTRY.as_ref() {
                Some(r) => r,
                None => return,
            };
            let x: Fp = match use_special_x {
                Some(idx) => special_value(idx),
                None => Fp::from(x_seed),
            };
            let y = Fp::from(y_seed);
            let witness = (b0, b1, x, y);
            let circuit = BoolCircuit;
            let expected = bool_native(b0, b1, x, y);

            let mut sim_value: Option<Fp> = None;
            let sim_result = Simulator::<Fp>::simulate(witness, |dr, w_just| {
                let cw = circuit.witness(dr, w_just)?;
                let elem = cw.into_output();
                sim_value = Some(*elem.value().take());
                Ok(())
            });

            if sim_result.is_err() {
                panic!(
                    "Simulator rejected BoolCircuit witness={witness:?} \
                     — BoolCircuit has no constraints that should fail for bool inputs"
                );
            }

            let sim_value = sim_value.expect("Simulator Ok without writing value");
            assert_eq!(
                sim_value, expected,
                "BoolCircuit: synthesis output != native conditional_select: \
                 witness={witness:?}, sim={sim_value:?}, expected={expected:?}"
            );

            let trace = match circuit.trace(witness) {
                Ok(t) => t.into_output(),
                Err(_) => panic!(
                    "trace::eval rejected BoolCircuit witness={witness:?} \
                     but Simulator accepted — driver disagreement"
                ),
            };

            if alphas_distinct {
                check_alpha_injection(registry, &trace, alpha_a, alpha_b);
            }
        }

        CircuitChoice::Point { scalar_seed } => {
            // scalar=0 gives the identity; Point::alloc rejects it. Skip.
            if scalar_seed == 0 {
                return;
            }
            let base = (EpAffine::generator() * Fq::from(scalar_seed)).to_affine();
            let registry = match POINT_REGISTRY.as_ref() {
                Some(r) => r,
                None => return,
            };
            let circuit = PointCircuit;
            let expected: EpAffine = match point_native(base) {
                Some(p) => p,
                None => return, // intermediate hit identity; skip
            };

            let mut sim_value: Option<EpAffine> = None;
            let sim_result = Simulator::<Fp>::simulate(base, |dr, w_just| {
                let cw = circuit.witness(dr, w_just)?;
                let point = cw.into_output();
                sim_value = Some(point.value().take());
                Ok(())
            });

            if sim_result.is_err() {
                // PointCircuit's only failure mode is Point::alloc on
                // identity, which we filtered above. Anything else is a
                // plumbing bug.
                panic!(
                    "Simulator rejected PointCircuit on a non-identity base \
                     (scalar={scalar_seed}): {:?}",
                    sim_result.err()
                );
            }

            let sim_value = sim_value.expect("Simulator Ok without writing value");
            assert_eq!(
                sim_value, expected,
                "PointCircuit: synthesis output != native endo→negate: \
                 scalar={scalar_seed}, sim={sim_value:?}, expected={expected:?}"
            );

            let trace = match circuit.trace(base) {
                Ok(t) => t.into_output(),
                Err(_) => panic!(
                    "trace::eval rejected PointCircuit scalar={scalar_seed} \
                     but Simulator accepted — driver disagreement"
                ),
            };

            if alphas_distinct {
                check_alpha_injection(registry, &trace, alpha_a, alpha_b);
            }
        }

        CircuitChoice::Routine {
            witness_seed,
            use_special,
        } => {
            let registry = match ROUTINE_REGISTRY.as_ref() {
                Some(r) => r,
                None => return,
            };
            let witness: Fp = match use_special {
                Some(idx) => special_value(idx),
                None => Fp::from(witness_seed),
            };
            let circuit = RoutineCircuit;
            let expected = routine_native(witness);

            let mut sim_value: Option<Fp> = None;
            let sim_result = Simulator::<Fp>::simulate(witness, |dr, w_just| {
                let cw = circuit.witness(dr, w_just)?;
                let elem = cw.into_output();
                sim_value = Some(*elem.value().take());
                Ok(())
            });

            if sim_result.is_err() {
                panic!(
                    "Simulator rejected RoutineCircuit witness={witness:?} \
                     — RoutineCircuit's ScaleByThree should accept any Fp witness"
                );
            }

            let sim_value = sim_value.expect("Simulator Ok without writing value");
            assert_eq!(
                sim_value, expected,
                "RoutineCircuit: synthesis output != native 3 * witness: \
                 witness={witness:?}, sim={sim_value:?}, expected={expected:?}"
            );

            let trace = match circuit.trace(witness) {
                Ok(t) => t.into_output(),
                Err(_) => panic!(
                    "trace::eval rejected RoutineCircuit witness={witness:?} \
                     but Simulator accepted — driver disagreement"
                ),
            };

            if alphas_distinct {
                check_alpha_injection(registry, &trace, alpha_a, alpha_b);
            }
        }

        CircuitChoice::KnownRoutine {
            witness_seed,
            use_special,
        } => {
            let registry = match KNOWN_ROUTINE_REGISTRY.as_ref() {
                Some(r) => r,
                None => return,
            };
            let witness: Fp = match use_special {
                Some(idx) => special_value(idx),
                None => Fp::from(witness_seed),
            };
            let circuit = KnownRoutineCircuit;
            let expected = known_routine_native(witness);

            let mut sim_value: Option<Fp> = None;
            let sim_result = Simulator::<Fp>::simulate(witness, |dr, w_just| {
                let cw = circuit.witness(dr, w_just)?;
                let elem = cw.into_output();
                sim_value = Some(*elem.value().take());
                Ok(())
            });

            if sim_result.is_err() {
                panic!(
                    "Simulator rejected KnownRoutineCircuit witness={witness:?} \
                     — DoubleKnown should accept any Fp witness"
                );
            }

            let sim_value = sim_value.expect("Simulator Ok without writing value");
            assert_eq!(
                sim_value, expected,
                "KnownRoutineCircuit: synthesis output != native 2 * witness: \
                 witness={witness:?}, sim={sim_value:?}, expected={expected:?}"
            );

            let trace = match circuit.trace(witness) {
                Ok(t) => t.into_output(),
                Err(_) => panic!(
                    "trace::eval rejected KnownRoutineCircuit witness={witness:?} \
                     but Simulator accepted — driver disagreement"
                ),
            };

            if alphas_distinct {
                check_alpha_injection(registry, &trace, alpha_a, alpha_b);
            }
        }
    }
});

//! Fuzz the canonical algebraic identity that bridges the witness-driver
//! and wiring/constraint sides of the synthesis pipeline.
//!
//! For a satisfying witness `w` of a registered `Circuit`, with assembled
//! trace polynomial `r`, the identity from `tests/mod.rs:158-187` is:
//!
//! ```text
//! r.revdot(b) == circuit.ky(instance, y)
//! where b = r + r.dilate(z) + s(X, y) + t(X, z)
//! ```
//!
//! `r` is the witness-side polynomial (assembled trace); `s(X, y)` is
//! the wiring polynomial restricted at `y`; `t(X, z)` is the registry
//! key constraint polynomial restricted at `z`; `circuit.ky(instance, y)`
//! is the instance polynomial evaluated at `y`. The equality is what
//! actually proves "this witness satisfies this circuit's constraints"
//! at the algebraic layer; under random `(y, z)` it holds with
//! overwhelming probability iff the witness is satisfying.
//!
//! This is the deferred Layer-1 strong oracle that `fuzz_circuit_witness`
//! could not implement with pub APIs alone. Here we sidestep the
//! `pub(crate)` `WiringObject::sy` by deriving `s(X, y)` from the public
//! `Registry::wy(omega_0, y)` minus the registry key term — valid for a
//! single-circuit registry whose circuit doesn't `is_mask()` (covers
//! `SquareCircuit` and `MySimpleCircuit`). When richer test circuits
//! land (staging, masking), or when we want to fuzz multi-circuit
//! registries, this trick stops working and the `unstable-fuzzing`
//! feature exposure of `WiringObject::sy` becomes the necessary path.
//!
//! ## What this catches
//!
//! - Witness pipeline bugs that produce a `Trace` whose assembled
//!   polynomial fails the algebraic identity — the strongest signal at
//!   this layer, equivalent to "the witness doesn't satisfy the
//!   constraint system."
//! - `Registry::wy` regressions where the key term is double-counted,
//!   omitted, or placed in the wrong slot.
//! - `Rank::tz` regressions in the key constraint polynomial
//!   construction.
//! - `Polynomial::revdot` regressions where the dot product over the
//!   reversed coefficient vector miscomputes.
//!
//! ## Circuit coverage
//!
//! Reuses `SquareCircuit { times }` and `MySimpleCircuit` from
//! `ragu_testing::circuits`. `MySimpleCircuit` runs only on satisfying
//! witnesses (`b = sqrt(a^5)`), since the algebraic identity is
//! meaningful only for witnesses that satisfy the circuit. `SquareCircuit`
//! has no `enforce_zero` constraints, so every witness is trivially
//! satisfying.
//!
//! See `fuzz_circuit_witness.rs` for the weaker pub-API-only invariants
//! (Simulator output vs native, trace/Simulator accept implication,
//! alpha injection contract).

#![no_main]

use arbitrary::Arbitrary;
use core::cell::OnceCell;
use ff::Field;
use ff::PrimeField;
use libfuzzer_sys::fuzz_target;
use pasta_curves::Fp;
use ragu_circuits::{
    CircuitExt, Trace,
    polynomials::{Rank, TestRank, sparse},
    registry::{CircuitIndex, Registry, RegistryBuilder},
};
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
    /// `MySimpleCircuit` over `(a, b = sqrt(a^5))`. We force a satisfying
    /// witness here because the algebraic identity is meaningful only
    /// for accepted witnesses; the rejection path is covered by
    /// `fuzz_circuit_witness`.
    Simple {
        a_seed: u64,
        use_special_a: Option<u8>,
    },
}

#[derive(Arbitrary, Debug)]
struct Input {
    circuit: CircuitChoice,
    y_seed: u64,
    z_seed: u64,
}

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

/// Per-`times` registry cache for `SquareCircuit`. Same shape as
/// `fuzz_circuit_witness.rs`.
struct SquareRegistryCache {
    slots: [OnceCell<Result<Registry<'static, Fp, TestRank>, ()>>; 120],
}

// SAFETY: libfuzzer runs the fuzz target on a single thread.
unsafe impl Sync for SquareRegistryCache {}

static SQUARE_REGISTRY_CACHE: LazyLock<SquareRegistryCache> =
    LazyLock::new(|| SquareRegistryCache {
        slots: [const { OnceCell::new() }; 120],
    });

fn square_registry_for(times: usize) -> Option<&'static Registry<'static, Fp, TestRank>> {
    debug_assert!((1..=120).contains(&times));
    SQUARE_REGISTRY_CACHE.slots[times - 1]
        .get_or_init(|| {
            RegistryBuilder::<Fp, TestRank>::new()
                .register_circuit(SquareCircuit { times })
                .and_then(|b| b.finalize())
                .map_err(|_| ())
        })
        .as_ref()
        .ok()
}

static SIMPLE_REGISTRY: LazyLock<Option<Registry<'static, Fp, TestRank>>> = LazyLock::new(|| {
    RegistryBuilder::<Fp, TestRank>::new()
        .register_circuit(MySimpleCircuit)
        .and_then(|b| b.finalize())
        .ok()
});

fn square_native(witness: Fp, times: usize) -> Fp {
    let mut acc = witness;
    for _ in 0..times {
        acc = acc.square();
    }
    acc
}

/// Try to compute `b = sqrt(a^5)` so that `(a, b)` is a satisfying witness
/// for `MySimpleCircuit`. Returns `None` if `a^5` is a non-residue.
fn derive_satisfying_b(a: Fp) -> Option<Fp> {
    Option::<Fp>::from(a.pow_vartime([5u64]).sqrt())
}

/// Compute `s(X, y)` for a single-circuit registry by stripping the
/// registry key term from `Registry::wy(omega_0, y)`. The key term lives
/// at the `c` wire of slot `R::n() - 1` (the X^{4n-1} position), with
/// coefficient `key.value() * y^{4n-1}` (see `registry.rs:589-597`).
///
/// Valid only when the circuit at index 0 doesn't `is_mask()` — true
/// for both `SquareCircuit` and `MySimpleCircuit`. For masked or
/// multi-circuit registries the wy decomposition picks up a global term
/// and Lagrange-weighted sums of per-circuit `sy`s, so this trick
/// stops working.
fn sy_from_registry(
    registry: &Registry<'_, Fp, TestRank>,
    y: Fp,
) -> sparse::Polynomial<Fp, TestRank> {
    let omega_0 = CircuitIndex::new(0).omega_j::<Fp>();
    let mut wy = registry.wy(omega_0, y);
    if y != Fp::ZERO {
        let y_4n_minus_1 = y.pow_vartime([(4 * TestRank::n() - 1) as u64]);
        let mut key_view = sparse::View::<_, TestRank, _>::wiring();
        key_view.c.push(registry.digest() * y_4n_minus_1);
        let key_term = key_view.build();
        wy.sub_assign(&key_term);
    }
    wy
}

/// Run the algebraic identity check on a satisfying witness's trace.
/// Returns the actual revdot value so the caller's panic message can
/// include both sides on failure.
fn check_identity(
    registry: &Registry<'_, Fp, TestRank>,
    trace: &Trace<Fp>,
    expected_ky: Fp,
    y: Fp,
    z: Fp,
) -> (Fp, Fp) {
    // Use alpha = 0 so the algebraic identity holds without a correction
    // term. `assemble_with_alpha`'s alpha lives at `a[0]` and would
    // contribute an unrelated revdot term for nonzero alpha.
    let r = registry
        .assemble_with_alpha(trace, CircuitIndex::new(0), Fp::ZERO)
        .expect("assemble_with_alpha failed on a registered, satisfying witness");

    let mut b = r.clone();
    b.dilate(z);
    b.add_assign(&sy_from_registry(registry, y));
    b.add_assign(&TestRank::tz(z));

    let actual = r.revdot(&b);
    (expected_ky, actual)
}

fuzz_target!(|input: Input| {
    if std::env::var("DEBUG_INPUT").is_ok() {
        eprintln!("{:#?}", input);
        return;
    }

    let y = Fp::from(input.y_seed);
    let z = Fp::from(input.z_seed);

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
                None => return,
            };
            let circuit = SquareCircuit { times };
            let instance = square_native(witness, times);
            let trace = match circuit.trace(witness) {
                Ok(t) => t.into_output(),
                Err(_) => return,
            };
            let expected_ky = circuit
                .ky(instance, y)
                .expect("SquareCircuit::ky should not fail on Fp instance");
            let (expected, actual) = check_identity(registry, &trace, expected_ky, y, z);
            assert_eq!(
                expected, actual,
                "SquareCircuit identity violated: \
                 times={times}, witness={witness:?}, instance={instance:?}, \
                 y={y:?}, z={z:?}, expected_ky={expected:?}, actual_revdot={actual:?}"
            );
        }

        CircuitChoice::Simple {
            a_seed,
            use_special_a,
        } => {
            let a: Fp = match use_special_a {
                Some(idx) => special_value(idx),
                None => Fp::from(a_seed),
            };
            let b = match derive_satisfying_b(a) {
                Some(v) => v,
                None => return,
            };

            let registry = match SIMPLE_REGISTRY.as_ref() {
                Some(r) => r,
                None => return,
            };
            let circuit = MySimpleCircuit;
            let instance: (Fp, Fp) = (a + b, a - b);
            let trace = match circuit.trace((a, b)) {
                Ok(t) => t.into_output(),
                Err(_) => return,
            };
            let expected_ky = circuit
                .ky(instance, y)
                .expect("MySimpleCircuit::ky should not fail on (Fp, Fp) instance");
            let (expected, actual) = check_identity(registry, &trace, expected_ky, y, z);
            assert_eq!(
                expected, actual,
                "MySimpleCircuit identity violated: \
                 a={a:?}, b={b:?}, instance={instance:?}, y={y:?}, z={z:?}, \
                 expected_ky={expected:?}, actual_revdot={actual:?}"
            );
        }
    }
});

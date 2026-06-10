//! Fuzz three-way agreement of the registry polynomial at a single circuit.
//!
//! For circuit $i$ at omega point $w$, three independent evaluators compute
//! the same registry polynomial:
//! - `wxy(w, x, y)` (scalar)
//! - `wx(w, x)` (polynomial in $Y$, evaluated at $y$)
//! - `wy(w, y)` (polynomial in $X$, evaluated at $x$)
//!
//! Invariant: `wxy(w, x, y) == wx(w, x).eval(y) == wy(w, y).eval(x)`

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use pasta_curves::Fp;
use ragu_circuits::{
    polynomials::TestRank,
    registry::{CircuitIndex, Registry, RegistryBuilder},
};
use ragu_testing::circuits::SquareCircuit;

use std::sync::{LazyLock, OnceLock};

#[derive(Arbitrary, Debug)]
struct Input {
    times: u8,
    x_seed: u64,
    y_seed: u64,
}

/// Per-`times` registry cache. Building the registry for a `SquareCircuit`
/// runs the floor-planner over `times`-many squarings — ~3x the cost of the
/// three evaluations we then perform. Memoizing across inputs turns the
/// hot path into eval-only after each distinct `times` is observed once.
///
/// Each slot is `Result<Registry, ()>` (`Err` covers both
/// `RegistryBuilder::register_circuit` failure and
/// `RegistryBuilder::finalize` `GateBoundExceeded` failures — those are
/// "skip" outcomes for the fuzz body).
struct RegistryCache {
    /// Slot for `times = i + 1`, indexed 0..119.
    slots: [OnceLock<Result<Registry<'static, Fp, TestRank>, ()>>; 120],
}

static REGISTRY_CACHE: LazyLock<RegistryCache> = LazyLock::new(|| RegistryCache {
    slots: [const { OnceLock::new() }; 120],
});

fn registry_for(times: usize) -> Option<&'static Registry<'static, Fp, TestRank>> {
    debug_assert!((1..=120).contains(&times));
    REGISTRY_CACHE.slots[times - 1]
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

fuzz_target!(|input: Input| {
    // DEBUG_INPUT=1 prints the parsed Arbitrary input and exits — useful for
    // triaging crash artifacts. See README.md "DEBUG_INPUT env var" section.
    if std::env::var("DEBUG_INPUT").is_ok() {
        eprintln!("{:#?}", input);
        return;
    }
    // Map u8 to `times ∈ [1, 120]` so every slot in the 120-entry cache is
    // reachable. `% 120` alone would yield `[0, 119]` (and the `.max(1)`
    // floor used previously left slot 119 unreachable).
    let times = ((input.times as usize) % 120) + 1;

    let registry = match registry_for(times) {
        Some(r) => r,
        None => return, // Circuit too large for rank — skip
    };

    let w = CircuitIndex::new(0).omega_j::<Fp>();
    let x = Fp::from(input.x_seed);
    let y = Fp::from(input.y_seed);

    let sxy = registry.wxy(w, x, y);
    let sx_at_y = registry.wx(w, x).eval(y);
    let sy_at_x = registry.wy(w, y).eval(x);

    assert_eq!(sxy, sx_at_y, "wxy != wx(w, x).eval(y) for times={times}");
    assert_eq!(sxy, sy_at_x, "wxy != wy(w, y).eval(x) for times={times}");
});

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
    registry::{CircuitIndex, RegistryBuilder},
};
use ragu_testing::circuits::SquareCircuit;

#[derive(Arbitrary, Debug)]
struct Input {
    times: u8,
    x_seed: u64,
    y_seed: u64,
}

fuzz_target!(|input: Input| {
    // DEBUG_INPUT=1 prints the parsed Arbitrary input and exits — useful for
    // triaging crash artifacts. See README.md "DEBUG_INPUT env var" section.
    if std::env::var("DEBUG_INPUT").is_ok() {
        eprintln!("{:#?}", input);
        return;
    }
    // Clamp times to stay within TestRank bounds.
    let times = ((input.times as usize) % 120).max(1);

    let circuit = SquareCircuit { times };
    let registry = match RegistryBuilder::<Fp, TestRank>::new().register_circuit(circuit) {
        Ok(b) => match b.finalize() {
            Ok(r) => r,
            Err(_) => return, // Circuit too large for rank — skip
        },
        Err(_) => return,
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

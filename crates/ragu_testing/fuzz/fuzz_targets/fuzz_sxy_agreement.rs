//! Fuzz three-way s(X,Y) polynomial agreement.
//!
//! Three independent evaluators compute the same circuit's wiring polynomial:
//! `sxy` (scalar), `sx` (unstructured), and `sy` (structured).
//!
//! Invariant: `sxy(x, y) == sx(x).eval(y) == sy(y).eval(x)`

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use pasta_curves::Fp;
use ragu_circuits::{
    CircuitExt,
    floor_planner::floor_plan,
    polynomials::TestRank,
    registry::Key,
};
use ragu_testing::circuits::SquareCircuit;

#[derive(Arbitrary, Debug)]
struct Input {
    times: u8,
    x_seed: u64,
    y_seed: u64,
    key_seed: u64,
}

fuzz_target!(|input: Input| {
    // Clamp times to stay within TestRank bounds (n = 2^7 = 128 muls max)
    let times = ((input.times as usize) % 120).max(1);

    let circuit = SquareCircuit { times };
    let obj = match circuit.into_object::<TestRank>() {
        Ok(obj) => obj,
        Err(_) => return, // Circuit too large for rank — skip
    };

    let plan = floor_plan(obj.segment_records());
    // Key::new requires a non-zero element (it computes the inverse).
    if input.key_seed == 0 {
        return;
    }
    let key = Key::new(Fp::from(input.key_seed));
    let x = Fp::from(input.x_seed);
    let y = Fp::from(input.y_seed);

    // Three independent evaluations
    let sxy = obj.sxy(x, y, &key, &plan);
    let sx_at_y = obj.sx(x, &key, &plan).eval(y);
    let sy_at_x = obj.sy(y, &key, &plan).eval(x);

    assert_eq!(sxy, sx_at_y, "sxy != sx(x).eval(y) for times={times}");
    assert_eq!(sxy, sy_at_x, "sxy != sy(y).eval(x) for times={times}");
});

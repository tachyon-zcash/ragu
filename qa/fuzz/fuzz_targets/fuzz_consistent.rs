//! Consistent trait fuzz target.
//!
//! The `Consistent` trait enforces a gadget's internal invariants on
//! existing wires: a `Boolean`'s wire must satisfy `self^2 == self`, a
//! `Point`'s coordinates must satisfy the curve equation, an `Element`
//! has no internal invariant (no-op). The trait is used after gadgets
//! are reconstituted from wires that bypassed the standard `alloc`
//! constraint-enforcement path (e.g., deserialization).
//!
//! # Test pattern
//!
//! For each input, allocate gadgets via the standard `alloc` paths
//! (which already enforce internal invariants), then call
//! `enforce_consistent` on each. The call should be a *no-op* in the
//! constraint system on a properly-allocated gadget — it re-adds
//! constraints that are already satisfied. Returning `Err` would mean
//! either:
//!
//!   1. A `Consistent` impl emits a constraint that fails even for
//!      a valid allocation (completeness bug), or
//!   2. The Simulator's constraint-checking diverges between the alloc
//!      path and the Consistent path (driver inconsistency).
//!
//! Composite gadgets are exercised via `[G; N]`-style array
//! delegation: `[Element; 3]`, `[Boolean; 2]`, etc.

#![no_main]

use arbitrary::Arbitrary;
use ff::PrimeField;
use group::Curve;
use group::CurveAffine;
use libfuzzer_sys::fuzz_target;
use pasta_curves::Fp;
use ragu_core::maybe::Maybe;
use ragu_pasta::{EpAffine, Fq};
use ragu_primitives::{
    Boolean, Element, Point, Simulator,
    allocator::Standard, consistent::Consistent,
};

use std::sync::LazyLock;

fn parse_fp(bytes: [u8; 32]) -> Fp {
    Option::<Fp>::from(Fp::from_repr(bytes)).unwrap_or_else(|| {
        Fp::from(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    })
}

/// Precomputed table of non-identity Pallas points.
///
/// Replacing per-input `EpAffine::generator() * Fq::from(seed)` with a
/// 32-point modular lookup. The Consistent trait tests check
/// `(x, y)` is on the curve regardless of which specific point — point
/// diversity beyond a handful adds no constraint-system coverage but
/// burns ~50µs/scalar-mul per input. At ~143µs/iter pre-change, removing
/// the two scalar muls is the dominant cost on this target.
const POINT_TABLE_LEN: usize = 32;
static POINT_TABLE: LazyLock<[EpAffine; POINT_TABLE_LEN]> = LazyLock::new(|| {
    let mut points = [EpAffine::generator(); POINT_TABLE_LEN];
    for (i, p) in points.iter_mut().enumerate() {
        // Skip seed=0 → generator already in slot 0.
        if i > 0 {
            *p = (EpAffine::generator() * Fq::from(i as u64)).to_affine();
        }
    }
    points
});

fn point_from_seed(seed: u64) -> EpAffine {
    POINT_TABLE[(seed as usize) % POINT_TABLE_LEN]
}

#[derive(Arbitrary, Debug)]
struct Input {
    a_bytes: [u8; 32],
    b_bytes: [u8; 32],
    bv: bool,
    bv2: bool,
    p_seed: u64,
    q_seed: u64,
}

fuzz_target!(|input: Input| {
    // DEBUG_INPUT=1 prints the parsed Arbitrary input and exits — useful for
    // triaging crash artifacts. See README.md "DEBUG_INPUT env var" section.
    if std::env::var("DEBUG_INPUT").is_ok() {
        eprintln!("{:#?}", input);
        return;
    }
    let a_val = parse_fp(input.a_bytes);
    let b_val = parse_fp(input.b_bytes);
    let p = point_from_seed(input.p_seed);
    let q = point_from_seed(input.q_seed);

    let r = Simulator::<Fp>::simulate(
        (a_val, b_val, input.bv, input.bv2, p, q),
        |dr, witness| {
            let allocator = &mut Standard::new();

            // Element: enforce_consistent is a no-op (no internal invariant).
            let e = Element::alloc(dr, allocator, witness.as_ref().map(|w| w.0))?;
            e.enforce_consistent(dr)?;

            // Boolean: enforce_consistent re-enforces the 0-or-1 constraint.
            let b = Boolean::alloc(dr, allocator, witness.as_ref().map(|w| w.2))?;
            b.enforce_consistent(dr)?;

            // Point: enforce_consistent re-enforces the curve equation.
            let pt = Point::alloc(dr, witness.as_ref().map(|w| w.4))?;
            pt.enforce_consistent(dr)?;

            // Array of Elements (no-op delegate).
            let elems: [Element<'_, _>; 3] = [
                Element::alloc(dr, allocator, witness.as_ref().map(|w| w.0))?,
                Element::alloc(dr, allocator, witness.as_ref().map(|w| w.1))?,
                Element::alloc(dr, allocator, witness.as_ref().map(|w| w.0))?,
            ];
            elems.enforce_consistent(dr)?;

            // Array of Booleans (delegates 0-or-1 enforcement to each).
            let bools: [Boolean<'_, _>; 2] = [
                Boolean::alloc(dr, allocator, witness.as_ref().map(|w| w.2))?,
                Boolean::alloc(dr, allocator, witness.as_ref().map(|w| w.3))?,
            ];
            bools.enforce_consistent(dr)?;

            // Array of Points (delegates curve-equation check to each).
            let points: [Point<'_, _, EpAffine>; 2] = [
                Point::alloc(dr, witness.as_ref().map(|w| w.4))?,
                Point::alloc(dr, witness.as_ref().map(|w| w.5))?,
            ];
            points.enforce_consistent(dr)?;

            // The unit type's Consistent impl is also a no-op; smoke-test it.
            ().enforce_consistent(dr)?;

            Ok(())
        },
    );

    assert!(
        r.is_ok(),
        "enforce_consistent on properly-allocated gadgets returned Err: {:?}",
        r.err(),
    );
});

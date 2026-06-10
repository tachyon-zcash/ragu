//! Point-gadget identity fuzz target.
//!
//! Generates two random Pallas points `P = G * p_seed` and
//! `Q = G * q_seed` (where `G` is the Pallas generator), allocates them as
//! `Point<EpAffine>` gadgets, and asserts a fixed list of algebraic and
//! API-contract identities hold. Complements `fuzz_endoscalar`, which
//! already does differential testing of `Point::endo`, `negate`, `double`,
//! and `conditional_*` against native arithmetic; this target adds:
//!
//!   - Direct algebraic identities those differential checks don't probe
//!     (e.g. that `endo` applied three times round-trips, since ζ³ = 1).
//!   - The only coverage of `Point::double_and_add_incomplete` anywhere
//!     in the fuzz suite (the optimization that fuses `2Q + P` into one
//!     gadget).
//!   - `add_incomplete` commutativity, beyond fuzz_endoscalar's single
//!     differential check.
//!
//! # Identities
//!
//!   - negate involution: `negate(negate(P)) == P`
//!   - endo cube:         `endo(endo(endo(P))) == P` (since ζ³ = 1)
//!   - conditional_negate(false, P) == P
//!   - conditional_negate(true, P)  == native -P
//!   - conditional_endo(false, P)   == P
//!   - conditional_endo(true, P)    == native endo(P)
//!   - add_incomplete commutativity: `P + Q == Q + P` (native check)
//!   - double_and_add_incomplete:    `Q.dna(P) == Q.double().add(P)`
//!
//! Tests are guarded so degenerate cases don't trip the gadget's
//! "incomplete" addition (x-coordinate collisions, identity, etc.).

#![no_main]

use arbitrary::Arbitrary;
use ff::WithSmallOrderMulGroup;
use group::{Curve, Group};
use group::CurveAffine as _;
use libfuzzer_sys::fuzz_target;
use pasta_curves::Fp;
use pasta_curves::arithmetic::CurveAffine;
use ragu_core::maybe::Maybe;
use ragu_pasta::{EpAffine, Fq};
use ragu_primitives::{Boolean, NonzeroBank, Point, Simulator, allocator::Standard};

use std::sync::LazyLock;

/// Precomputed table of non-identity Pallas points.
///
/// Replaces per-input `EpAffine::generator() * Fq::from(seed)` (~50µs
/// each) with a 64-point modular lookup. The point-identity tests
/// (negate involution, endo cube, conditional_*, add commutativity,
/// double-and-add) exercise *algebraic gadget paths*, not point-shape
/// coverage — 64 distinct on-curve points is enough to hit every gadget
/// branch the test probes. The pair (`p_seed`, `q_seed`) still controls
/// whether `p` and `q` collide on x (skipped via existing distinctness
/// guard) and whether `2P` and `Q` collide on x (existing skip guard).
const POINT_TABLE_LEN: usize = 64;
static POINT_TABLE: LazyLock<[EpAffine; POINT_TABLE_LEN]> = LazyLock::new(|| {
    let mut points = [EpAffine::generator(); POINT_TABLE_LEN];
    for (i, p) in points.iter_mut().enumerate() {
        if i > 0 {
            *p = (EpAffine::generator() * Fq::from(i as u64)).to_affine();
        }
    }
    points
});

/// Get a non-trivial curve point from a fuzzer-supplied seed.
fn point_from_seed(seed: u64) -> EpAffine {
    POINT_TABLE[(seed as usize) % POINT_TABLE_LEN]
}

/// Native negation of an EpAffine point.
fn native_negate(p: EpAffine) -> EpAffine {
    (-p.to_curve()).to_affine()
}

/// Native endomorphism: multiply the x-coordinate by ζ (Fp::ZETA).
fn native_endo(p: EpAffine) -> EpAffine {
    let coords = p.coordinates().unwrap();
    let new_x = *coords.x() * Fp::ZETA;
    EpAffine::from_xy(new_x, *coords.y()).unwrap()
}

/// Native point addition.
fn native_add(p: EpAffine, q: EpAffine) -> EpAffine {
    (p.to_curve() + q.to_curve()).to_affine()
}

/// Native point doubling.
fn native_double(p: EpAffine) -> EpAffine {
    (p.to_curve().double()).to_affine()
}

#[derive(Arbitrary, Debug)]
struct Input {
    /// First point seed.
    p_seed: u64,
    /// Second point seed.
    q_seed: u64,
}

fuzz_target!(|input: Input| {
    // DEBUG_INPUT=1 prints the parsed Arbitrary input and exits — useful for
    // triaging crash artifacts. See README.md "DEBUG_INPUT env var" section.
    if std::env::var("DEBUG_INPUT").is_ok() {
        eprintln!("{:#?}", input);
        return;
    }
    // Skip degenerate cases. point_from_seed(0) returns the generator (not
    // the identity), so seed 0 is fine, but equal seeds put P and Q at the
    // same affine coordinates, which trips add_incomplete's distinctness
    // requirement.
    if input.p_seed == input.q_seed {
        return;
    }

    let p = point_from_seed(input.p_seed);
    let q = point_from_seed(input.q_seed);

    // Astronomically unlikely with random scalars, but defensive: skip if
    // P and Q share an x-coordinate (would make add_incomplete fail with
    // div-by-zero on (x_q - x_p)).
    let p_coords = p.coordinates().unwrap();
    let q_coords = q.coordinates().unwrap();
    if p_coords.x() == q_coords.x() {
        return;
    }

    // Pre-compute the doubled P. Pallas's group has prime order, so 2P
    // is never the identity for non-identity P — coordinates always
    // exist.
    let p_doubled = native_double(p);
    let p_doubled_x = *p_doubled.coordinates().unwrap().x();

    let _ = Simulator::<Fp>::simulate((p, q), |dr, witness| {
        let allocator = &mut Standard::new();

        let p_val = witness.as_ref().map(|w| w.0);
        let q_val = witness.as_ref().map(|w| w.1);

        let p_pt = Point::alloc(dr, p_val)?;
        let q_pt = Point::alloc(dr, q_val)?;
        let true_b = Boolean::alloc(dr, allocator, witness.as_ref().map(|_| true))?;
        let false_b = Boolean::alloc(dr, allocator, witness.as_ref().map(|_| false))?;

        // negate involution: negate(negate(P)) == P
        let neg = p_pt.negate(dr);
        let neg_neg = neg.negate(dr);
        assert_eq!(
            neg_neg.value().take(),
            p,
            "negate(negate(P)) != P; P seed={}",
            input.p_seed,
        );

        // endo cube: endo(endo(endo(P))) == P (since ζ³ = 1)
        let e1 = p_pt.endo(dr);
        let e2 = e1.endo(dr);
        let e3 = e2.endo(dr);
        assert_eq!(
            e3.value().take(),
            p,
            "endo³(P) != P; P seed={}",
            input.p_seed,
        );

        // conditional_negate(false, P) == P
        let cn_false = p_pt.conditional_negate(dr, &false_b)?;
        assert_eq!(
            cn_false.value().take(),
            p,
            "conditional_negate(false, P) != P; P seed={}",
            input.p_seed,
        );

        // conditional_negate(true, P) == native -P
        let cn_true = p_pt.conditional_negate(dr, &true_b)?;
        assert_eq!(
            cn_true.value().take(),
            native_negate(p),
            "conditional_negate(true, P) != -P; P seed={}",
            input.p_seed,
        );

        // conditional_endo(false, P) == P
        let ce_false = p_pt.conditional_endo(dr, &false_b)?;
        assert_eq!(
            ce_false.value().take(),
            p,
            "conditional_endo(false, P) != P; P seed={}",
            input.p_seed,
        );

        // conditional_endo(true, P) == native endo(P)
        let ce_true = p_pt.conditional_endo(dr, &true_b)?;
        assert_eq!(
            ce_true.value().take(),
            native_endo(p),
            "conditional_endo(true, P) != endo(P); P seed={}",
            input.p_seed,
        );

        // add_incomplete commutativity: P + Q == Q + P, both equal native sum
        let expected_sum = native_add(p, q);
        let sum_pq = NonzeroBank::scope(dr, |dr, bank| p_pt.add_incomplete(dr, &q_pt, bank))?;
        let sum_qp = NonzeroBank::scope(dr, |dr, bank| q_pt.add_incomplete(dr, &p_pt, bank))?;
        assert_eq!(
            sum_pq.value().take(),
            expected_sum,
            "P + Q != native sum; P seed={} Q seed={}",
            input.p_seed,
            input.q_seed,
        );
        assert_eq!(
            sum_qp.value().take(),
            expected_sum,
            "Q + P != native sum; P seed={} Q seed={}",
            input.p_seed,
            input.q_seed,
        );

        // double_and_add_incomplete: P.dna(Q) computes 2*P + Q.
        // Skip when 2*P and Q share an x-coordinate (would make the
        // inner add_incomplete's divide fail).
        let q_x = *q_coords.x();
        if p_doubled_x != q_x {
            let dna = NonzeroBank::scope(dr, |dr, bank| {
                p_pt.double_and_add_incomplete(dr, &q_pt, bank)
            })?;
            let expected_dna = native_add(p_doubled, q);
            assert_eq!(
                dna.value().take(),
                expected_dna,
                "P.dna(Q) != 2P + Q; P seed={} Q seed={}",
                input.p_seed,
                input.q_seed,
            );

            // Also verify it matches the slower equivalent:
            //   P.double().add_incomplete(Q) == P.dna(Q)
            let slow_path = NonzeroBank::scope(dr, |dr, bank| {
                p_pt.double(dr)?.add_incomplete(dr, &q_pt, bank)
            })?;
            assert_eq!(
                slow_path.value().take(),
                dna.value().take(),
                "double().add() != dna; P seed={} Q seed={}",
                input.p_seed,
                input.q_seed,
            );
        }

        Ok(())
    });
});

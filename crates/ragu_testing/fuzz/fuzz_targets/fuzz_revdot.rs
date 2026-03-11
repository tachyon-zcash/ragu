//! Fuzz structured polynomial operations against naive unstructured equivalents.
//!
//! Invariants:
//! - `p1.revdot(&p2) == dot(p1.unstructured(), rev(p2.unstructured()))`
//! - `p.eval(z) == p.unstructured().eval(z)` (structured eval == unstructured eval)
//! - `fold([p1, p2], s).unstructured() == fold of unstructured equivalents`

#![no_main]

use arbitrary::Arbitrary;
use ff::Field;
use libfuzzer_sys::fuzz_target;
use pasta_curves::Fp;
use ragu_circuits::polynomials::{TestRank, Rank, structured::Polynomial};

#[derive(Arbitrary, Debug)]
struct Input {
    p1_lens: [u8; 4],
    p2_lens: [u8; 4],
    coeffs: Vec<u64>,
    eval_point: u64,
    fold_scale: u64,
}

fn build_poly(lens: &[u8; 4], coeffs: &mut impl Iterator<Item = Fp>) -> Polynomial<Fp, TestRank> {
    let n = TestRank::n();
    let mut poly = Polynomial::new();
    let clamp = |l: u8| (l as usize) % (n + 1);

    let fwd = poly.forward();
    for _ in 0..clamp(lens[0]) {
        fwd.a.push(coeffs.next().unwrap_or(Fp::ZERO));
    }
    for _ in 0..clamp(lens[1]) {
        fwd.b.push(coeffs.next().unwrap_or(Fp::ZERO));
    }
    for _ in 0..clamp(lens[2]) {
        fwd.c.push(coeffs.next().unwrap_or(Fp::ZERO));
    }
    drop(fwd);
    let bwd = poly.backward();
    for _ in 0..clamp(lens[3]) {
        bwd.c.push(coeffs.next().unwrap_or(Fp::ZERO));
    }

    poly
}

fuzz_target!(|input: Input| {
    if input.coeffs.is_empty() {
        return;
    }

    let mut coeffs = input.coeffs.iter().map(|&v| Fp::from(v));

    let p1 = build_poly(&input.p1_lens, &mut coeffs);
    let p2 = build_poly(&input.p2_lens, &mut coeffs);

    // 1. Revdot agreement
    let structured_revdot = p1.revdot(&p2);
    let u1 = p1.unstructured();
    let u2 = p2.unstructured();
    let naive_revdot = ragu_arithmetic::dot(u1.iter(), u2.iter().rev());

    assert_eq!(
        structured_revdot, naive_revdot,
        "revdot mismatch: p1 lens={:?}, p2 lens={:?}",
        input.p1_lens, input.p2_lens
    );

    // 2. Eval agreement: structured eval == unstructured eval
    let z = Fp::from(input.eval_point);
    let structured_eval = p1.eval(z);
    let unstructured_eval = u1.eval(z);

    assert_eq!(
        structured_eval, unstructured_eval,
        "eval mismatch for p1 at z={z:?}"
    );

    let structured_eval2 = p2.eval(z);
    let unstructured_eval2 = u2.eval(z);

    assert_eq!(
        structured_eval2, unstructured_eval2,
        "eval mismatch for p2 at z={z:?}"
    );

    // 3. Fold-then-eval agreement
    let s = Fp::from(input.fold_scale);
    let folded = Polynomial::fold([&p1, &p2].into_iter(), s);
    let folded_eval = folded.eval(z);
    let folded_u_eval = folded.unstructured().eval(z);

    assert_eq!(
        folded_eval, folded_u_eval,
        "fold eval mismatch at z={z:?}"
    );
});

//! Fuzz sparse polynomial operations against naive dense equivalents.
//!
//! Invariants:
//! - `p1.revdot(&p2) == dot(p1.iter_coeffs(), p2.iter_coeffs().rev())`
//! - `p.eval(z) == naive Horner over p.iter_coeffs()`
//! - `fold([p1, p2], s).eval(z) == naive eval of folded dense coefficients`

#![no_main]

use arbitrary::Arbitrary;
use ff::Field;
use libfuzzer_sys::fuzz_target;
use pasta_curves::Fp;
use ragu_circuits::polynomials::{
    Rank, TestRank,
    sparse::{Polynomial, View},
};

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
    let mut view: View<Fp, TestRank, _> = View::trace();
    let clamp = |l: u8| (l as usize) % (n + 1);

    for _ in 0..clamp(lens[0]) {
        view.a.push(coeffs.next().unwrap_or(Fp::ZERO));
    }
    for _ in 0..clamp(lens[1]) {
        view.b.push(coeffs.next().unwrap_or(Fp::ZERO));
    }
    for _ in 0..clamp(lens[2]) {
        view.c.push(coeffs.next().unwrap_or(Fp::ZERO));
    }
    for _ in 0..clamp(lens[3]) {
        view.d.push(coeffs.next().unwrap_or(Fp::ZERO));
    }

    view.build()
}

fn naive_eval(coeffs: impl DoubleEndedIterator<Item = Fp>, z: Fp) -> Fp {
    coeffs.rev().fold(Fp::ZERO, |acc, c| acc * z + c)
}

/// Naive revdot over arbitrary iterators. Takes iterators directly so the
/// caller doesn't have to materialize an intermediate `Vec<Fp>` per input.
fn naive_revdot_iter(
    a: impl Iterator<Item = Fp>,
    b: impl DoubleEndedIterator<Item = Fp>,
) -> Fp {
    a.zip(b.rev()).map(|(x, y)| x * y).sum()
}

fuzz_target!(|input: Input| {
    // DEBUG_INPUT=1 prints the parsed Arbitrary input and exits — useful for
    // triaging crash artifacts. See README.md "DEBUG_INPUT env var" section.
    if std::env::var("DEBUG_INPUT").is_ok() {
        eprintln!("{:#?}", input);
        return;
    }
    if input.coeffs.is_empty() {
        return;
    }

    let mut coeffs = input.coeffs.iter().map(|&v| Fp::from(v));

    let p1 = build_poly(&input.p1_lens, &mut coeffs);
    let p2 = build_poly(&input.p2_lens, &mut coeffs);

    // 1. Revdot agreement
    let sparse_revdot = p1.revdot(&p2);
    let dense_revdot = naive_revdot_iter(p1.iter_coeffs(), p2.iter_coeffs());

    assert_eq!(
        sparse_revdot, dense_revdot,
        "revdot mismatch: p1 lens={:?}, p2 lens={:?}",
        input.p1_lens, input.p2_lens
    );

    // 2. Eval agreement: sparse eval == naive Horner over iter_coeffs
    let z = Fp::from(input.eval_point);
    let sparse_eval = p1.eval(z);
    let dense_eval = naive_eval(p1.iter_coeffs(), z);

    assert_eq!(sparse_eval, dense_eval, "eval mismatch for p1 at z={z:?}");

    let sparse_eval2 = p2.eval(z);
    let dense_eval2 = naive_eval(p2.iter_coeffs(), z);

    assert_eq!(sparse_eval2, dense_eval2, "eval mismatch for p2 at z={z:?}");

    // 3. Fold-then-eval agreement
    let s = Fp::from(input.fold_scale);
    let folded = Polynomial::fold([&p1, &p2].into_iter(), s);
    let folded_eval = folded.eval(z);
    let folded_dense_eval = naive_eval(folded.iter_coeffs(), z);

    assert_eq!(
        folded_eval, folded_dense_eval,
        "fold eval mismatch at z={z:?}"
    );
});

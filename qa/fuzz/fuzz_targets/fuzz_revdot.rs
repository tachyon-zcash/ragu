//! Fuzz sparse polynomial operations against naive dense equivalents.
//!
//! Invariants:
//! - `p1.revdot(&p2) == dot(p1.iter_coeffs(), p2.iter_coeffs().rev())`
//! - `p.eval(z) == naive Horner over p.iter_coeffs()`
//! - `fold([p1, p2], s).eval(z) == naive eval of folded dense coefficients`
//!
//! All three run at a fuzzer-chosen field and rank (see
//! [`ragu_testing_fuzz::params`]). This target used to be pinned to `Fp` and
//! `TestRank`, which left the rank that actually ships untested here — and
//! rank is not incidental to what is under test: `View`'s four segments are
//! clamped against `R::n()`, and `revdot` pairs coefficients against the
//! reversal of a vector whose length is the rank's. A dense-vs-sparse
//! disagreement that only appears at production capacity would have been invisible.
//! The field is drawn evenly; the rank draw is skewed toward `TestRank`, so
//! the throughput cost of the larger vectors is bounded.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use ragu_circuits::polynomials::{
    Rank,
    sparse::{Polynomial, View},
};
use ragu_testing_fuzz::{
    params::{FieldChoice, RankChoice},
    with_field, with_rank,
};
use udon::field::Field;

#[derive(Arbitrary, Debug)]
struct Input {
    field: FieldChoice,
    rank: RankChoice,
    p1_lens: [u8; 4],
    p2_lens: [u8; 4],
    coeffs: Vec<u64>,
    eval_point: u64,
    fold_scale: u64,
}

fn build_poly<F: Field, R: Rank>(
    lens: &[u8; 4],
    coeffs: &mut impl Iterator<Item = F>,
) -> Polynomial<F, R> {
    let n = R::n();
    let mut view: View<F, R, _> = View::trace();
    let clamp = |l: u8| (l as usize) % (n + 1);

    for _ in 0..clamp(lens[0]) {
        view.a.push(coeffs.next().unwrap_or(F::ZERO));
    }
    for _ in 0..clamp(lens[1]) {
        view.b.push(coeffs.next().unwrap_or(F::ZERO));
    }
    for _ in 0..clamp(lens[2]) {
        view.c.push(coeffs.next().unwrap_or(F::ZERO));
    }
    for _ in 0..clamp(lens[3]) {
        view.d.push(coeffs.next().unwrap_or(F::ZERO));
    }

    view.build()
}

fn naive_eval<F: Field>(coeffs: impl DoubleEndedIterator<Item = F>, z: F) -> F {
    coeffs.rev().fold(F::ZERO, |acc, c| acc * z + c)
}

/// Naive revdot over arbitrary iterators. Takes iterators directly so the
/// caller doesn't have to materialize an intermediate `Vec<F>` per input.
fn naive_revdot_iter<F: Field>(
    a: impl Iterator<Item = F>,
    b: impl DoubleEndedIterator<Item = F>,
) -> F {
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

    with_field!(input.field, |F| {
        with_rank!(input.rank, |R| {
            run::<F, R>(&input);
        });
    });
});

fn run<F: Field, R: Rank>(input: &Input) {
    let mut coeffs = input.coeffs.iter().map(|&v| F::from(v));

    let p1 = build_poly::<F, R>(&input.p1_lens, &mut coeffs);
    let p2 = build_poly::<F, R>(&input.p2_lens, &mut coeffs);

    // 1. Revdot agreement
    let sparse_revdot = p1.revdot(&p2);
    let dense_revdot = naive_revdot_iter(p1.iter_coeffs(), p2.iter_coeffs());

    assert_eq!(
        sparse_revdot,
        dense_revdot,
        "revdot mismatch at rank {}: p1 lens={:?}, p2 lens={:?}",
        R::RANK,
        input.p1_lens,
        input.p2_lens
    );

    // 2. Eval agreement: sparse eval == naive Horner over iter_coeffs
    let z = F::from(input.eval_point);
    let sparse_eval = p1.eval(z);
    let dense_eval = naive_eval(p1.iter_coeffs(), z);

    assert_eq!(
        sparse_eval,
        dense_eval,
        "eval mismatch for p1 at rank {}",
        R::RANK
    );

    let sparse_eval2 = p2.eval(z);
    let dense_eval2 = naive_eval(p2.iter_coeffs(), z);

    assert_eq!(
        sparse_eval2,
        dense_eval2,
        "eval mismatch for p2 at rank {}",
        R::RANK
    );

    // 3. Fold-then-eval agreement
    let s = F::from(input.fold_scale);
    let folded = Polynomial::fold([&p1, &p2], s);
    let folded_eval = folded.eval(z);
    let folded_dense_eval = naive_eval(folded.iter_coeffs(), z);

    assert_eq!(
        folded_eval,
        folded_dense_eval,
        "fold eval mismatch at rank {}",
        R::RANK
    );
}

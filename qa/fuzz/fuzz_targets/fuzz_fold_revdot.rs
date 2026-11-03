//! Fuzz the folding-revdot identity for sparse polynomials.
//!
//! Invariants:
//! - `fold(lhs, s).revdot(&fold(rhs, t)) == sum_{i,j} s^i * t^j * lhs[i].revdot(&rhs[j])`
//! - `fold(polys, s).eval(z) == sum_i s^i * polys[i].eval(z)` (linearity of eval over fold)
//!
//! Both at a fuzzer-chosen field and rank — see [Field and rank
//! dispatch](../README.md). The bilinear expansion in the first identity is
//! quadratic in the fold count and linear in the rank's vector length, so
//! wallet rank is exactly where a term-ordering or accumulation mistake
//! would show up and test rank is where it would hide.

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
    count: u8,
    lens: Vec<[u8; 4]>,
    coeffs: Vec<u64>,
    s_seed: u64,
    t_seed: u64,
    eval_point: u64,
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

fuzz_target!(|input: Input| {
    // DEBUG_INPUT=1 prints the parsed Arbitrary input and exits — useful for
    // triaging crash artifacts. See README.md "DEBUG_INPUT env var" section.
    if std::env::var("DEBUG_INPUT").is_ok() {
        eprintln!("{:#?}", input);
        return;
    }
    with_field!(input.field, |F| {
        with_rank!(input.rank, |R| {
            run::<F, R>(&input);
        });
    });
});

fn run<F: Field, R: Rank>(input: &Input) {
    let count = ((input.count as usize) % 8).max(1);
    if input.coeffs.len() < count * 8 {
        return;
    }

    let s = F::from(input.s_seed);
    let t = F::from(input.t_seed);
    let z = F::from(input.eval_point);

    let mut coeff_iter = input.coeffs.iter().map(|&v| F::from(v));

    let lhs: Vec<_> = (0..count)
        .map(|i| build_poly::<F, R>(input.lens.get(i * 2).unwrap_or(&[0; 4]), &mut coeff_iter))
        .collect();
    let rhs: Vec<_> = (0..count)
        .map(|i| {
            build_poly::<F, R>(
                input.lens.get(i * 2 + 1).unwrap_or(&[0; 4]),
                &mut coeff_iter,
            )
        })
        .collect();

    // --- Invariant 1: fold-then-revdot identity ---
    let folded_lhs = Polynomial::fold(lhs.iter(), s);
    let folded_rhs = Polynomial::fold(rhs.iter(), t);
    let folded_revdot = folded_lhs.revdot(&folded_rhs);

    // Horner fold: first element gets s^{n-1}, last gets s^0.
    let s_powers: Vec<F> = {
        let mut powers = vec![F::ZERO; count];
        let mut p = F::ONE;
        for i in (0..count).rev() {
            powers[i] = p;
            p *= s;
        }
        powers
    };
    let t_powers: Vec<F> = {
        let mut powers = vec![F::ZERO; count];
        let mut p = F::ONE;
        for i in (0..count).rev() {
            powers[i] = p;
            p *= t;
        }
        powers
    };

    let mut expected_revdot = F::ZERO;
    for i in 0..count {
        for j in 0..count {
            expected_revdot += s_powers[i] * t_powers[j] * lhs[i].revdot(&rhs[j]);
        }
    }

    assert_eq!(
        folded_revdot, expected_revdot,
        "fold-then-revdot != sum of pairwise revdots for count={count}"
    );

    // --- Invariant 2: fold-then-eval linearity ---
    let folded_eval = folded_lhs.eval(z);

    let mut expected_eval = F::ZERO;
    for i in 0..count {
        expected_eval += s_powers[i] * lhs[i].eval(z);
    }

    assert_eq!(
        folded_eval, expected_eval,
        "fold(lhs, s).eval(z) != sum of s^i * lhs[i].eval(z) for count={count}"
    );
}

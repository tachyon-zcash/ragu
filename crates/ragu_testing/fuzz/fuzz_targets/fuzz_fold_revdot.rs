//! Fuzz the folding-revdot identity for structured polynomials.
//!
//! Invariants:
//! - `fold(lhs, s).revdot(&fold(rhs, t)) == sum_{i,j} s^i * t^j * lhs[i].revdot(&rhs[j])`
//! - `fold(polys, s).eval(z) == sum_i s^i * polys[i].eval(z)` (linearity of eval over fold)

#![no_main]

use arbitrary::Arbitrary;
use ff::Field;
use libfuzzer_sys::fuzz_target;
use pasta_curves::Fp;
use ragu_circuits::polynomials::{TestRank, Rank, structured::Polynomial};

#[derive(Arbitrary, Debug)]
struct Input {
    count: u8,
    lens: Vec<[u8; 4]>,
    coeffs: Vec<u64>,
    s_seed: u64,
    t_seed: u64,
    eval_point: u64,
}

fn build_poly(
    lens: &[u8; 4],
    coeffs: &mut impl Iterator<Item = Fp>,
) -> Polynomial<Fp, TestRank> {
    let n = TestRank::n();
    let clamp = |l: u8| (l as usize) % (n + 1);
    let mut poly = Polynomial::new();

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
    let count = ((input.count as usize) % 8).max(1);
    if input.coeffs.len() < count * 8 {
        return;
    }

    let s = Fp::from(input.s_seed);
    let t = Fp::from(input.t_seed);
    let z = Fp::from(input.eval_point);

    let mut coeff_iter = input.coeffs.iter().map(|&v| Fp::from(v));

    let lhs: Vec<_> = (0..count)
        .map(|i| build_poly(input.lens.get(i * 2).unwrap_or(&[0; 4]), &mut coeff_iter))
        .collect();
    let rhs: Vec<_> = (0..count)
        .map(|i| build_poly(input.lens.get(i * 2 + 1).unwrap_or(&[0; 4]), &mut coeff_iter))
        .collect();

    // --- Invariant 1: fold-then-revdot identity ---
    let folded_lhs = Polynomial::fold(lhs.iter(), s);
    let folded_rhs = Polynomial::fold(rhs.iter(), t);
    let folded_revdot = folded_lhs.revdot(&folded_rhs);

    // Horner fold: first element gets s^{n-1}, last gets s^0.
    let s_powers: Vec<Fp> = {
        let mut powers = vec![Fp::ZERO; count];
        let mut p = Fp::ONE;
        for i in (0..count).rev() {
            powers[i] = p;
            p *= s;
        }
        powers
    };
    let t_powers: Vec<Fp> = {
        let mut powers = vec![Fp::ZERO; count];
        let mut p = Fp::ONE;
        for i in (0..count).rev() {
            powers[i] = p;
            p *= t;
        }
        powers
    };

    let mut expected_revdot = Fp::ZERO;
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

    let mut expected_eval = Fp::ZERO;
    for i in 0..count {
        expected_eval += s_powers[i] * lhs[i].eval(z);
    }

    assert_eq!(
        folded_eval, expected_eval,
        "fold(lhs, s).eval(z) != sum of s^i * lhs[i].eval(z) for count={count}"
    );
});

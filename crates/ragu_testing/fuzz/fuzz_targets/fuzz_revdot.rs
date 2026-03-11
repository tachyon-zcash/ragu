//! Fuzz structured polynomial `revdot` against naive unstructured dot product.
//!
//! Invariant: `p1.revdot(&p2) == dot(p1.unstructured(), rev(p2.unstructured()))`
//! for all independent (u, v, w, d) vector lengths.

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
}

fn build_poly(lens: &[u8; 4], coeffs: &mut impl Iterator<Item = Fp>) -> Polynomial<Fp, TestRank> {
    let n = TestRank::n();
    let mut poly = Polynomial::new();
    let clamp = |l: u8| (l as usize) % (n + 1);

    let fwd = poly.forward();
    // a = u, b = v, c = w in forward view
    for _ in 0..clamp(lens[0]) {
        fwd.a.push(coeffs.next().unwrap_or(Fp::ZERO));
    }
    for _ in 0..clamp(lens[1]) {
        fwd.b.push(coeffs.next().unwrap_or(Fp::ZERO));
    }
    for _ in 0..clamp(lens[2]) {
        fwd.c.push(coeffs.next().unwrap_or(Fp::ZERO));
    }
    // d is not exposed via forward view, access via backward where c = d
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

    // Structured revdot
    let structured_result = p1.revdot(&p2);

    // Naive: dot(unstructured(p1), reverse(unstructured(p2)))
    let u1 = p1.unstructured();
    let u2 = p2.unstructured();
    let naive_result = ragu_arithmetic::dot(u1.iter(), u2.iter().rev());

    assert_eq!(
        structured_result, naive_result,
        "revdot mismatch: p1 lens={:?}, p2 lens={:?}",
        input.p1_lens, input.p2_lens
    );
});

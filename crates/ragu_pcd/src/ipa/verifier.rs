//! IPA verifier.
//!
//! Adapted from halo2's `halo2_proofs/src/poly/commitment/verifier.rs`.

use alloc::vec;
use alloc::vec::Vec;
use ff::{BatchInverter, Field, PrimeField};
use pasta_curves::group::Group;
use ragu_arithmetic::{Cycle, FixedGenerators, mul};

use super::compress::IpaProof;
use super::transcript::Transcript;

/// Checks to see if an IPA proof is valid for a polynomial commitment `P`
/// that opens at point `x` to the value `v`.
pub fn verify_proof<'p, C, G>(
    generators: &G,
    transcript: &mut Transcript<'p, C>,
    commitment: C::HostCurve,
    x: C::CircuitField,
    v: C::CircuitField,
    proof: &IpaProof<C::HostCurve>,
) -> bool
where
    C: Cycle,
    C::CircuitField: PrimeField,
    G: FixedGenerators<C::HostCurve>,
{
    let k = proof.rounds.len();
    if k == 0 {
        return false;
    }

    // P' = P - [v] G_0 + [ξ] S
    let mut scalars = vec![C::CircuitField::ONE];
    let mut points = vec![commitment];

    transcript.absorb_point(&proof.s_commitment);
    let xi = transcript.squeeze_challenge();

    // Challenge that ensures that the prover did not interfere with the H term
    // in their commitments.
    let z = transcript.squeeze_challenge();

    scalars.push(xi);
    points.push(proof.s_commitment);

    let mut rounds = Vec::with_capacity(k);
    for (l, r) in &proof.rounds {
        // Read L and R from the proof and write them to the transcript
        transcript.absorb_point(l);
        transcript.absorb_point(r);

        let u_j = transcript.squeeze_challenge();

        rounds.push((*l, *r, u_j, /* to be inverted */ u_j));
    }

    let mut u_to_invert: Vec<_> = rounds.iter().map(|(_, _, _, u_j)| *u_j).collect();
    let mut scratch = vec![C::CircuitField::ZERO; k];
    BatchInverter::invert_with_external_scratch(&mut u_to_invert, &mut scratch);
    for (round, u_inv) in rounds.iter_mut().zip(u_to_invert) {
        round.3 = u_inv;
    }

    // This is the left-hand side of the verifier equation.
    // P' + \sum([u_j^{-1}] L_j) + \sum([u_j] R_j)
    let mut u = Vec::with_capacity(k);
    for (l, r, u_j, u_j_inv) in rounds {
        scalars.push(u_j_inv);
        points.push(l);
        scalars.push(u_j);
        points.push(r);

        u.push(u_j);
    }

    // Our goal is to check that the left hand side of the verifier
    // equation
    //     P' + \sum([u_j^{-1}] L_j) + \sum([u_j] R_j)
    // equals (given b = \mathbf{b}_0, and the prover's values c, f),
    // the right-hand side
    //   = [c] (G'_0 + [b * z] H) + [f] H
    // Subtracting the right-hand side from both sides we get
    //   P' + \sum([u_j^{-1}] L_j) + \sum([u_j] R_j)
    //   + [-c] G'_0 + [-cbz - f] H
    //   = 0

    let c = proof.c;
    let neg_c = -c;
    let f = proof.f;
    let b = compute_b(x, &u);

    transcript.absorb_scalar(&c);
    transcript.absorb_scalar(&f);

    // H term: [-cbz - f]
    scalars.push(neg_c * b * z - f);
    points.push(*generators.h());

    // G terms: [-c] G'_0 expanded as [-c * s_i] G_i
    let s = compute_s(&u, neg_c);
    let n = s.len();

    // First G term gets an extra [-v] for the P' = P - [v] G_0 adjustment
    scalars.push(s[0] - v);
    scalars.extend_from_slice(&s[1..]);
    points.extend(generators.g()[..n].iter().copied());

    mul(scalars.iter(), &points).is_identity().into()
}

/// Computes $\prod\limits_{i=0}^{k-1} (1 + u_{k - 1 - i} x^{2^i})$.
fn compute_b<F: Field>(x: F, u: &[F]) -> F {
    let mut tmp = F::ONE;
    let mut cur = x;
    for u_j in u.iter().rev() {
        tmp *= F::ONE + *u_j * cur;
        cur *= cur;
    }
    tmp
}

/// Computes the coefficients of $g(X) = \prod\limits_{i=0}^{k-1} (1 + u_{k - 1 - i} X^{2^i})$.
fn compute_s<F: Field>(u: &[F], init: F) -> Vec<F> {
    assert!(!u.is_empty());
    let mut v = vec![F::ZERO; 1 << u.len()];
    v[0] = init;

    for (len, u_j) in u.iter().rev().enumerate().map(|(i, u_j)| (1 << i, u_j)) {
        let (left, right) = v.split_at_mut(len);
        let right = &mut right[0..len];
        right.copy_from_slice(left);
        for v in right {
            *v *= u_j;
        }
    }

    v
}

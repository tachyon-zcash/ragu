//! IPA prover.
//!
//! Adapted from halo2's `halo2_proofs/src/poly/commitment/prover.rs`.

use alloc::vec::Vec;
use ff::Field;
use pasta_curves::group::Curve;
use pasta_curves::group::prime::PrimeCurveAffine;
use ragu_arithmetic::{Cycle, FixedGenerators, dot, eval, mul};
use rand::{CryptoRng, RngCore};

use super::compress::IpaProof;
use super::transcript::Transcript;

/// Create a polynomial commitment opening proof for the polynomial defined
/// by the coefficients `p_poly`, the blinding factor `p_blind` used for the
/// polynomial commitment, and the point `x` that the polynomial is
/// evaluated at.
///
/// This function will panic if the provided polynomial is too large with
/// respect to the polynomial commitment parameters.
///
/// **Important:** This function assumes that the provided `transcript` has
/// already seen the common inputs: the polynomial commitment P, the claimed
/// opening v, and the point x.
pub fn create_proof<'p, C, G, R>(
    generators: &G,
    rng: &mut R,
    transcript: &mut Transcript<'p, C>,
    p_poly: &[C::CircuitField],
    p_blind: C::CircuitField,
    x: C::CircuitField,
) -> IpaProof<C::HostCurve>
where
    C: Cycle,
    G: FixedGenerators<C::HostCurve>,
    R: CryptoRng + RngCore,
{
    // We're limited to polynomials of degree n - 1.
    let n = p_poly.len();
    let k = n.ilog2() as usize;
    assert!(n <= generators.g().len() && n.is_power_of_two());

    // Sample a random polynomial (of same degree) that has a root at x, first
    // by setting all coefficients to random values.
    let mut s_poly: Vec<_> = (0..n).map(|_| C::CircuitField::random(&mut *rng)).collect();
    // Evaluate the random polynomial at x
    let s_at_x = eval(&s_poly, x);
    // Subtract constant coefficient to get a random polynomial with a root at x
    s_poly[0] -= s_at_x;
    // And sample a random blind
    let s_poly_blind = C::CircuitField::random(&mut *rng);

    // Write a commitment to the random polynomial to the transcript
    let s_poly_commitment =
        (mul(s_poly.iter(), generators.g()) + *generators.h() * s_poly_blind).to_affine();

    transcript.absorb_point(&s_poly_commitment);

    // Challenge that will ensure that the prover cannot change P but can only
    // witness a random polynomial commitment that agrees with P at x, with high
    // probability.
    let xi = transcript.squeeze_challenge();

    // Challenge that ensures that the prover did not interfere with the H term
    // in their commitments.
    let z = transcript.squeeze_challenge();

    // We'll be opening P' = P - [v] G_0 + [ξ] S to ensure it has a root at x.
    let mut p_prime: Vec<_> = p_poly
        .iter()
        .zip(&s_poly)
        .map(|(p, s)| *p + xi * s)
        .collect();
    let v = eval(&p_prime, x);
    p_prime[0] -= v;
    let p_prime_blind = p_blind + xi * s_poly_blind;

    // This accumulates the synthetic blinding factor `f` starting
    // with the blinding factor for P'.
    let mut f = p_prime_blind;

    // Initialize the vector `b` as the powers of `x`. The inner product of
    // `p_prime` and `b` is the evaluation of the polynomial at `x`.
    let mut b: Vec<_> = core::iter::successors(Some(C::CircuitField::ONE), |&v| Some(v * x))
        .take(n)
        .collect();

    // Initialize the vector `G'` from the generators. We'll be progressively
    // collapsing this vector into smaller and smaller vectors until it is of
    // length 1.
    let mut g_prime: Vec<_> = generators.g()[..n].to_vec();

    // Perform the inner product argument, round by round.
    let mut rounds = Vec::with_capacity(k);
    for _ in 0..k {
        let half = p_prime.len() / 2; // half the length of `p_prime`, `b`, `G'`

        let (p_lo, p_hi) = p_prime.split_at(half);
        let (b_lo, b_hi) = b.split_at(half);
        let (g_lo, g_hi) = g_prime.split_at(half);

        // Compute L, R
        let l_j_randomness = C::CircuitField::random(&mut *rng);
        let r_j_randomness = C::CircuitField::random(&mut *rng);
        let value_l_j = dot(p_hi, b_lo);
        let value_r_j = dot(p_lo, b_hi);
        let l_j = (mul(p_hi.iter(), g_lo) + *generators.h() * (value_l_j * z + l_j_randomness))
            .to_affine();
        let r_j = (mul(p_lo.iter(), g_hi) + *generators.h() * (value_r_j * z + r_j_randomness))
            .to_affine();

        // Feed L and R into the transcript
        rounds.push((l_j, r_j));
        transcript.absorb_point(&l_j);
        transcript.absorb_point(&r_j);

        let u_j = transcript.squeeze_challenge();
        let u_j_inv = u_j
            .invert()
            .expect("challenge is zero with negligible probability");

        // Collapse `p_prime` and `b`.
        for i in 0..half {
            let (p_hi, b_hi, g_hi) = (p_prime[i + half], b[i + half], g_prime[i + half]);
            p_prime[i] += u_j_inv * p_hi;
            b[i] += u_j * b_hi;
            g_prime[i] = (g_prime[i].to_curve() + g_hi * u_j).to_affine();
        }
        p_prime.truncate(half);
        b.truncate(half);
        g_prime.truncate(half);

        // Update randomness (the synthetic blinding factor at the end)
        f += l_j_randomness * u_j_inv;
        f += r_j_randomness * u_j;
    }

    // We have fully collapsed `p_prime`, `b`, `G'`
    assert_eq!(p_prime.len(), 1);
    let c = p_prime[0];

    transcript.absorb_scalar(&c);
    transcript.absorb_scalar(&f);

    IpaProof {
        s_commitment: s_poly_commitment,
        rounds,
        c,
        f,
    }
}

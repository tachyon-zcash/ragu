// Reference operands are kept as halo2 writes them so the body stays
// diffable against upstream.
#![allow(clippy::op_ref)]

use alloc::vec::Vec;

use ragu_core::{Error, Result};
use rand::CryptoRng;
use udon::{
    curve::{Affine, Projective},
    field::Field,
    polynomial::evaluate_iter,
};

use super::{IpaProof, IpaTranscript, Params, msm::multiexp};
use crate::{SelectableBackend, multicore::parallelize};

/// Creates an unblinded opening of `p_poly` at `x_3`.
///
/// The commitment is $P = \langle p,G\rangle$. A random polynomial $s$ with
/// $s(x_3) = 0$ masks the coefficients folded by the argument. Neither the
/// input commitment nor the proof's commitments have Pedersen blinds.
///
/// Panics unless the polynomial has exactly `params.n` coefficients.
///
/// **Important:** This function assumes that the provided `transcript` has
/// already seen the common inputs: the polynomial commitment P, the claimed
/// opening v, and the point x. It's probably also nice for the transcript
/// to have seen the elliptic curve description and the URS, if you want to
/// be rigorous.
pub fn create_proof<C: Affine, R: CryptoRng, T: IpaTranscript<C>, B: SelectableBackend>(
    params: &Params<C, B>,
    mut rng: R,
    transcript: &mut T,
    p_poly: &[C::Scalar],
    x_3: C::Scalar,
) -> Result<IpaProof<C>> {
    // We're limited to polynomials of degree n - 1.
    assert_eq!(p_poly.len(), params.n as usize);

    // Sample a random polynomial (of same degree) that has a root at x_3, first
    // by setting all coefficients to random values.
    let mut s_poly = p_poly.to_vec();
    for coeff in s_poly.iter_mut() {
        *coeff = C::Scalar::random(|bytes| rng.fill_bytes(bytes));
    }
    // Evaluate the random polynomial at x_3
    let s_at_x3 = evaluate_iter(&s_poly[..], x_3);
    // Subtract constant coefficient to get a random polynomial with a root at x_3
    s_poly[0] -= &s_at_x3;

    // Write a commitment to the random polynomial to the transcript
    let s_poly_commitment = params.commit(&s_poly).to_affine();
    transcript.write_point(s_poly_commitment)?;

    // Challenge that will ensure that the prover cannot change P but can only
    // witness a random polynomial commitment that agrees with P at x_3, with high
    // probability.
    let xi = transcript.squeeze_challenge()?;

    // Challenge that ensures that the prover did not interfere with the U term
    // in their commitments.
    let z = transcript.squeeze_challenge()?;

    // We'll be opening `P' = P - [v] G_0 + [ξ] S` to ensure it has a root at
    // x_3.
    let mut p_prime_poly: Vec<_> = s_poly
        .iter()
        .zip(p_poly.iter())
        .map(|(s, p)| *s * &xi + p)
        .collect();
    let v = evaluate_iter(&p_prime_poly, x_3);
    p_prime_poly[0] -= &v;

    // Initialize the vector `p_prime` as the coefficients of the polynomial.
    let mut p_prime = p_prime_poly;
    assert_eq!(p_prime.len(), params.n as usize);

    // Initialize the vector `b` as the powers of `x_3`. The inner product of
    // `p_prime` and `b` is the evaluation of the polynomial at `x_3`.
    let mut b = Vec::with_capacity(1 << params.k);
    {
        let mut cur = C::Scalar::ONE;
        for _ in 0..(1 << params.k) {
            b.push(cur);
            cur *= &x_3;
        }
    }

    // Initialize the vector `G'` from the URS. We'll be progressively collapsing
    // this vector into smaller and smaller vectors until it is of length 1.
    let mut g_prime = params.g.clone();

    // Collect `(L_j, R_j)` for the returned proof; halo2 leaves them in the
    // byte-stream transcript.
    let mut rounds = Vec::with_capacity(params.k as usize);

    // Perform the inner product argument, round by round.
    for j in 0..params.k {
        let half = 1 << (params.k - j - 1); // half the length of `p_prime`, `b`, `G'`

        // Compute L, R
        //
        // TODO: If we modify multiexp to take "extra" bases, we could speed
        // this piece up a bit by combining the multiexps.
        let l_j = multiexp::<C, B>(&p_prime[half..], &g_prime[0..half]);
        let r_j = multiexp::<C, B>(&p_prime[0..half], &g_prime[half..]);
        let value_l_j = C::Scalar::sum_of_products_slice(&p_prime[half..], &b[0..half]);
        let value_r_j = C::Scalar::sum_of_products_slice(&p_prime[0..half], &b[half..]);
        let l_j = l_j + &(params.u * (value_l_j * &z));
        let r_j = r_j + &(params.u * (value_r_j * &z));
        let l_j = l_j.to_affine();
        let r_j = r_j.to_affine();

        // Feed L and R into the real transcript
        transcript.write_point(l_j)?;
        transcript.write_point(r_j)?;
        rounds.push((l_j, r_j));

        let u_j = transcript.squeeze_challenge()?;
        let u_j_inv = u_j
            .invert()
            .ok_or_else(|| Error::InvalidWitness("IPA round challenge is zero".into()))?;

        // Collapse `p_prime` and `b`.
        // TODO: parallelize
        #[allow(clippy::assign_op_pattern)]
        for i in 0..half {
            p_prime[i] = p_prime[i] + &(p_prime[i + half] * &u_j_inv);
            b[i] = b[i] + &(b[i + half] * &u_j);
        }
        p_prime.truncate(half);
        b.truncate(half);

        // Collapse `G'`
        parallel_generator_collapse(&mut g_prime, u_j);
        g_prime.truncate(half);
    }

    // We have fully collapsed `p_prime`, `b`, `G'`
    assert_eq!(p_prime.len(), 1);
    let c = p_prime[0];

    transcript.write_scalar(c)?;

    Ok(IpaProof {
        s_commitment: s_poly_commitment,
        rounds,
        c,
    })
}

fn parallel_generator_collapse<C: Affine>(g: &mut [C], challenge: C::Scalar) {
    let len = g.len() / 2;
    let (g_lo, g_hi) = g.split_at_mut(len);

    parallelize(g_lo, |g_lo, start| {
        let g_hi = &g_hi[start..];
        let mut tmp = Vec::with_capacity(g_lo.len());
        for (g_lo, g_hi) in g_lo.iter().zip(g_hi.iter()) {
            tmp.push(g_lo.to_projective() + &(*g_hi * challenge));
        }
        C::batch_to_affine(&tmp, g_lo);
    });
}

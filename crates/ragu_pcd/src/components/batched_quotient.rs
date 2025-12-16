//! Batched quotient computation (SHPLONK-style) V for polynomial verification.

use ragu_core::{Result, drivers::Driver};
use ragu_primitives::{
    Element,
    vec::{FixedVec, Len},
};

/// Computes the batched quotient V via Horner-style accumulation:
///
<<<<<<< HEAD
/// `V = sum_i {alpha^i * (challenge_eval[i] - opening_evals[i]) / (u - query_points[i])}`
=======
/// `V = sum_i {alpha^i * (final_evals[i] - intermediate_evals[i]) / (u - eval_points[i])}`
>>>>>>> 7c958f9 (docs: fmt)
pub fn compute_v<'dr, D: Driver<'dr>, L: Len>(
    dr: &mut D,
    alpha: &Element<'dr, D>,
    u: &Element<'dr, D>,
    query_points: &FixedVec<Element<'dr, D>, L>,
    opening_evals: &FixedVec<Element<'dr, D>, L>,
    challenge_evals: &FixedVec<Element<'dr, D>, L>,
) -> Result<Element<'dr, D>> {
    let mut v = Element::zero(dr);

    for i in 0..L::len() {
        // Compute inverse via invert gadget: 1 / (u - point).
        let diff = u.sub(dr, &query_points[i]);
        let inv = diff.invert(dr)?;

        // v = v * alpha + (challenge_eval - opening_eval) * inv.
        v = v.mul(dr, alpha)?;
        let eval_diff = challenge_evals[i].sub(dr, &opening_evals[i]);
        let term = inv.mul(dr, &eval_diff)?;
        v = v.add(dr, &term);
    }

    Ok(v)
}

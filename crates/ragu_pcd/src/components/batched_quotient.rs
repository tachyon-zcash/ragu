//! Batched quotient computation (SHPLONK-style) V for polynomial verification.

use ragu_core::{Result, drivers::Driver};
use ragu_primitives::{
    Element,
    vec::{FixedVec, Len},
};

/// Computes the batched quotient V via Horner-style accumulation:
///
/// `V = sum_i {alpha^i * (final_evals[i] - intermediate_evals[i]) / (u - eval_points[i])}`
pub fn compute_v<'dr, D: Driver<'dr>, L: Len>(
    dr: &mut D,
    alpha: &Element<'dr, D>,
    u: &Element<'dr, D>,
    eval_points: &FixedVec<Element<'dr, D>, L>,
    intermediate_evals: &FixedVec<Element<'dr, D>, L>,
    final_evals_for_queries: &FixedVec<Element<'dr, D>, L>,
) -> Result<Element<'dr, D>> {
    let mut v = Element::zero(dr);

    for i in 0..L::len() {
        // Compute inverse via invert gadget: 1 / (u - point).
        let diff = u.sub(dr, &eval_points[i]);
        let inv = diff.invert(dr)?;

        // v = v * alpha + (final_eval - intermediate_eval) * inv.
        v = v.mul(dr, alpha)?;
        let eval_diff = final_evals_for_queries[i].sub(dr, &intermediate_evals[i]);
        let term = inv.mul(dr, &eval_diff)?;
        v = v.add(dr, &term);
    }

    Ok(v)
}

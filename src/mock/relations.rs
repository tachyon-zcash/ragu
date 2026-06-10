//! Mock equivalents of ragu's enforce-only polynomial relation free functions.
//!
//! Each relation here is a convenience tool over the two framework hooks a step
//! body reaches for -- [`StepCtx::enforce_poly_query`] and
//! [`StepCtx::derive_challenge`]. They share one shape: the result is
//! prover-supplied (built off-circuit) rather than computed by the relation, the
//! relation computes each operand's commitment internally, derives a Fiat-Shamir
//! challenge `z` from those commitments, checks the defining algebraic identity
//! at `z`, and emits one opening claim per operand at `(commitment, z, eval(z))`.
//! These functions only *record* the openings; actually verifying them is the
//! proof system's job, not done here.
//!
//! Soundness rests on Schwartz-Zippel: every operand commitment is absorbed into
//! `z`, so the operands are fixed *before* `z` exists and the identity at a
//! random `z` pins the corresponding polynomial identity (error `~deg/|F|`). An
//! input that is **not** a committed operand (a raw scalar, say) is not absorbed
//! into `z` and is not pinned this way; a relation that takes such an input
//! states its own precondition.
//!
//! # Caller obligation: binding
//!
//! These relations prove the identity among the polynomials passed; pinning
//! *which* polynomials those are is the caller's job. Every operand the
//! surrounding statement relies on must have its commitment grounded in a
//! statement-fixed value -- a public input, a prior-step output, a
//! transcript/header-absorbed value, or a consensus/output-checked commitment --
//! and the binding holds only once that chain actually terminates in such a value
//! (a fresh witness, or a commitment merely threaded onward, is not itself
//! enough). The binding target is the commitment *point*
//! (`= operand.commit()`); trailing-zero coefficients collapse under
//! [`Polynomial::commit`], so this is commitment-identity, not the literal
//! coefficient vector.
//!
//! This principle is common to all of these relations; each states which operands
//! it covers and any relation-specific nuance.
//!
//! Implementation invariant: the eval fed to each identity check is the same
//! eval emitted in that operand's opening claim (one `operand.eval(z)` call per
//! operand). A refactor that recomputed or separately witnessed the evals could
//! let the checked value diverge from the opened one and break soundness.

use ff::Field as _;
use pasta_curves::Fp;

use crate::{
    ctx::StepCtx,
    error::{Error, Result},
    polynomial::Polynomial,
};

/// Faithful polynomial product: confirm `product = multiplicand · multiplier`
/// among three committed polynomials by opening all three at a Fiat-Shamir
/// challenge.
///
/// `product` is prover-supplied and the relation works only from the three
/// commitments and their openings at `z` -- it does not multiply the inputs. The
/// point-wise identity `product(z) = multiplicand(z)·multiplier(z)` at a random
/// `z` confirms the relation: with every operand committed and absorbed into `z`,
/// the difference `product − multiplicand·multiplier` is a fixed polynomial
/// pinned to zero by Schwartz-Zippel.
///
/// # Caller obligation (soundness)
///
/// Every operand is committed and absorbed into `z`, so the module-level binding
/// obligation -- here applying symmetrically to `multiplicand`, `multiplier`, and
/// `product` -- is the only precondition.
pub fn enforce_poly_product(
    ctx: &mut StepCtx<'_>,
    multiplicand: &Polynomial,
    multiplier: &Polynomial,
    product: &Polynomial,
) -> Result<()> {
    let multiplicand_com = multiplicand.commit();
    let multiplier_com = multiplier.commit();
    let product_com = product.commit();
    let z = ctx.derive_challenge(&[multiplicand_com, multiplier_com, product_com])?;

    if product.eval(z) != multiplicand.eval(z) * multiplier.eval(z) {
        return Err(Error("poly product: product identity fails at challenge"));
    }

    ctx.enforce_poly_query(multiplicand_com, z, multiplicand.eval(z))?;
    ctx.enforce_poly_query(multiplier_com, z, multiplier.eval(z))?;
    ctx.enforce_poly_query(product_com, z, product.eval(z))?;

    Ok(())
}

/// Faithful ordered-sequence concatenation: confirm `result = head ++ tail`
/// (head's coefficients followed by tail's) among three committed polynomials by
/// opening all three at a Fiat-Shamir challenge.
///
/// `result` is prover-supplied (built off-circuit). `offset` is the shift the
/// tail sits at -- `result(X) = head(X) + X^{offset}·tail(X)` -- supplied as a
/// bounded witness, which keeps the relation length-agnostic.
///
/// The point-wise identity `result(z) = head(z) + z^{offset}·tail(z)` at a
/// random `z` confirms the relation; each operand's commitment is computed here
/// and absorbed into `z`, so `z` is fixed *before* any `offset` is chosen. For
/// nonzero `tail`, `result - head = X^{offset}·tail` then admits at most one
/// `offset`, and a free integer `offset` is sound: an adaptive search over wrong
/// offsets succeeds with probability `<= tries/|F|` (negligible).
///
/// # Caller obligations (soundness)
///
/// 1. **Binding.** Subject to the module-level binding obligation for `head`,
///    `tail`, and `result`. One relation-specific nuance: `result`'s commitment
///    must be threaded *independently* if `result` is consumed downstream --
///    `commit(X^{offset}·tail)` lands on shifted generators, so it is not
///    homomorphically recoverable from `head`/`tail`.
/// 2. **No coefficient overlap.** Pin `deg(head) < offset`; otherwise head's
///    coefficients at degree `>= offset` overlap tail's low coefficients
///    additively and the check still passes.
/// 3. **Absolute layout.** `deg(head) < offset` is the exact no-overlap
///    condition but does not fix an *absolute* position: a prover-supplied
///    `offset > len(head)` zero-pads between head and tail and still passes. If
///    the surrounding statement reads `result` against a fixed absolute layout,
///    `offset` must be a compile-time constant or otherwise constrained.
///
/// The `offset` parameter and the `z^{offset}` point-wise check stand in for a
/// positional shift the commitment scheme does not express directly; a
/// first-class committed `X^{k}·p` (or a built-in shifted-sum) would carry the
/// shift itself and collapse this to a direct call.
pub fn enforce_poly_concat(
    ctx: &mut StepCtx<'_>,
    head: &Polynomial,
    tail: &Polynomial,
    offset: usize,
    result: &Polynomial,
) -> Result<()> {
    let head_com = head.commit();
    let tail_com = tail.commit();
    let result_com = result.commit();
    let z = ctx.derive_challenge(&[head_com, tail_com, result_com])?;

    let zo = z.pow_vartime([offset as u64]);
    if result.eval(z) != head.eval(z) + zo * tail.eval(z) {
        return Err(Error(
            "poly concat: shifted-sum identity fails at challenge",
        ));
    }

    ctx.enforce_poly_query(head_com, z, head.eval(z))?;
    ctx.enforce_poly_query(tail_com, z, tail.eval(z))?;
    ctx.enforce_poly_query(result_com, z, result.eval(z))?;

    Ok(())
}

/// Splice one scalar between two committed sequences: confirm `result = left ++
/// [mid] ++ right`, i.e. `result(X) = left(X) + X^{offset}·mid +
/// X^{offset+1}·right(X)`, among the committed `left`, `right`, and `result` by
/// opening all three at a Fiat-Shamir challenge.
///
/// `result` is prover-supplied (built off-circuit). `mid` is a raw field
/// scalar passed separately from the committed operands; because it is not
/// absorbed into the challenge, it carries its own precondition (obligation 2).
///
/// # Caller obligations (soundness)
///
/// 1. **Binding.** Subject to the module-level binding obligation for `left`,
///    `right`, and `result`. (`mid` is covered by obligation 2 instead.)
/// 2. **`mid` fixed before the challenge.** The identity is *linear* in
///    `mid`, so pin its value independently of `z` -- a public/statement
///    input, a prior-step output, or a value absorbed into the transcript before
///    `z`. A prover free to choose it after seeing `z` solves `mid =
///    (result(z) - left(z) - z^{offset+1} right(z)) z^{-offset}` and passes for
///    any committed `result`; binding `left`/`right`/`result` does not help,
///    since the relation reads `mid` only through this identity.
/// 3. **No coefficient overlap.** `deg(left) < offset`, so `left` stays clear of
///    the spliced slot at degree `offset`.
///
/// The integer `offset` may be left free: `z` is fixed by the commitments before
/// `offset` is chosen, at most one offset satisfies the identity, and solving
/// `z^{offset} = c` for an integer is discrete-log-hard.
pub fn enforce_poly_splice(
    ctx: &mut StepCtx<'_>,
    head: &Polynomial,
    mid: Fp,
    tail: &Polynomial,
    offset: usize,
    result: &Polynomial,
) -> Result<()> {
    let head_com = head.commit();
    let tail_com = tail.commit();
    let result_com = result.commit();
    let z = ctx.derive_challenge(&[head_com, tail_com, result_com])?;

    let zo = z.pow_vartime([offset as u64]);
    if result.eval(z) != head.eval(z) + zo * mid + zo * z * tail.eval(z) {
        return Err(Error(
            "poly splice: spliced-sum identity fails at challenge",
        ));
    }

    ctx.enforce_poly_query(head_com, z, head.eval(z))?;
    ctx.enforce_poly_query(tail_com, z, tail.eval(z))?;
    ctx.enforce_poly_query(result_com, z, result.eval(z))?;

    Ok(())
}

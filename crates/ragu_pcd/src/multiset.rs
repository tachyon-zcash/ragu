//! Polynomial-with-commitment building block for [`Step::witness`] bodies.
//!
//! A [`Multiset`] pairs a (prover-only) polynomial with an (in-circuit)
//! commitment to it. [`Multiset::merge`] consumes two multisets and produces a
//! third whose polynomial is the product of the inputs, with the equality
//! `(a · b)(z) = a(z) · b(z)` enforced at a transcript-derived challenge `z`.
//! Verifier-side confidence comes from Schwartz–Zippel: if `z` is sampled
//! after the prover commits to all three polynomials, equality at `z` implies
//! equality everywhere except on a negligible-probability bad set.
//!
//! Built on top of [`StepCtx`]: the merge uses
//! [`StepCtx::derive_challenge`] to sample `z` from a caller-supplied sponge
//! and [`StepCtx::enforce_poly_query`] to surface the three opening claims for
//! later fuse-time verification.
//!
//! [`Step::witness`]: crate::step::Step::witness

use alloc::vec;
use alloc::vec::Vec;

use ff::Field;
use ragu_arithmetic::{CurveAffine, PoseidonPermutation};
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Gadget,
    maybe::Maybe,
};
use ragu_primitives::{Element, GadgetExt, Point, allocator::Standard, poseidon::Sponge};

use crate::step::StepCtx;

/// A polynomial paired with an in-circuit commitment to it.
///
/// `polynomial` is prover-only data threaded through a [`DriverValue`];
/// `commitment` is a real in-circuit gadget. See the [module
/// docs](crate::multiset) for merge semantics.
pub struct Multiset<'dr, D, C, R>
where
    D: Driver<'dr>,
    C: CurveAffine<Base = D::F>,
    R: Rank,
{
    /// In-circuit commitment to [`polynomial`](Self::polynomial).
    pub commitment: Point<'dr, D, C>,
    /// The polynomial committed to by [`commitment`](Self::commitment), held
    /// as a `DriverValue` so verifier-side synthesis (which has no witness)
    /// compiles unchanged.
    pub polynomial: DriverValue<D, sparse::Polynomial<D::F, R>>,
}

impl<'dr, D, C, R> Multiset<'dr, D, C, R>
where
    D: Driver<'dr>,
    C: CurveAffine<Base = D::F>,
    R: Rank,
{
    /// Constructs a multiset from a pre-allocated commitment and its
    /// associated polynomial witness.
    pub fn new(
        commitment: Point<'dr, D, C>,
        polynomial: DriverValue<D, sparse::Polynomial<D::F, R>>,
    ) -> Self {
        Self {
            commitment,
            polynomial,
        }
    }

    /// Merges two multisets. The result carries the product polynomial and a
    /// prover-supplied commitment to it. Three opening claims are recorded —
    /// one per input plus the product — at a transcript-derived challenge,
    /// and `y_prod = y_a · y_b` is enforced in-circuit.
    ///
    /// The caller is responsible for keeping `sponge`'s state aligned with
    /// the surrounding protocol: anything the challenge must be bound to
    /// should already have been absorbed before `merge` is called. `merge`
    /// itself absorbs the three commitments before squeezing.
    ///
    /// `product_com_witness` is the prover-supplied commitment to the product
    /// polynomial; the Schwartz–Zippel check installed below is what ties it
    /// back to the inputs.
    ///
    /// # Rank
    ///
    /// `R` must be wide enough to hold the product. The naive helper used to
    /// build the product polynomial will panic via
    /// [`sparse::Polynomial::from_coeffs`] if the result exceeds
    /// `R::num_coeffs()`. Choosing the right `R` is the caller's
    /// responsibility.
    pub fn merge<P: PoseidonPermutation<D::F>>(
        self,
        other: Self,
        ctx: &mut StepCtx<'_, 'dr, D, C>,
        sponge: &mut Sponge<'dr, D, P>,
        product_com_witness: DriverValue<D, C>,
    ) -> Result<Self> {
        // 1. Compute the product polynomial natively (prover-only).
        let product_poly = self.polynomial.clone().and_then(|a| {
            other
                .polynomial
                .clone()
                .map(|b| product_poly_naive::<D::F, R>(&a, &b))
        });

        // 2. Allocate the in-circuit commitment to the product.
        let product_com = Point::alloc(ctx.dr, product_com_witness)?;

        // 3. Bind all three commitments into the sponge, then derive z.
        self.commitment.write(ctx.dr, sponge)?;
        other.commitment.write(ctx.dr, sponge)?;
        product_com.write(ctx.dr, sponge)?;
        let z = ctx.derive_challenge(sponge)?;

        // 4. Allocate the three evaluations at z; prover-side values flow
        //    through the polynomial DriverValues.
        let z_val = z.value().map(|v| *v);
        let eval_at = |poly: DriverValue<D, sparse::Polynomial<D::F, R>>| {
            z_val.clone().and_then(|zv| poly.map(|p| p.eval(zv)))
        };
        let alloc = &mut Standard::new();
        let y_a = Element::alloc(ctx.dr, alloc, eval_at(self.polynomial.clone()))?;
        let y_b = Element::alloc(ctx.dr, alloc, eval_at(other.polynomial.clone()))?;
        let y_prod = Element::alloc(ctx.dr, alloc, eval_at(product_poly.clone()))?;

        // 5. Surface three poly-query claims for fuse-time verification.
        ctx.enforce_poly_query(self.commitment, z.clone(), y_a.clone())?;
        ctx.enforce_poly_query(other.commitment, z.clone(), y_b.clone())?;
        ctx.enforce_poly_query(product_com.clone(), z, y_prod.clone())?;

        // 6. In-circuit Schwartz–Zippel check: y_prod == y_a · y_b at z.
        let computed = y_a.mul(ctx.dr, &y_b)?;
        y_prod.enforce_equal(ctx.dr, &computed)?;

        Ok(Self::new(product_com, product_poly))
    }
}

/// Naive O(n·m) polynomial product. Illustration-grade; real callers should
/// swap in an FFT-based multiplier and reuse it across merges.
fn product_poly_naive<F: Field, R: Rank>(
    a: &sparse::Polynomial<F, R>,
    b: &sparse::Polynomial<F, R>,
) -> sparse::Polynomial<F, R> {
    let a_coeffs: Vec<F> = a.iter_coeffs().collect();
    let b_coeffs: Vec<F> = b.iter_coeffs().collect();
    let mut out = vec![F::ZERO; a_coeffs.len() + b_coeffs.len()];
    for (i, ai) in a_coeffs.iter().enumerate() {
        if bool::from(ai.is_zero()) {
            continue;
        }
        for (j, bj) in b_coeffs.iter().enumerate() {
            out[i + j] += *ai * *bj;
        }
    }
    while matches!(out.last(), Some(v) if bool::from(v.is_zero())) {
        out.pop();
    }
    sparse::Polynomial::from_coeffs(out)
}

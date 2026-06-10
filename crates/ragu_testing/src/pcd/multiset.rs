//! Polynomial-with-commitment building block for [`Step::witness`] bodies.
//!
//! A [`Multiset`] pairs a (prover-only) polynomial with an (in-circuit)
//! commitment to it. [`Multiset::merge`] consumes two multisets and produces a
//! third whose polynomial is the product of the inputs, with the equality
//! `(a · b)(z) = a(z) · b(z)` enforced at a framework-derived challenge `z`.
//! Verifier-side confidence comes from Schwartz–Zippel: if `z` is sampled
//! after the prover commits to all three polynomials, equality at `z` implies
//! equality everywhere except on a negligible-probability bad set.
//!
//! Built on top of [`StepCtx`]: the merge uses [`StepCtx::derive_challenge`] to
//! obtain `z` — the framework binds the challenge to the three commitments by
//! committing to them and hashing the commitment, so the `Multiset` never
//! instantiates a sponge — and [`StepCtx::enforce_poly_query`] to surface the
//! three opening claims for later fuse-time verification.
//!
//! [`Step::witness`]: ragu_pcd::step::Step::witness

use ragu_arithmetic::{CurveAffine, ff::PrimeField, poly_mul};
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe,
};
use ragu_pcd::step::StepCtx;
use ragu_primitives::{Element, GadgetExt, Point, allocator::Standard};

/// A polynomial paired with an in-circuit commitment to it.
///
/// `polynomial` is prover-only data threaded through a [`DriverValue`];
/// `commitment` is a real in-circuit gadget. See the [module
/// docs](self) for merge semantics.
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
    /// one per input plus the product — at a framework-derived challenge,
    /// and `y_prod = y_a · y_b` is enforced in-circuit.
    ///
    /// The challenge `z` comes from [`StepCtx::derive_challenge`]: the framework
    /// binds it to the three commitments (committing to them and hashing the
    /// commitment), so this method never instantiates or reasons about a sponge.
    ///
    /// `product_com_witness` is the prover-supplied commitment to the product
    /// polynomial; the Schwartz–Zippel check installed below is what ties it
    /// back to the inputs.
    ///
    /// # Rank
    ///
    /// `R` must be wide enough to hold the product:
    /// [`sparse::Polynomial::from_coeffs`] will panic if the result exceeds
    /// `R::num_coeffs()`. Choosing the right `R` is the caller's
    /// responsibility.
    pub fn merge(
        self,
        other: Self,
        ctx: &mut StepCtx<'_, 'dr, D, C>,
        product_com_witness: DriverValue<D, C>,
    ) -> Result<Self>
    where
        D::F: PrimeField,
    {
        // 1. Compute the product polynomial via FFT (prover-only).
        let product = self.polynomial.clone().and_then(|a| {
            other.polynomial.clone().map(|b| {
                let a_coeffs: Vec<D::F> = a.iter_coeffs().collect();
                let b_coeffs: Vec<D::F> = b.iter_coeffs().collect();
                let mut out = Vec::new();
                poly_mul(&a_coeffs, &b_coeffs, &mut out);
                sparse::Polynomial::from_coeffs(out)
            })
        });

        // 2. Allocate the in-circuit commitment to the product.
        let product_com = Point::alloc(ctx.dr, product_com_witness)?;

        // 3. Derive z, bound to all three commitments. Ragu commits to the
        //    bundled points and hashes that commitment to produce the
        //    challenge — the Multiset never touches a sponge. We only need the
        //    challenge here, so the returned binding commitment is discarded.
        let (_, z) = ctx.derive_challenge([
            self.commitment.clone(),
            other.commitment.clone(),
            product_com.clone(),
        ])?;

        // 4. Allocate the three evaluations at z; prover-side values flow
        //    through the polynomial DriverValues.
        let z_val = z.value().map(|v| *v);
        let eval_at = |poly: DriverValue<D, sparse::Polynomial<D::F, R>>| {
            z_val.clone().and_then(|zv| poly.map(|p| p.eval(zv)))
        };
        let alloc = &mut Standard::new();
        let y_a = Element::alloc(ctx.dr, alloc, eval_at(self.polynomial.clone()))?;
        let y_b = Element::alloc(ctx.dr, alloc, eval_at(other.polynomial.clone()))?;
        let y_prod = Element::alloc(ctx.dr, alloc, eval_at(product.clone()))?;

        // 5. Surface three poly-query claims for fuse-time verification.
        ctx.enforce_poly_query(self.commitment, z.clone(), y_a.clone())?;
        ctx.enforce_poly_query(other.commitment, z.clone(), y_b.clone())?;
        ctx.enforce_poly_query(product_com.clone(), z, y_prod.clone())?;

        // 6. In-circuit Schwartz–Zippel check: y_prod == y_a · y_b at z.
        let computed = y_a.mul(ctx.dr, &y_b)?;
        y_prod.enforce_equal(ctx.dr, &computed)?;

        Ok(Self::new(product_com, product))
    }
}

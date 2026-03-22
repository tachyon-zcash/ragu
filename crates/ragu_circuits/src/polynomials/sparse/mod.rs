//! Sparse polynomial representation with block-compressed coefficient storage.
//!
//! Circuits produced by the alloc optimization have wire assignments where the
//! `b` and `c` wires are zero for most alloc gates and the `d` wire is zero
//! for most multiplication gates. A dense coefficient vector would store those
//! zeros explicitly, wasting memory and commitment bandwidth. This module
//! stores coefficients as sorted, non-overlapping blocks of contiguous
//! values. Gaps between blocks are implicitly zero; individual elements
//! within a block may be zero when the polynomial is built from wire
//! buffers via [`View`].
//!
//! [`Polynomial<T, R>`] stores a degree $4n - 1$ polynomial (where $4n$ =
//! `R::num_coeffs()`) as sorted, non-overlapping blocks of contiguous
//! coefficients. Gaps between blocks are implicitly zero.
//!
//! # Construction
//!
//! There are three ways to create a polynomial:
//!
//! - [`Polynomial::new`]: empty (zero) polynomial.
//! - [`Polynomial::from_coeffs`]: compress a dense coefficient vector,
//!   omitting zero elements.
//! - [`View`]: a builder with four dense wire buffers (a, b, c, d) that
//!   maps gate-indexed values to degree positions and produces a polynomial via
//!   [`View::build`]. Zero elements within a wire buffer
//!   are preserved in the resulting blocks.
//!
//! Once constructed, the polynomial supports algebraic operations ([`scale`],
//! [`add_assign`], [`sub_assign`], [`negate`], [`eval`], [`revdot`],
//! [`dilate`], [`fold`], [`commit`], etc.) but cannot be converted back to a
//! view. Construction and mutation are separate phases.
//!
//! [`scale`]: Polynomial::scale
//! [`add_assign`]: Polynomial::add_assign
//! [`sub_assign`]: Polynomial::sub_assign
//! [`negate`]: Polynomial::negate
//! [`eval`]: Polynomial::eval
//! [`revdot`]: Polynomial::revdot
//! [`dilate`]: Polynomial::dilate
//! [`fold`]: Polynomial::fold
//! [`commit`]: Polynomial::commit

pub(crate) mod view;
pub use view::View;

#[cfg(test)]
mod tests;

use alloc::vec::Vec;
use core::borrow::Borrow;
use core::marker::PhantomData;

use ff::Field;
use ragu_arithmetic::CurveAffine;
use rand::CryptoRng;

use super::Rank;

/// A sparse polynomial with coefficients stored as non-overlapping blocks.
///
/// See the [module documentation](self) for details.
#[derive(Clone, Debug)]
pub struct Polynomial<T, R: Rank> {
    /// Sorted, non-overlapping, non-empty blocks of `(start_index, values)`.
    blocks: Vec<(usize, Vec<T>)>,
    _marker: PhantomData<R>,
}

// ---------------------------------------------------------------------------
// Invariant checking
// ---------------------------------------------------------------------------

impl<T, R: Rank> Polynomial<T, R> {
    /// Panics if the block list violates any structural invariant: blocks must
    /// be sorted by start index, non-empty, non-overlapping, and each block
    /// must fit within `[0, R::num_coeffs())`. Adjacent blocks are permitted.
    fn assert_invariants(&self) {
        let mut prev_end: usize = 0;
        for (i, (start, data)) in self.blocks.iter().enumerate() {
            assert!(!data.is_empty(), "block {i} is empty");
            assert!(
                *start + data.len() <= R::num_coeffs(),
                "block {i} exceeds capacity"
            );
            if i > 0 {
                assert!(
                    *start >= prev_end,
                    "block {i} overlaps previous (start={start}, prev_end={prev_end})"
                );
            }
            prev_end = *start + data.len();
        }
    }

    /// Creates a polynomial from pre-built blocks. The caller must ensure
    /// blocks are sorted, non-overlapping, non-empty, and within capacity.
    fn from_blocks(blocks: Vec<(usize, Vec<T>)>) -> Self {
        let poly = Self {
            blocks,
            _marker: PhantomData,
        };
        poly.assert_invariants();
        poly
    }
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

impl<T, R: Rank> Default for Polynomial<T, R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, R: Rank> Polynomial<T, R> {
    /// Creates a new empty (zero) polynomial.
    pub fn new() -> Self {
        Self {
            blocks: Vec::new(),
            _marker: PhantomData,
        }
    }
}

impl<F: Field, R: Rank> Polynomial<F, R> {
    /// Compresses a dense coefficient vector into sparse block form, omitting
    /// zero elements.
    ///
    /// Panics if `coeffs.len()` exceeds `R::num_coeffs()`.
    pub fn from_coeffs(coeffs: Vec<F>) -> Self {
        assert!(
            coeffs.len() <= R::num_coeffs(),
            "coefficient vector length {} exceeds capacity {}",
            coeffs.len(),
            R::num_coeffs()
        );

        let mut blocks = Vec::new();
        let mut block_start = None;
        let mut current_block = Vec::new();

        for (i, coeff) in coeffs.into_iter().enumerate() {
            if bool::from(coeff.is_zero()) {
                if !current_block.is_empty() {
                    blocks.push((
                        block_start.expect("set when current_block is non-empty"),
                        current_block,
                    ));
                    current_block = Vec::new();
                    block_start = None;
                }
            } else {
                if block_start.is_none() {
                    block_start = Some(i);
                }
                current_block.push(coeff);
            }
        }

        if !current_block.is_empty() {
            blocks.push((
                block_start.expect("set when current_block is non-empty"),
                current_block,
            ));
        }

        let poly = Self {
            blocks,
            _marker: PhantomData,
        };
        poly.assert_invariants();
        poly
    }

    /// Creates a polynomial with random coefficients filling all `4n` slots.
    pub fn random<RNG: CryptoRng>(rng: &mut RNG) -> Self {
        let coeffs: Vec<F> = (0..R::num_coeffs()).map(|_| F::random(&mut *rng)).collect();
        Self {
            blocks: alloc::vec![(0, coeffs)],
            _marker: PhantomData,
        }
    }
}

// ---------------------------------------------------------------------------
// Block storage operations (generic, no field bounds)
// ---------------------------------------------------------------------------

impl<T, R: Rank> Polynomial<T, R> {
    /// Applies a closure to every stored element.
    fn apply_all(&mut self, mut op: impl FnMut(&mut T)) {
        for (_, data) in &mut self.blocks {
            for elem in data.iter_mut() {
                op(elem);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Polynomial operations (require F: Field)
// ---------------------------------------------------------------------------

impl<F: Field, R: Rank> Polynomial<F, R> {
    /// Expands to a dense coefficient vector of length `R::num_coeffs()`.
    pub(crate) fn to_dense(&self) -> Vec<F> {
        let mut dense = alloc::vec![F::ZERO; R::num_coeffs()];
        for (start, data) in &self.blocks {
            dense[*start..*start + data.len()].copy_from_slice(data);
        }
        dense
    }

    /// Iterates over the coefficients of this polynomial in ascending order of
    /// degree, yielding `F::ZERO` for gaps between blocks.
    pub fn iter_coeffs(&self) -> impl DoubleEndedIterator<Item = F> + ExactSizeIterator + '_ {
        self.to_dense().into_iter()
    }

    /// Merges another polynomial into this one using the given binary
    /// operation, pruning zero-valued results.
    fn combine_assign(&mut self, other: &Self, mut op: impl FnMut(&mut F, &F)) {
        let capacity = R::num_coeffs();
        let mut dense = alloc::vec![F::ZERO; capacity];

        for (start, data) in &self.blocks {
            dense[*start..*start + data.len()].copy_from_slice(data);
        }

        for (start, data) in &other.blocks {
            for (i, val) in data.iter().enumerate() {
                op(&mut dense[start + i], val);
            }
        }

        let mut blocks: Vec<(usize, Vec<F>)> = Vec::new();
        let mut current_block: Option<(usize, Vec<F>)> = None;
        for (i, val) in dense.into_iter().enumerate() {
            if !bool::from(val.is_zero()) {
                if let Some((_, ref mut data)) = current_block {
                    data.push(val);
                } else {
                    current_block = Some((i, alloc::vec![val]));
                }
            } else if let Some(block) = current_block.take() {
                blocks.push(block);
            }
        }
        if let Some(block) = current_block {
            blocks.push(block);
        }
        self.blocks = blocks;
    }

    /// Multiplies all coefficients by `by`, dropping any blocks that become
    /// entirely zero.
    pub fn scale(&mut self, by: F) {
        self.apply_all(|x| *x *= by);
        self.blocks
            .retain(|(_, data)| data.iter().any(|x| !bool::from(x.is_zero())));
    }

    /// Adds the coefficients of `other` to `self`.
    pub fn add_assign(&mut self, other: &Self) {
        self.combine_assign(other, |a, b| *a += *b);
    }

    /// Subtracts the coefficients of `other` from `self`.
    pub fn sub_assign(&mut self, other: &Self) {
        self.combine_assign(other, |a, b| *a -= *b);
    }

    /// Negates all coefficients.
    pub fn negate(&mut self) {
        self.apply_all(|x| *x = -*x);
    }

    /// Horner-style weighted sum of polynomials by powers of `scale_factor`.
    ///
    /// Given polynomials $p\_{0}, p\_{1}, \ldots, p\_{k-1}$ and factor
    /// $\alpha$:
    ///
    /// $$\text{fold} = \alpha^{k-1} p\_{0} + \alpha^{k-2} p\_{1} + \cdots + p\_{k-1}$$
    pub fn fold<E: Borrow<Self>>(polys: impl IntoIterator<Item = E>, scale_factor: F) -> Self {
        polys.into_iter().fold(Self::default(), |mut acc, poly| {
            acc.scale(scale_factor);
            acc.add_assign(poly.borrow());
            acc
        })
    }

    /// Evaluates this polynomial at `z`.
    pub fn eval(&self, z: F) -> F {
        let mut result = F::ZERO;
        let mut power = F::ONE;
        let mut prev_end: usize = 0;
        for (start, data) in &self.blocks {
            for _ in prev_end..*start {
                power *= z;
            }
            for coeff in data {
                result += *coeff * power;
                power *= z;
            }
            prev_end = *start + data.len();
        }
        result
    }

    /// Transforms `p(X)` into `p(zX)` by multiplying each coefficient at
    /// degree `k` by `z^k`.
    pub fn dilate(&mut self, z: F) {
        let mut power = F::ONE;
        let mut prev_end: usize = 0;
        for (start, data) in &mut self.blocks {
            for _ in prev_end..*start {
                power *= z;
            }
            for coeff in data.iter_mut() {
                *coeff *= power;
                power *= z;
            }
            prev_end = *start + data.len();
        }
    }

    /// Inner product of `self` with the coefficient-reversed `other`.
    ///
    /// Computes $\sum\_{k} \text{self}\[k\] \cdot \text{other}\[4n - 1 - k\]$.
    ///
    /// Uses a two-pointer merge over both block lists for $O(\text{nnz})$
    /// time.
    pub fn revdot(&self, other: &Self) -> F {
        let max_deg = R::num_coeffs() - 1;
        let mut result = F::ZERO;

        let mut a_iter = self.blocks.iter().peekable();
        // Iterating other's blocks in reverse yields ascending reversed-index
        // ranges, suitable for a merge with self's ascending blocks.
        let mut b_iter = other.blocks.iter().rev().peekable();

        while let (Some(a_blk), Some(b_blk)) = (a_iter.peek(), b_iter.peek()) {
            let (a_start, a_data) = (a_blk.0, &a_blk.1);
            let (b_start, b_data) = (b_blk.0, &b_blk.1);

            let a_end = a_start + a_data.len();
            let b_len = b_data.len();
            // Other block (b_start, b_data) covers original indices
            // [b_start, b_start + b_len). In the reversed view these map to
            // [max_deg - b_start - b_len + 1, max_deg - b_start + 1).
            let rev_lo = max_deg + 1 - b_start - b_len;
            let rev_hi = max_deg + 1 - b_start;

            let overlap_lo = a_start.max(rev_lo);
            let overlap_hi = a_end.min(rev_hi);

            if overlap_lo < overlap_hi {
                let a_slice = &a_data[overlap_lo - a_start..overlap_hi - a_start];
                // For index k in [overlap_lo, overlap_hi), the other value is
                // at b_data[max_deg - k - b_start]. As k increases, the
                // b_data index decreases, so we zip a forward with b reversed.
                let b_idx_lo = max_deg - (overlap_hi - 1) - b_start;
                let b_idx_hi = max_deg - overlap_lo - b_start;
                let b_slice = &b_data[b_idx_lo..=b_idx_hi];

                for (a_val, b_val) in a_slice.iter().zip(b_slice.iter().rev()) {
                    result += *a_val * *b_val;
                }
            }

            if a_end <= rev_hi {
                a_iter.next();
            }
            if rev_hi <= a_end {
                b_iter.next();
            }
        }

        result
    }

    /// Computes a commitment to this polynomial in projective form. Use
    /// [`batch_to_affine`](ragu_arithmetic::batch_to_affine) to efficiently
    /// convert multiple projective commitments to affine with a single
    /// field inversion.
    pub fn commit<C: CurveAffine<ScalarExt = F>>(
        &self,
        generators: &impl ragu_arithmetic::FixedGenerators<C>,
        blind: F,
    ) -> C::Curve {
        assert!(generators.g().len() >= R::num_coeffs());

        let g = generators.g();
        ragu_arithmetic::mul(
            self.blocks
                .iter()
                .flat_map(|(_, data)| data.iter())
                .chain(core::iter::once(&blind)),
            self.blocks
                .iter()
                .flat_map(|(start, data)| &g[*start..*start + data.len()])
                .chain(core::iter::once(generators.h())),
        )
    }

    /// Computes a commitment to this polynomial, normalized to affine. For
    /// multiple commitments, prefer [`commit`](Self::commit) with
    /// [`batch_to_affine`](ragu_arithmetic::batch_to_affine) to share a
    /// single field inversion.
    pub fn commit_to_affine<C: CurveAffine<ScalarExt = F>>(
        &self,
        generators: &impl ragu_arithmetic::FixedGenerators<C>,
        blind: F,
    ) -> C {
        self.commit(generators, blind).into()
    }
}

// ---------------------------------------------------------------------------
// Trait impls
// ---------------------------------------------------------------------------

impl<F: Field, R: Rank> ragu_arithmetic::Ring for Polynomial<F, R> {
    type R = Self;
    type F = F;

    fn scale_assign(r: &mut Self, by: F) {
        r.scale(by);
    }
    fn add_assign(r: &mut Self, other: &Self) {
        Polynomial::add_assign(r, other);
    }
    fn sub_assign(r: &mut Self, other: &Self) {
        Polynomial::sub_assign(r, other);
    }
}

impl<F: Field, R: Rank> core::ops::AddAssign<&Self> for Polynomial<F, R> {
    fn add_assign(&mut self, rhs: &Self) {
        Polynomial::add_assign(self, rhs);
    }
}

//! Block-compressed sparse polynomial representation.
//!
//! [`Polynomial<T, R>`] stores a polynomial of degree up to
//! `R::num_coeffs() - 1` as sorted, non-overlapping blocks of contiguous
//! coefficients. Gaps between blocks are implicitly zero, so memory and
//! commitment cost scale with the number of stored coefficients rather than the
//! total degree.
//!
//! Several sources of sparsity arise in practice:
//!
//! - **Alloc-optimized circuits** leave most `b`/`c`-wire coefficients zero for
//!   allocation gates and the `d`-wire zero for multiplication gates.
//! - **Stage polynomials** are zero outside a small active region.
//! - **Tail-sparse vectors** have long trailing zero runs after synthesis.
//!
//! # Construction
//!
//! - [`Polynomial::new`]: empty (zero) polynomial.
//! - [`Polynomial::from_coeffs`]: compress a dense coefficient vector, stripping
//!   leading and trailing zeros; short interior zero gaps are kept inline
//!   within blocks.
//! - [`View`]: a builder that maps four gate-indexed wire buffers to degree
//!   positions, producing a polynomial via [`View::build`]. Zero elements within
//!   a wire buffer are **preserved** in the resulting blocks — push only
//!   non-zero values for maximum compression, or use [`Polynomial::from_coeffs`]
//!   to compress a pre-built dense vector.
//!
//! Once constructed, the polynomial supports algebraic operations ([`scale`],
//! [`add_assign`], [`sub_assign`], [`negate`], [`eval`], [`revdot`],
//! [`dilate`], [`fold`], [`commit`]) but cannot be deconstructed back into wire
//! buffers.
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

use ff::Field;
use ragu_arithmetic::CurveAffine;
use rand::CryptoRng;

use alloc::vec::Vec;
use core::borrow::Borrow;
use core::marker::PhantomData;

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

/// Maximum number of consecutive zero coefficients that may be kept inline
/// within a block rather than triggering a split. Inline zeros waste MSM
/// slots in [`commit`](Polynomial::commit), so this is kept small. The
/// tolerance covers only the per-block overhead (allocation, merge
/// iterations in [`combine_assign`](Polynomial::combine_assign)) — each
/// extra block requires a `pow_vartime` call to skip the gap.
///
/// TODO(#608): benchmark to determine the optimal value.
const GAP_TOLERANCE: usize = 4;

/// Splits `data` into runs of coefficients and appends each run to `out` as
/// `(base + run_offset, run_values)`. Zero gaps of up to [`GAP_TOLERANCE`]
/// consecutive zeros are kept inline within a run; longer gaps cause a split.
/// Leading and trailing zeros are always trimmed.
fn extend_runs<F: Field>(out: &mut Vec<(usize, Vec<F>)>, base: usize, data: Vec<F>) {
    let mut run_start: Option<usize> = None;
    let mut run = Vec::new();
    let mut zero_count: usize = 0;

    for (i, coeff) in data.into_iter().enumerate() {
        let is_zero = bool::from(coeff.is_zero());

        match (run_start, is_zero) {
            (None, true) => {}
            (None, false) => {
                run_start = Some(base + i);
                run.push(coeff);
            }
            (Some(_), false) => {
                run.extend(core::iter::repeat_n(F::ZERO, zero_count));
                zero_count = 0;
                run.push(coeff);
            }
            (Some(_), true) => {
                zero_count += 1;
                if zero_count > GAP_TOLERANCE {
                    out.push((run_start.take().unwrap(), core::mem::take(&mut run)));
                    zero_count = 0;
                }
            }
        }
    }

    if let Some(s) = run_start {
        out.push((s, run));
    }
}

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
    /// Compresses a dense coefficient vector into sparse block form. Short
    /// interior zero gaps are kept inline within blocks; longer gaps cause a
    /// block split. Leading and trailing zeros are always stripped.
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
        extend_runs(&mut blocks, 0, coeffs);
        Self::from_blocks(blocks)
    }

    /// Creates a polynomial with random coefficients filling all `4n` slots.
    pub fn random<RNG: CryptoRng>(rng: &mut RNG) -> Self {
        assert!(R::num_coeffs() > 0, "num_coeffs must be positive");
        let coeffs: Vec<F> = (0..R::num_coeffs()).map(|_| F::random(&mut *rng)).collect();
        Self::from_blocks(alloc::vec![(0, coeffs)])
    }
}

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

impl<F: Field, R: Rank> Polynomial<F, R> {
    /// Returns an iterator over the coefficients of this polynomial in
    /// ascending degree order, yielding `F::ZERO` for gaps between blocks.
    pub fn iter_coeffs(&self) -> impl DoubleEndedIterator<Item = F> + ExactSizeIterator + '_ {
        CoeffIter {
            blocks: &self.blocks,
            front: 0,
            back: R::num_coeffs(),
            front_block: 0,
            back_block: self.blocks.len(),
        }
    }

    /// Merges another polynomial into this one using the given binary
    /// operation, pruning all-zero blocks from the result.
    fn combine_assign(&mut self, other: &Self, mut op: impl FnMut(&mut F, &F)) {
        if other.blocks.is_empty() {
            return;
        }
        if self.blocks.is_empty() {
            let mut out = Vec::new();
            for (s, d) in &other.blocks {
                let mut v = alloc::vec![F::ZERO; d.len()];
                for (o, r) in v.iter_mut().zip(d) {
                    op(o, r);
                }
                extend_runs(&mut out, *s, v);
            }
            self.blocks = out;
            self.assert_invariants();
            return;
        }

        let mut lhs = core::mem::take(&mut self.blocks);
        let rhs = &other.blocks;
        let mut out = Vec::with_capacity(lhs.len() + rhs.len());
        let mut li = 0usize;
        let mut ri = 0usize;

        while li < lhs.len() || ri < rhs.len() {
            // Start of the next cluster of overlapping/adjacent blocks.
            let cluster_start = match (lhs.get(li), rhs.get(ri)) {
                (Some(l), Some(r)) => l.0.min(r.0),
                (Some(l), None) => l.0,
                (None, Some(r)) => r.0,
                (None, None) => break,
            };

            // Extend the cluster to cover all overlapping or adjacent blocks.
            let mut cluster_end = cluster_start;
            let li_start = li;
            let ri_start = ri;
            loop {
                let mut extended = false;
                while li < lhs.len() && lhs[li].0 <= cluster_end {
                    cluster_end = cluster_end.max(lhs[li].0 + lhs[li].1.len());
                    li += 1;
                    extended = true;
                }
                while ri < rhs.len() && rhs[ri].0 <= cluster_end {
                    cluster_end = cluster_end.max(rhs[ri].0 + rhs[ri].1.len());
                    ri += 1;
                    extended = true;
                }
                if !extended {
                    break;
                }
            }

            // No RHS blocks in this cluster — LHS blocks pass through
            // unchanged, avoiding the dense intermediate buffer.
            if ri == ri_start {
                for block in &mut lhs[li_start..li] {
                    out.push((block.0, core::mem::take(&mut block.1)));
                }
                continue;
            }

            let cluster_len = cluster_end - cluster_start;

            // If one LHS block covers the entire cluster, reuse its
            // allocation instead of copying into a fresh buffer.
            let mut data = if li == li_start + 1
                && lhs[li_start].0 == cluster_start
                && lhs[li_start].1.len() == cluster_len
            {
                core::mem::take(&mut lhs[li_start].1)
            } else {
                let mut data = alloc::vec![F::ZERO; cluster_len];
                for (ls, ld) in &lhs[li_start..li] {
                    let off = ls - cluster_start;
                    data[off..off + ld.len()].copy_from_slice(ld);
                }
                data
            };

            // Apply RHS contributions with tight slice loops.
            for (rs, rd) in &rhs[ri_start..ri] {
                let off = rs - cluster_start;
                for (d, r) in data[off..off + rd.len()].iter_mut().zip(rd) {
                    op(d, r);
                }
            }

            if cluster_start == 0 && cluster_len == R::num_coeffs() {
                out.push((cluster_start, data));
            } else {
                extend_runs(&mut out, cluster_start, data);
            }
        }

        self.blocks = out;
        self.assert_invariants();
    }

    /// Multiplies all coefficients by `by`.
    pub fn scale(&mut self, by: F) {
        if bool::from(by.is_zero()) {
            self.blocks.clear();
        } else {
            self.apply_all(|x| *x *= by);
        }
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

    /// Evaluates this polynomial at `z` using reverse Horner's method by block.
    pub fn eval(&self, z: F) -> F {
        let mut result = F::ZERO;
        let mut prev_start = R::num_coeffs();
        for (start, data) in self.blocks.iter().rev() {
            let gap = prev_start - (start + data.len());
            if gap > 0 {
                result *= z.pow_vartime([gap as u64]);
            }
            for coeff in data.iter().rev() {
                result = result * z + *coeff;
            }
            prev_start = *start;
        }
        if prev_start > 0 {
            result *= z.pow_vartime([prev_start as u64]);
        }
        result
    }

    /// Transforms `p(X)` into `p(zX)` by multiplying each coefficient at
    /// degree `k` by `z^k`.
    pub fn dilate(&mut self, z: F) {
        let mut power = F::ONE;
        let mut prev_end: usize = 0;
        for (start, data) in &mut self.blocks {
            let gap = *start - prev_end;
            if gap > 0 {
                power *= z.pow_vartime([gap as u64]);
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
    ) -> C::Curve {
        assert!(generators.g().len() >= R::num_coeffs());

        let g = generators.g();
        ragu_arithmetic::mul(
            self.blocks.iter().flat_map(|(_, data)| data.iter()),
            self.blocks
                .iter()
                .flat_map(|(start, data)| &g[*start..*start + data.len()]),
        )
    }

    /// Computes a commitment to this polynomial, normalized to affine. For
    /// multiple commitments, prefer [`commit`](Self::commit) with
    /// [`batch_to_affine`](ragu_arithmetic::batch_to_affine) to share a
    /// single field inversion.
    pub fn commit_to_affine<C: CurveAffine<ScalarExt = F>>(
        &self,
        generators: &impl ragu_arithmetic::FixedGenerators<C>,
    ) -> C {
        self.commit(generators).into()
    }
}

/// An iterator over all coefficients of a sparse polynomial in ascending
/// degree order, yielding `F::ZERO` for gaps between blocks.
struct CoeffIter<'a, F> {
    blocks: &'a [(usize, Vec<F>)],
    front: usize,
    back: usize,
    /// Index of the first block whose end extends past `front`.
    front_block: usize,
    /// One past the last block whose start is at or before `back - 1`.
    back_block: usize,
}

impl<F: Field> Iterator for CoeffIter<'_, F> {
    type Item = F;

    fn next(&mut self) -> Option<F> {
        if self.front >= self.back {
            return None;
        }
        // Advance past blocks fully before `front`.
        while self.front_block < self.blocks.len() {
            let (start, data) = &self.blocks[self.front_block];
            if *start + data.len() > self.front {
                break;
            }
            self.front_block += 1;
        }
        let val = if self.front_block < self.blocks.len() {
            let (start, data) = &self.blocks[self.front_block];
            if self.front >= *start {
                data[self.front - *start]
            } else {
                F::ZERO
            }
        } else {
            F::ZERO
        };
        self.front += 1;
        Some(val)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.back - self.front;
        (len, Some(len))
    }
}

impl<F: Field> DoubleEndedIterator for CoeffIter<'_, F> {
    fn next_back(&mut self) -> Option<F> {
        if self.front >= self.back {
            return None;
        }
        self.back -= 1;
        // Retreat past blocks that start after `back`.
        while self.back_block > 0 {
            let (start, _) = &self.blocks[self.back_block - 1];
            if *start <= self.back {
                break;
            }
            self.back_block -= 1;
        }
        let val = if self.back_block > 0 {
            let (start, data) = &self.blocks[self.back_block - 1];
            if self.back < *start + data.len() {
                data[self.back - *start]
            } else {
                F::ZERO
            }
        } else {
            F::ZERO
        };
        Some(val)
    }
}

impl<F: Field> ExactSizeIterator for CoeffIter<'_, F> {}

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

impl<F: Field, R: Rank> core::ops::SubAssign<&Self> for Polynomial<F, R> {
    fn sub_assign(&mut self, rhs: &Self) {
        Polynomial::sub_assign(self, rhs);
    }
}

#[cfg(test)]
impl<F: Field, R: Rank> Polynomial<F, R> {
    /// Expands to a dense coefficient vector of length `R::num_coeffs()`.
    pub(crate) fn to_dense(&self) -> Vec<F> {
        self.iter_coeffs().collect()
    }
}

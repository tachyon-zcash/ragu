//! Sparse polynomial representation using three fixed-region blocks.
//!
//! [`Polynomial<T, R>`] stores a polynomial of degree up to
//! `R::num_coeffs() - 1` using three dense blocks separated by two gaps,
//! with each block constrained to a fixed degree region:
//!
//! - **lo**: degrees `[0, n)` — the `c`-wire region
//! - **mid**: degrees `[n, 3n)` — the `b_rev ++ a` region (meeting at `2n`)
//! - **hi**: degrees `[3n, 4n)` — the `d_rev` region
//!
//! where `n = R::n()`. Each block stores an offset and a dense vector
//! within its region. The fixed region boundaries guarantee that
//! block-wise arithmetic is always safe — no variant dispatch or
//! compatibility checks needed.
//!
//! # Construction
//!
//! - [`Polynomial::new`]: empty (zero) polynomial.
//! - [`Polynomial::from_coeffs`]: decompose a dense coefficient vector into the
//!   three regions, trimming leading and trailing zeros within each.
//! - [`View`]: a builder that maps four gate-indexed wire buffers to degree
//!   positions via [`View::build`]. Zero elements within a wire buffer are
//!   **preserved** in the resulting blocks — push only non-zero values for
//!   maximum compression, or use [`Polynomial::from_coeffs`] to strip a
//!   pre-built dense vector.
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

/// Block names for assertion messages.
const BLOCK_NAMES: [&str; 3] = ["lo", "mid", "hi"];

/// A sparse polynomial with coefficients stored in three fixed-region blocks.
///
/// See the [module documentation](self) for details.
#[derive(Clone, Debug)]
pub struct Polynomial<T, R: Rank> {
    /// Three `(offset, data)` blocks for lo `[0, n)`, mid `[n, 3n)`, hi
    /// `[3n, 4n)`.
    blocks: [(usize, Vec<T>); 3],
    _marker: PhantomData<R>,
}

impl<T, R: Rank> Polynomial<T, R> {
    /// Default offsets for the three regions: `[0, n, 3n]`.
    fn default_offsets() -> [usize; 3] {
        let n = R::n();
        [0, n, 3 * n]
    }

    /// Panics if the representation violates region-bound invariants.
    ///
    /// Each block must stay within its fixed degree region:
    /// - `lo` within `[0, n)`
    /// - `mid` within `[n, 3n)`
    /// - `hi` within `[3n, 4n)`
    fn assert_invariants(&self) {
        let n = R::n();
        let bounds = [(0, n), (n, 3 * n), (3 * n, 4 * n)];
        for (i, ((off, data), (lo, hi))) in self.blocks.iter().zip(bounds).enumerate() {
            assert!(
                *off >= lo && off + data.len() <= hi,
                "{} block [{}, {}) exceeds region [{lo}, {hi})",
                BLOCK_NAMES[i],
                off,
                off + data.len(),
            );
        }
    }

    // Constructs from three `(offset, data)` blocks, asserting region-bound
    // invariants. The blocks correspond to lo, mid, hi in order.
    fn from_blocks(blocks: [(usize, Vec<T>); 3]) -> Self {
        let poly = Self {
            blocks,
            _marker: PhantomData,
        };
        poly.assert_invariants();
        poly
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
        let offsets = Self::default_offsets();
        Self {
            blocks: [
                (offsets[0], Vec::new()),
                (offsets[1], Vec::new()),
                (offsets[2], Vec::new()),
            ],
            _marker: PhantomData,
        }
    }
}

impl<F: Field, R: Rank> Polynomial<F, R> {
    /// Decomposes a dense coefficient vector into three fixed-region blocks,
    /// trimming leading and trailing zeros within each region.
    ///
    /// Panics if `coeffs.len()` exceeds `R::num_coeffs()`.
    pub fn from_coeffs(mut coeffs: Vec<F>) -> Self {
        let len = coeffs.len();
        assert!(
            len <= R::num_coeffs(),
            "coefficient vector length {len} exceeds capacity {}",
            R::num_coeffs()
        );

        let n = R::n();
        let mut offsets = Self::default_offsets();

        // Split at region boundaries without padding — only split what exists.
        let mut hi = if len > 3 * n {
            coeffs.split_off(3 * n)
        } else {
            Vec::new()
        };
        let mut mid = if len > n {
            coeffs.split_off(n)
        } else {
            Vec::new()
        };
        let mut lo = coeffs;

        Self::trim_block(&mut offsets[0], &mut lo);
        Self::trim_block(&mut offsets[1], &mut mid);
        Self::trim_block(&mut offsets[2], &mut hi);

        Self::from_blocks([(offsets[0], lo), (offsets[1], mid), (offsets[2], hi)])
    }

    /// Creates a polynomial with random coefficients filling all `4n` slots.
    pub fn random<RNG: CryptoRng>(rng: &mut RNG) -> Self {
        assert!(R::num_coeffs() > 0, "num_coeffs must be positive");
        let n = R::n();
        let mut coeffs: Vec<F> = (0..R::num_coeffs()).map(|_| F::random(&mut *rng)).collect();
        let hi = coeffs.split_off(3 * n);
        let mid = coeffs.split_off(n);
        let lo = coeffs;
        Self::from_blocks([(0, lo), (n, mid), (3 * n, hi)])
    }
}

impl<T, R: Rank> Polynomial<T, R> {
    /// Applies a closure to every stored element.
    fn apply_all(&mut self, mut op: impl FnMut(&mut T)) {
        for (_, data) in &mut self.blocks {
            for elem in data {
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
            blocks: [
                (self.blocks[0].0, self.blocks[0].1.as_slice()),
                (self.blocks[1].0, self.blocks[1].1.as_slice()),
                (self.blocks[2].0, self.blocks[2].1.as_slice()),
            ],
            front: 0,
            back: R::num_coeffs(),
            front_blk: 0,
            back_blk: 3,
        }
    }

    /// Multiplies all coefficients by `by`.
    pub fn scale(&mut self, by: F) {
        if bool::from(by.is_zero()) {
            *self = Self::new();
        } else {
            self.apply_all(|x| *x *= by);
        }
    }

    /// Negates all coefficients.
    pub fn negate(&mut self) {
        self.apply_all(|x| *x = -*x);
    }

    /// Adds the coefficients of `other` to `self`.
    pub fn add_assign(&mut self, other: &Self) {
        self.combine_assign(other, |a, b| *a += *b);
    }

    /// Subtracts the coefficients of `other` from `self`.
    pub fn sub_assign(&mut self, other: &Self) {
        self.combine_assign(other, |a, b| *a -= *b);
    }

    /// Applies a binary operation block-wise. Always safe because both
    /// polynomials have blocks within the same fixed region bounds.
    fn combine_assign(&mut self, other: &Self, op: impl Fn(&mut F, &F)) {
        for i in 0..3 {
            Self::merge(
                &mut self.blocks[i].0,
                &mut self.blocks[i].1,
                other.blocks[i].0,
                &other.blocks[i].1,
                &op,
            );
            Self::trim_block(&mut self.blocks[i].0, &mut self.blocks[i].1);
        }
    }

    /// Strips leading and trailing zeros from a block in place, adjusting
    /// the offset. Clears the block entirely if all elements are zero.
    fn trim_block(offset: &mut usize, data: &mut Vec<F>) {
        // Trim trailing zeros.
        while data.last().is_some_and(|v| bool::from(v.is_zero())) {
            data.pop();
        }
        // Trim leading zeros.
        let leading = data
            .iter()
            .position(|v| !bool::from(v.is_zero()))
            .unwrap_or(0);
        if leading > 0 {
            data.drain(..leading);
            *offset += leading;
        }
    }

    /// Merges `other` block into `self` block, expanding `self` to cover
    /// the union range if needed, then applying `op` element-wise.
    fn merge(
        s_off: &mut usize,
        s_data: &mut Vec<F>,
        o_off: usize,
        o_data: &[F],
        op: &impl Fn(&mut F, &F),
    ) {
        if o_data.is_empty() {
            return;
        }
        if s_data.is_empty() {
            *s_off = o_off;
            *s_data = alloc::vec![F::ZERO; o_data.len()];
            for (dst, src) in s_data.iter_mut().zip(o_data) {
                op(dst, src);
            }
            return;
        }
        let s_end = *s_off + s_data.len();
        let o_end = o_off + o_data.len();
        let new_off = (*s_off).min(o_off);
        let new_end = s_end.max(o_end);

        if new_off < *s_off || new_end > s_end {
            let mut new_buf = alloc::vec![F::ZERO; new_end - new_off];
            let rel = *s_off - new_off;
            new_buf[rel..rel + s_data.len()].copy_from_slice(s_data);
            *s_data = new_buf;
            *s_off = new_off;
        }

        let rel = o_off - *s_off;
        for (dst, src) in s_data[rel..rel + o_data.len()].iter_mut().zip(o_data) {
            op(dst, src);
        }
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

    /// Evaluates this polynomial at `z` using reverse Horner's method by
    /// block.
    pub fn eval(&self, z: F) -> F {
        let mut result = F::ZERO;
        let mut prev_start = R::num_coeffs();

        for &(start, ref data) in self.blocks.iter().rev() {
            if data.is_empty() {
                continue;
            }
            let gap = prev_start - (start + data.len());
            if gap > 0 {
                result *= z.pow_vartime([gap as u64]);
            }
            for coeff in data.iter().rev() {
                result = result * z + *coeff;
            }
            prev_start = start;
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

        for &mut (start, ref mut data) in &mut self.blocks {
            if data.is_empty() {
                continue;
            }
            let gap = start - prev_end;
            if gap > 0 {
                power *= z.pow_vartime([gap as u64]);
            }
            for coeff in data.iter_mut() {
                *coeff *= power;
                power *= z;
            }
            prev_end = start + data.len();
        }
    }

    /// Inner product of `self` with the coefficient-reversed `other`.
    ///
    /// Computes $\sum\_{k} \text{self}\[k\] \cdot \text{other}\[4n - 1 - k\]$.
    ///
    /// The fixed region boundaries mean only 3 pairs contribute:
    /// lo `[0,n)` pairs with reversed hi `[3n,4n)`, mid `[n,3n)` with
    /// reversed mid, and hi with reversed lo.
    pub fn revdot(&self, other: &Self) -> F {
        let n4 = R::num_coeffs();
        // lo x rev(hi), mid x rev(mid), hi x rev(lo)
        Self::revdot_pair(&self.blocks[0], &other.blocks[2], n4)
            + Self::revdot_pair(&self.blocks[1], &other.blocks[1], n4)
            + Self::revdot_pair(&self.blocks[2], &other.blocks[0], n4)
    }

    /// Dot product of block `a` with the coefficient-reversed block `b`.
    fn revdot_pair(a: &(usize, Vec<F>), b: &(usize, Vec<F>), n4: usize) -> F {
        let (a_off, a_data) = (a.0, a.1.as_slice());
        let (b_off, b_data) = (b.0, b.1.as_slice());
        if a_data.is_empty() || b_data.is_empty() {
            return F::ZERO;
        }

        // Block b at [b_off, b_off+b_len) reversed maps to
        // [n4 - b_off - b_len, n4 - b_off).
        let a_end = a_off + a_data.len();
        let rev_lo = n4 - b_off - b_data.len();
        let rev_hi = n4 - b_off;

        let overlap_lo = a_off.max(rev_lo);
        let overlap_hi = a_end.min(rev_hi);
        if overlap_lo >= overlap_hi {
            return F::ZERO;
        }

        let a_slice = &a_data[overlap_lo - a_off..overlap_hi - a_off];
        // For index k in [overlap_lo, overlap_hi), b's value is at
        // b_data[n4 - 1 - k - b_off]. As k increases, the b_data index
        // decreases, so we zip a forward with b reversed.
        let b_idx_lo = n4 - 1 - (overlap_hi - 1) - b_off;
        let b_idx_hi = n4 - 1 - overlap_lo - b_off;
        let b_slice = &b_data[b_idx_lo..=b_idx_hi];

        let mut result = F::ZERO;
        for (a_val, b_val) in a_slice.iter().zip(b_slice.iter().rev()) {
            result += *a_val * *b_val;
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
                .filter(|(_, data)| !data.is_empty())
                .flat_map(|(_, data)| data.iter())
                .chain(core::iter::once(&blind)),
            self.blocks
                .iter()
                .filter(|(_, data)| !data.is_empty())
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

/// An iterator over all coefficients of a sparse polynomial in ascending
/// degree order, yielding `F::ZERO` for gaps between blocks.
struct CoeffIter<'a, F> {
    /// All 3 blocks (including empty ones — skipped naturally by the
    /// advance/retreat logic since empty blocks have `start + 0 <= front`).
    blocks: [(usize, &'a [F]); 3],
    front: usize,
    back: usize,
    /// Index of the first block whose end extends past `front`.
    front_blk: usize,
    /// One past the last block whose start is at or before `back - 1`.
    back_blk: usize,
}

impl<F: Field> Iterator for CoeffIter<'_, F> {
    type Item = F;

    fn next(&mut self) -> Option<F> {
        if self.front >= self.back {
            return None;
        }
        // Advance past blocks fully before `front`.
        while self.front_blk < 3 {
            let (start, data) = self.blocks[self.front_blk];
            if start + data.len() > self.front {
                break;
            }
            self.front_blk += 1;
        }
        let val = if self.front_blk < 3 {
            let (start, data) = self.blocks[self.front_blk];
            if self.front >= start {
                data[self.front - start]
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
        while self.back_blk > 0 {
            let (start, _) = self.blocks[self.back_blk - 1];
            if start <= self.back {
                break;
            }
            self.back_blk -= 1;
        }
        let val = if self.back_blk > 0 {
            let (start, data) = self.blocks[self.back_blk - 1];
            if self.back < start + data.len() {
                data[self.back - start]
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

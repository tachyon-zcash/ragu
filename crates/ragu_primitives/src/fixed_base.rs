use alloc::vec::Vec;
use core::array;

use ragu_core::{Error, Result, drivers::Driver};
use udon::{
    curve::{EndomorphismAffine, Projective},
    field::Field,
};

use crate::{
    Boolean, Element, Nonzero, NonzeroBank, Point, multiadd,
    vec::{ConstLen, FixedVec},
};

/// An affine table evaluated in at most two gates.
struct Window<F> {
    left: [F; 3],
    right: [F; 3],
    inner: [F; 3],
    x: [F; 6],
    y: [F; 6],
}

impl<F: Field> Window<F> {
    /// Applies the Möbius transform on $\{0, 1\}^3$, indexed by monomial mask.
    fn monomials(mut values: [F; 8]) -> [F; 8] {
        for bit in [1, 2, 4] {
            for mask in 0..8 {
                if mask & bit != 0 {
                    values[mask] -= values[mask ^ bit];
                }
            }
        }
        values
    }

    fn new(entries: [(F, F); 8], width: usize) -> Result<Self> {
        let x = Self::monomials(entries.map(|(x, _)| x));
        let y = Self::monomials(entries.map(|(_, y)| y));
        if width < 3 {
            // A short window uses only its first 2^width entries. Their
            // monomials are 1, b0, b1 and b0*b1, with absent bits set to zero.
            let short = |v: [F; 8]| [v[0], v[1], v[2], F::ZERO, v[3], F::ZERO];
            return Ok(Self {
                left: [F::ONE, F::ZERO, F::ZERO],
                right: [F::ZERO, F::ONE, F::ZERO],
                inner: [F::ZERO; 3],
                x: short(x),
                y: short(y),
            });
        }

        let degenerate = || Error::Initialization("degenerate fixed-base window".into());
        // `x[7] * y - y[7] * x` cancels the cubic term; match its three
        // quadratic coefficients with one product `p`.
        let [q01, q02, q12] = [3, 5, 6].map(|mask| x[7] * y[mask] - y[7] * x[mask]);
        let q01_inv = q01.invert().ok_or_else(degenerate)?;
        let x7_inv = x[7].invert().ok_or_else(degenerate)?;
        let left = [F::ONE, F::ZERO, q12 * q01_inv];
        let right = [F::ZERO, q01, q02];

        // Subtracting `x`'s `b0 * b1` term via `p` leaves only `b2` multiples in
        // the nonlinear part, matched by `c = b2 * (a*b0 + b*b1 + rho*p)`.
        let rho = x[7] * q01_inv;
        let shift = x[3] * q01_inv + rho;
        let inner = [x[5] - shift * q02, x[6] - shift * q12, rho];

        let dot =
            |coeffs: &[F], terms: &[F]| coeffs.iter().zip(terms).map(|(&a, &b)| a * b).sum::<F>();
        let basis: [[F; 6]; 8] = array::from_fn(|digit| {
            let bits = [1, 2, 4].map(|mask| F::from(u64::from(digit & mask != 0)));
            let [b0, b1, b2] = bits;
            let p = dot(&left, &bits) * dot(&right, &bits);
            let c = b2 * dot(&inner, &[b0, b1, p]);
            [F::ONE, b0, b1, b2, p, c]
        });
        let solve = |coordinate: [F; 8]| {
            let alpha = coordinate[3] * q01_inv;
            let gamma = coordinate[7] * x7_inv;
            let linear =
                |digit: usize| coordinate[digit] - dot(&[alpha, gamma], &basis[digit][4..]);
            [coordinate[0], linear(1), linear(2), linear(4), alpha, gamma]
        };
        let window = Self {
            left,
            right,
            inner,
            x: solve(x),
            y: solve(y),
        };
        // Check all eight evaluations directly before using them to derive the
        // `Point` contract in `select`.
        for (row, entry) in basis.iter().zip(entries) {
            assert!(
                (dot(&window.x, row), dot(&window.y, row)) == entry,
                "invertible pivots reproduce every table entry"
            );
        }
        Ok(window)
    }

    fn select<'dr, D: Driver<'dr, F = F>, C: EndomorphismAffine<Base = F>>(
        &self,
        dr: &mut D,
        bits: &[Boolean<'dr, D>],
    ) -> Result<Point<'dr, D, C>> {
        let elements: [_; 3] = array::from_fn(|i| match bits.get(i) {
            Some(bit) => bit.element(),
            None => Element::zero(dr),
        });
        let p = if bits.len() >= 2 {
            let left = multiadd(dr, &elements, &self.left);
            let right = multiadd(dr, &elements, &self.right);
            left.mul(dr, &right)?
        } else {
            Element::zero(dr)
        };
        let [b0, b1, b2] = elements;
        let c = if bits.len() == 3 {
            let inner = multiadd(dr, &[b0.clone(), b1.clone(), p.clone()], &self.inner);
            b2.mul(dr, &inner)?
        } else {
            Element::zero(dr)
        };
        let basis = [Element::one(), b0, b1, b2, p, c];
        // The products and table coefficients select a finite curve point
        // exactly on the Boolean cube (including its zero-padded faces).
        Ok(Point::new_unchecked(
            Nonzero::new_unchecked(multiadd(dr, &basis, &self.x)),
            Nonzero::new_unchecked(multiadd(dr, &basis, &self.y)),
        ))
    }
}

/// A prepared base for unsigned radix-8 scalar multiplication on a [`Point`]
/// curve.
///
/// Requires `N >= 4` and scalar field capacity at least
/// $3\lceil N/3\rceil - 2$ (4 through 255 bits on Pasta).
pub struct FixedBase<C: EndomorphismAffine, const N: usize> {
    windows: Vec<Window<C::Base>>,
}

impl<C: EndomorphismAffine, const N: usize> FixedBase<C, N> {
    const WINDOWS: usize = N.div_ceil(3);
    const TOP_BITS: usize = (N - 1) % 3 + 1;

    /// Prepares a table for a nonidentity `base`, folding the constant point
    /// `correction` into the top window at no circuit cost. Pass the identity
    /// as `correction` for ordinary multiplication.
    ///
    /// # Errors
    ///
    /// Returns a setup error if `base` or any window entry is the identity, or
    /// if a three-bit window has a degenerate interpolation pivot.
    pub fn new(base: C, correction: C::Projective) -> Result<Self> {
        const {
            assert!(N >= 4);
            assert!(Self::WINDOWS <= (C::Scalar::CAPACITY as usize).div_ceil(3));
        }
        if base.is_identity() {
            return Err(Error::Initialization(
                "fixed base must be nonidentity".into(),
            ));
        }
        let mut windows = Vec::with_capacity(Self::WINDOWS);
        let mut power = C::Scalar::ONE;
        let mut offset = C::Scalar::ZERO;
        for i in 0..Self::WINDOWS {
            let top = i == Self::WINDOWS - 1;
            let width = if top { Self::TOP_BITS } else { 3 };
            let mut entries = [(C::Base::ZERO, C::Base::ZERO); 8];
            for (digit, entry) in entries.iter_mut().take(1 << width).enumerate() {
                let digit = C::Scalar::from(digit as u64);
                let point = if top {
                    base * (digit * power - offset) + correction
                } else {
                    base * ((digit + C::Scalar::from(2)) * power)
                };
                *entry = point.to_affine().coordinates().ok_or_else(|| {
                    Error::Initialization("fixed-base window contains the identity".into())
                })?;
            }
            windows.push(Window::new(entries, width)?);
            offset += C::Scalar::from(2) * power;
            power *= C::Scalar::from(8);
        }
        Ok(Self { windows })
    }

    /// Scales base $B$ by the unsigned little-endian value of `bits` and adds
    /// correction $C$. An identity result is unsatisfiable, including scalar
    /// zero with identity correction; use [`Self::mul_and_add`] to add a point
    /// without needing the intermediate result.
    ///
    /// Costs $N + 2W - 2$ gates and twice as many constraints, where
    /// $W = \lceil N/3\rceil$ is the number of windows.
    /// This does not bind `bits` to another value or require a canonical encoding.
    ///
    /// # Completeness
    ///
    /// Witness generation fails exactly when the prefix and top entry have
    /// the same $x$-coordinate (doubling or cancellation). With identity
    /// correction on Pasta, this excludes multiples of the group order $q$
    /// and the doubling input $(10H + 4)/7$, where $H = 8^{W-1}$.
    /// At 255 bits it also excludes the noncanonical doubling input
    /// $(66H + 4)/7 - q$.
    ///
    /// # Soundness
    ///
    /// Any satisfying assignment makes the returned point represent
    /// $\[\sum_i 2^i b_i\]B + C$. Each selector fixes the window point. For
    /// interior digit $k_j$, its coefficient is $D_j = (k_j + 2)8^j$ and the
    /// preceding prefix has coefficient $0 < A_j \le 9(8^j - 1)/7 < D_j$.
    /// For $1 \le j \le W - 2$, the sum satisfies
    /// $A_j + D_j \le 9(8^{j+1} - 1)/7 < 2^{3W-2} < q$. The nonidentity base
    /// has order $q$, so the points are neither equal nor opposite. Their
    /// distinct $x$-coordinates justify unchecked interior addition.
    ///
    /// Writing the scalar as $hH + l$ with $0 \le l < H$, the prefix is
    /// $\[l + O\]B$ and the top is $\[hH - O\]B + C$, with offset
    /// $O = 2(H - 1)/7$. The final addition
    /// enforces distinct $x$-coordinates, cancels $O$, and adds $C$. For
    /// identity correction the excluded pairs therefore satisfy either
    /// $hH + l \equiv 0 \pmod q$ or $l + 2O \equiv hH \pmod q$.
    ///
    /// # Errors
    ///
    /// Returns a witness-generation error for an exceptional addition.
    pub fn mul<'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        bits: &FixedVec<Boolean<'dr, D>, ConstLen<N>>,
    ) -> Result<Point<'dr, D, C>> {
        let (prefix, top) = self.prefix_and_top(dr, bits)?;
        Self::add_checked(dr, &prefix, &top)
    }

    /// Adds `onto` before the top window, so a zero scalar with identity
    /// correction can yield `onto` without an intermediate identity. A
    /// separate addition after [`Self::mul`] cannot do this.
    ///
    /// This costs four additional gates and eight additional constraints.
    ///
    /// # Completeness
    ///
    /// Given a prepared table, witness generation succeeds iff both the
    /// addition of `onto` and the subsequent addition of the top entry have
    /// distinct $x$-coordinates. Both inequalities are enforced.
    ///
    /// # Soundness
    ///
    /// Any satisfying assignment makes the returned point represent
    /// $\[\sum_i 2^i b_i\]B + C + P$, where $B$ is the base, $C$ is the
    /// correction, and `onto` represents $P$.
    ///
    /// # Errors
    ///
    /// Returns a witness-generation error for either exceptional addition.
    pub fn mul_and_add<'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        bits: &FixedVec<Boolean<'dr, D>, ConstLen<N>>,
        onto: &Point<'dr, D, C>,
    ) -> Result<Point<'dr, D, C>> {
        let (prefix, top) = self.prefix_and_top(dr, bits)?;
        let sum = Self::add_checked(dr, &prefix, onto)?;
        Self::add_checked(dr, &sum, &top)
    }

    fn prefix_and_top<'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        bits: &FixedVec<Boolean<'dr, D>, ConstLen<N>>,
    ) -> Result<(Point<'dr, D, C>, Point<'dr, D, C>)> {
        let (low, high) = bits.split_at(3 * (Self::WINDOWS - 1));
        let mut prefix = self.windows[0].select(dr, &low[..3])?;
        let top = Self::WINDOWS - 1;
        // The offset bound proves every interior x-difference nonzero.
        let mut bank = NonzeroBank::new_unchecked();
        for (window, bits) in self.windows[1..top].iter().zip(low[3..].chunks(3)) {
            let entry = window.select(dr, bits)?;
            prefix = prefix.add_incomplete(dr, &entry, &mut bank)?;
        }
        Ok((prefix, self.windows[top].select(dr, high)?))
    }

    fn add_checked<'dr, D: Driver<'dr, F = C::Base>>(
        dr: &mut D,
        left: &Point<'dr, D, C>,
        right: &Point<'dr, D, C>,
    ) -> Result<Point<'dr, D, C>> {
        right.x.sub(dr, &left.x).enforce_nonzero(dr)?;
        // `add_incomplete` folds only `right.x - left.x`, enforced nonzero above.
        left.add_incomplete(dr, right, &mut NonzeroBank::new_unchecked())
    }
}

#[cfg(test)]
mod tests;

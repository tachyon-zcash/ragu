use alloc::{vec, vec::Vec};
use core::array;

use ragu_core::{Coeff, Error, Result, drivers::Driver};
use udon::{curve::EndomorphismAffine, field::Field};

use crate::{
    Boolean, Element, Nonzero, NonzeroBank, Point, multiadd,
    vec::{ConstLen, FixedVec},
};

/// An affine table of up to eight points, selected by `width` bits in at most
/// two gates.
#[derive(Clone, Debug)]
struct Window<F> {
    /// The number of bits that select an entry, fixed when the table is
    /// prepared. It alone decides which products [`Self::select`] emits.
    width: usize,
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
                width,
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
            width,
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

    /// Selects the entry indexed by the little-endian `bits`.
    fn select<'dr, D: Driver<'dr, F = F>, C: EndomorphismAffine<Base = F>>(
        &self,
        dr: &mut D,
        bits: &[Boolean<'dr, D>],
    ) -> Result<Point<'dr, D, C>> {
        // This never reads a witness value. Every branch below depends only on
        // `self.width`, fixed when the table was prepared, so the emitted
        // constraints are the same for every witness.
        assert_eq!(bits.len(), self.width, "a window selects with its own bits");

        // Positions at or above the width are absent and hold a constant zero.
        let elements: [_; 3] = array::from_fn(|i| {
            if i < self.width {
                bits[i].element()
            } else {
                Element::zero(dr)
            }
        });

        // The quadratic product needs two bits, so a one-bit window omits it.
        let p = if self.width >= 2 {
            let left = multiadd(dr, &elements, &self.left);
            let right = multiadd(dr, &elements, &self.right);
            left.mul(dr, &right)?
        } else {
            Element::zero(dr)
        };
        let [b0, b1, b2] = elements;

        // The cubic product needs three bits, so only a full window emits it.
        let c = if self.width == 3 {
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
#[derive(Clone, Debug)]
pub struct FixedBase<C: EndomorphismAffine, const N: usize> {
    windows: Vec<Window<C::Base>>,
}

impl<C: EndomorphismAffine, const N: usize> FixedBase<C, N> {
    const WINDOWS: usize = N.div_ceil(3);
    const TOP_BITS: usize = (N - 1) % 3 + 1;

    /// The number of bits window `i` takes: three, or `TOP_BITS` for the top
    /// window.
    const fn width(i: usize) -> usize {
        if i == Self::WINDOWS - 1 {
            Self::TOP_BITS
        } else {
            3
        }
    }

    /// Prepares a table for a nonidentity `base`, folding the constant point
    /// `correction` into the top window at no circuit cost. Pass the identity
    /// as `correction` for ordinary multiplication.
    ///
    /// # Errors
    ///
    /// Returns a setup error if `base` or any window entry is the identity, or
    /// if a three-bit window has a degenerate interpolation pivot.
    pub fn new(base: C, correction: C) -> Result<Self> {
        const {
            assert!(N >= 4);
            assert!(Self::WINDOWS <= (C::Scalar::CAPACITY as usize).div_ceil(3));
        }
        if base.is_identity() {
            return Err(Error::Initialization(
                "fixed base must be nonidentity".into(),
            ));
        }

        // Window `i` below the top holds `(digit + 2) 8^i B`. The top window
        // holds `digit 8^i B` plus the correction, less the interior offsets.
        let correction = correction.to_projective();
        let mut points = Vec::with_capacity(8 * Self::WINDOWS);
        let mut power = C::Scalar::ONE;
        let mut offset = C::Scalar::ZERO;
        for i in 0..Self::WINDOWS {
            let top = i == Self::WINDOWS - 1;
            for digit in 0..1u64 << Self::width(i) {
                let digit = C::Scalar::from(digit);
                points.push(if top {
                    base * (digit * power - offset) + correction
                } else {
                    base * ((digit + C::Scalar::from(2)) * power)
                });
            }
            offset += C::Scalar::from(2) * power;
            power *= C::Scalar::from(8);
        }

        // One shared inversion normalizes every entry.
        let mut entries = vec![C::identity(); points.len()];
        C::batch_to_affine(&points, &mut entries);

        // Every window below the top has eight entries, so the top window's
        // entries are the last chunk.
        let windows = entries
            .chunks(8)
            .enumerate()
            .map(|(i, chunk)| {
                let mut coordinates = [(C::Base::ZERO, C::Base::ZERO); 8];
                for (slot, entry) in coordinates.iter_mut().zip(chunk) {
                    *slot = entry.coordinates().ok_or_else(|| {
                        Error::Initialization("fixed-base window contains the identity".into())
                    })?;
                }
                Window::new(coordinates, Self::width(i))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { windows })
    }

    /// Scales base $B$ by the unsigned little-endian value of `bits` and adds
    /// correction $C$. An identity result is unsatisfiable, including scalar
    /// zero with identity correction; use [`Self::mul_and_add`] to add a point
    /// without needing the intermediate result.
    ///
    /// Costs $N + 2W + 3$ gates and $2N + 4W + 7$ constraints, where
    /// $W = \lceil N/3\rceil$ is the number of windows.
    /// This does not bind `bits` to another value or require a canonical encoding.
    ///
    /// # Constraints
    ///
    /// `N` determines the emitted constraints, and the table's base and
    /// correction determine their coefficients.
    ///
    /// # Completeness
    ///
    /// Witness generation succeeds exactly when the result is not the
    /// identity. With identity correction, that excludes only the scalars
    /// divisible by the group order $q$: zero, and also $q$ at 255 bits.
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
    /// Writing the scalar as $hH + l$ with $0 \le l < H = 8^{W-1}$, the prefix
    /// is $\[l + O\]B$ and the top is $\[hH - O\]B + C$, with offset
    /// $O = 2(H - 1)/7$. The final addition cancels $O$ and adds $C$. It
    /// doubles equal points, which the scalar $(10H + 4)/7$ produces under
    /// identity correction, and has no satisfying assignment for opposite
    /// points, whose sum is the identity.
    ///
    /// # Errors
    ///
    /// Returns a witness-generation error if the result is the identity.
    pub fn mul<'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        bits: &FixedVec<Boolean<'dr, D>, ConstLen<N>>,
    ) -> Result<Point<'dr, D, C>> {
        let (prefix, top) = self.prefix_and_top(dr, bits)?;
        Self::add_or_double(dr, &prefix, &top)
    }

    /// Adds `onto` before the top window, so a zero scalar with identity
    /// correction can yield `onto` without an intermediate identity. A
    /// separate addition after [`Self::mul`] cannot do this.
    ///
    /// This costs nine additional gates and nineteen additional constraints.
    ///
    /// # Constraints
    ///
    /// As for [`Self::mul`].
    ///
    /// # Exceptional Cases
    ///
    /// `onto` is added to the prefix $\[l + O\]B$ described in [`Self::mul`],
    /// so it must not represent $-\[l + O\]B$, and the result must not be the
    /// identity. Both additions double equal points.
    ///
    /// # Soundness
    ///
    /// Any satisfying assignment makes the returned point represent
    /// $\[\sum_i 2^i b_i\]B + C + P$, where $B$ is the base, $C$ is the
    /// correction, and `onto` represents $P$.
    ///
    /// # Errors
    ///
    /// Returns a witness-generation error for either exceptional case.
    pub fn mul_and_add<'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        bits: &FixedVec<Boolean<'dr, D>, ConstLen<N>>,
        onto: &Point<'dr, D, C>,
    ) -> Result<Point<'dr, D, C>> {
        let (prefix, top) = self.prefix_and_top(dr, bits)?;
        let sum = Self::add_or_double(dr, &prefix, onto)?;
        Self::add_or_double(dr, &sum, &top)
    }

    /// Selects every window's entry and sums all but the top one, which is
    /// returned separately.
    fn prefix_and_top<'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        bits: &FixedVec<Boolean<'dr, D>, ConstLen<N>>,
    ) -> Result<(Point<'dr, D, C>, Point<'dr, D, C>)> {
        // This never reads a witness value. `N` fixes the number of windows and
        // the width of each, so the emitted constraints are the same for every
        // witness.
        //
        // Pair each window with its bits: three per window, least significant
        // first, with the top window taking the last `TOP_BITS`.
        let windows: Vec<_> = self.windows.iter().zip(bits.chunks(3)).collect();
        let (&(first, first_bits), rest) = windows
            .split_first()
            .expect("N >= 4 gives at least two windows");
        let (&(top, top_bits), interior) = rest
            .split_last()
            .expect("N >= 4 gives at least two windows");

        let mut prefix = first.select(dr, first_bits)?;
        // The offset bound proves every interior x-difference nonzero.
        let mut bank = NonzeroBank::new_unchecked();
        for &(window, window_bits) in interior {
            let entry = window.select(dr, window_bits)?;
            prefix = prefix.add_incomplete(dr, &entry, &mut bank)?;
        }
        Ok((prefix, top.select(dr, top_bits)?))
    }

    /// Adds two points that may be equal. Opposite points, whose sum is the
    /// identity, have no satisfying assignment, and witness generation fails
    /// for them.
    ///
    /// This costs nine gates and nineteen constraints.
    fn add_or_double<'dr, D: Driver<'dr, F = C::Base>>(
        dr: &mut D,
        left: &Point<'dr, D, C>,
        right: &Point<'dr, D, C>,
    ) -> Result<Point<'dr, D, C>> {
        let dx = right.x.sub(dr, &left.x);
        let dy = right.y.sub(dr, &left.y);

        // Points with equal x-coordinates are equal or opposite. `same` is one
        // exactly when the x-coordinates agree, and requiring `same * dy = 0`
        // leaves it one only for equal points.
        let same = dx.is_zero(dr, &mut ())?.element();
        same.mul(dr, &dy)?.enforce_zero(dr)?;

        // The slope is the chord's `dy / dx` for distinct points and the
        // tangent's `3x^2 / 2y` for equal ones. The denominator is `dx` where
        // `same` is zero, which `is_zero` proves nonzero, and `2y` where it is
        // one, nonzero because a `Point` coordinate is. Opposite points would
        // make it `y + (-y) = 0`, so their witness generation fails here. The
        // constraint above is what excludes them, since the numerator also
        // vanishes where `3x^2 = 2y`.
        let x_squared = left.x.square(dr)?;
        let tangent = same.mul(dr, &x_squared)?;
        let numerator = dy.add_coeff(dr, &tangent, Coeff::Arbitrary(C::Base::from(3)));
        let y_sum = left.y.add(dr, &right.y);
        let doubled_y = same.mul(dr, &y_sum)?;
        let denominator = dx.add(dr, &doubled_y);
        let slope = numerator.divide(dr, &Nonzero::new_unchecked(denominator))?;

        // Chord and tangent share the formulas for the sum.
        let x = slope.square(dr)?.sub(dr, &left.x).sub(dr, &right.x);
        let left_x_minus_x = left.x.sub(dr, &x);
        let y = slope.mul(dr, &left_x_minus_x)?.sub(dr, &left.y);

        // The sum of two equal, or of two neither equal nor opposite, finite
        // points is finite.
        Ok(Point::new_unchecked(
            Nonzero::new_unchecked(x),
            Nonzero::new_unchecked(y),
        ))
    }
}

#[cfg(test)]
mod tests {
    use alloc::{format, string::String};

    use ragu_core::{
        maybe::Maybe,
        pasta::{EpAffine, Fp, Fq},
    };
    use ragu_testing::patcher::{
        Event, Recorder, constraints_hold, repair, underconstrained_derived,
    };
    use udon::curve::{Affine, Projective};

    use super::*;
    use crate::{Simulator, decompose};

    fn allocate<'dr, D: Driver<'dr>, const N: usize>(
        dr: &mut D,
        bits: [bool; N],
    ) -> Result<FixedVec<Boolean<'dr, D>, ConstLen<N>>> {
        FixedVec::try_from_fn(|i| Boolean::alloc(dr, &mut (), D::just(|| bits[i])))
    }

    /// The little-endian bits of `scalar`, zero above bit 63.
    fn bits_of<const N: usize>(scalar: u64) -> [bool; N] {
        array::from_fn(|i| i < 64 && scalar >> i & 1 == 1)
    }

    /// The `(a, b, c)` wires of the gate `nth` from the end of `events`.
    fn gate_from_end(events: &[Event<Fp>], nth: usize) -> (usize, usize, usize) {
        events
            .iter()
            .rev()
            .filter_map(|event| match event {
                Event::Gate { a, b, c } => Some((*a, *b, *c)),
                _ => None,
            })
            .nth(nth)
            .unwrap()
    }

    #[test]
    fn multiply_decomposed_and_short_scalars() -> Result<()> {
        let base = EpAffine::generator();
        let table = FixedBase::<_, 254>::new(base, EpAffine::identity())?;
        let short = FixedBase::<_, 4>::new(base, EpAffine::identity())?;
        // Set both top bits so the two-bit selector's product contributes.
        let scalar = 17;
        let high = Fp::from(3) * Fp::from(2).pow_u64(252);
        let expected =
            (base * (Fq::from(3) * Fq::from(2).pow_u64(252) + Fq::from(scalar))).to_affine();
        Simulator::simulate(high + Fp::from(scalar), |dr, witness| {
            let element = Element::alloc(dr, &mut (), witness)?;
            let bits = FixedVec::try_from(decompose(dr, &mut (), &element)?)?;
            dr.reset();
            assert_eq!(table.mul(dr, &bits)?.value().take(), expected);
            assert_eq!(dr.num_gates(), 427);
            assert_eq!(dr.num_constraints(), 855);

            let bits = allocate(dr, [true, true, false, true])?;
            dr.reset();
            assert_eq!(
                short.mul(dr, &bits)?.value().take(),
                (base * Fq::from(11)).to_affine()
            );
            assert_eq!(dr.num_gates(), 11);
            Ok(())
        })?;
        Ok(())
    }

    #[test]
    fn short_scalars_and_correction() -> Result<()> {
        let base = EpAffine::generator();
        let correction = -(base * Fq::from(5)).to_affine();
        let table = FixedBase::<_, 51>::new(base, correction)?;
        for scalar in [0, 1, (1 << 51) - 1] {
            Simulator::simulate((), |dr, _| {
                let bits = allocate::<_, 51>(dr, bits_of(scalar))?;
                dr.reset();
                let out = table.mul(dr, &bits)?;
                assert_eq!(
                    out.value().take(),
                    (base * Fq::from(scalar) + correction.to_projective()).to_affine()
                );
                assert_eq!(dr.num_gates(), 88);
                Ok(())
            })?;
        }
        Ok(())
    }

    #[test]
    fn full_width_scalars() -> Result<()> {
        let base = EpAffine::generator();
        let table = FixedBase::<_, 255>::new(base, EpAffine::identity())?;
        for scalar_bits in [array::from_fn(|i| i % 5 < 2), [true; 255]] {
            Simulator::simulate((), |dr, _| {
                let bits = allocate(dr, scalar_bits)?;
                let expected_scalar = scalar_bits.iter().rev().fold(Fq::ZERO, |acc, &bit| {
                    acc.double() + Fq::from(u64::from(bit))
                });
                let expected = (base * expected_scalar).to_affine();
                dr.reset();
                assert_eq!(table.mul(dr, &bits)?.value().take(), expected);
                assert_eq!(dr.num_gates(), 428);
                Ok(())
            })?;
        }
        Ok(())
    }

    /// Every scalar of four through seven bits multiplies correctly, including
    /// each table's doubling input $(10H + 4)/7$, and only an identity result
    /// fails. A correction moves that failure to the scalar it cancels.
    #[test]
    fn every_finite_result_is_provable() -> Result<()> {
        fn check<const N: usize>(correction: Fq) -> Result<()> {
            let base = EpAffine::generator();
            let correction = (base * correction).to_affine();
            let table = FixedBase::<_, N>::new(base, correction)?;
            for scalar in 0..1u64 << N {
                let expected = (base * Fq::from(scalar) + correction.to_projective()).to_affine();
                let proved = Simulator::simulate((), |dr, _| {
                    let bits = allocate(dr, bits_of(scalar))?;
                    assert_eq!(table.mul(dr, &bits)?.value().take(), expected);
                    Ok(())
                });
                assert_eq!(proved.is_ok(), !expected.is_identity(), "scalar {scalar}");
            }
            Ok(())
        }
        check::<4>(Fq::ZERO)?;
        check::<5>(Fq::ZERO)?;
        check::<6>(Fq::ZERO)?;
        check::<7>(Fq::ZERO)?;
        check::<6>(-Fq::from(9))
    }

    #[test]
    fn zero_scalar_can_join_an_addend() -> Result<()> {
        let base = EpAffine::generator();
        let table = FixedBase::<_, 6>::new(base, EpAffine::identity())?;
        assert!(matches!(
            Simulator::<Fp>::simulate((), |dr, _| {
                let bits = allocate(dr, [false; 6])?;
                table.mul(dr, &bits)?;
                Ok(())
            }),
            Err(Error::InvalidWitness(_))
        ));
        Simulator::simulate((), |dr, _| {
            let bits = allocate(dr, [false; 6])?;
            let addend = (base * Fq::from(9)).to_affine();
            let onto = Point::alloc(dr, Simulator::<Fp>::just(|| addend))?;
            dr.reset();
            assert_eq!(table.mul_and_add(dr, &bits, &onto)?.value().take(), addend);
            assert_eq!(dr.num_gates(), 22);
            assert_eq!(dr.num_constraints(), 46);
            Ok(())
        })?;
        Ok(())
    }

    /// With `onto` = $\[9\]B$ and two windows, the prefix is $\[l + 2\]B$ and
    /// the top entry $\[8h - 2\]B$. Scalar 7 makes the prefix equal `onto`,
    /// and 19 makes their sum equal the top entry; both double. Only an
    /// identity sum fails.
    #[test]
    fn mul_and_add_doubles_equal_points() -> Result<()> {
        let base = EpAffine::generator();
        let table = FixedBase::<_, 6>::new(base, EpAffine::identity())?;
        let add = |scalar: u64, addend: EpAffine| {
            Simulator::simulate((), |dr, _| {
                let bits = allocate(dr, bits_of(scalar))?;
                let onto = Point::alloc(dr, Simulator::<Fp>::just(|| addend))?;
                let expected = (base * Fq::from(scalar) + addend.to_projective()).to_affine();
                assert_eq!(
                    table.mul_and_add(dr, &bits, &onto)?.value().take(),
                    expected
                );
                Ok(())
            })
        };
        let addend = (base * Fq::from(9)).to_affine();
        for scalar in 0..64 {
            add(scalar, addend)?;
        }
        // Scalar 5 has prefix [7]B, which an addend of [-7]B cancels.
        assert!(add(5, -(base * Fq::from(7)).to_affine()).is_err());
        Ok(())
    }

    /// `N` and the table fix the emitted constraints; the scalar never changes
    /// them, for each top-window width, through both entry points, and on
    /// either side of each doubling.
    #[test]
    fn constraints_do_not_depend_on_the_scalar() -> Result<()> {
        fn events<const N: usize>(
            table: &FixedBase<EpAffine, N>,
            scalar: u64,
            onto: Option<EpAffine>,
        ) -> Result<String> {
            let mut dr = Recorder::<Fp>::new();
            let bits = allocate(&mut dr, bits_of(scalar))?;
            match onto {
                Some(onto) => {
                    let onto = Point::alloc(&mut dr, Recorder::<Fp>::just(|| onto))?;
                    table.mul_and_add(&mut dr, &bits, &onto)?;
                }
                None => {
                    table.mul(&mut dr, &bits)?;
                }
            }
            Ok(format!("{:?}", dr.events))
        }
        fn assert_same<const K: usize>(traces: [Result<String>; K]) -> Result<()> {
            let traces = traces.into_iter().collect::<Result<Vec<_>>>()?;
            assert!(traces.windows(2).all(|pair| pair[0] == pair[1]));
            Ok(())
        }

        let base = EpAffine::generator();
        let identity = EpAffine::identity();
        // Each set gives every bit both values and includes the table's
        // doubling input, 12 for two windows.
        let one_bit_top = FixedBase::<_, 4>::new(base, identity)?;
        assert_same([1, 6, 12, 15].map(|scalar| events(&one_bit_top, scalar, None)))?;
        let two_bit_top = FixedBase::<_, 5>::new(base, identity)?;
        assert_same([1, 6, 12, 31].map(|scalar| events(&two_bit_top, scalar, None)))?;
        let three_bit_top = FixedBase::<_, 6>::new(base, identity)?;
        assert_same([1, 12, 22, 63].map(|scalar| events(&three_bit_top, scalar, None)))?;
        // With `onto` = [9]B, scalars 7 and 19 double in the first and second
        // additions.
        let onto = (base * Fq::from(9)).to_affine();
        assert_same([0, 7, 13, 19, 50].map(|scalar| events(&three_bit_top, scalar, Some(onto))))?;
        // Under a correction of [-5]B, the doubling input is (10H + 4)/7 - 5.
        let corrected = FixedBase::<_, 51>::new(base, -(base * Fq::from(5)).to_affine())?;
        assert_same(
            [1, 0x2_AAAA_AAAA_AAAA, 402_107_109_586_647, (1 << 51) - 1]
                .map(|scalar| events(&corrected, scalar, None)),
        )?;
        Ok(())
    }

    #[test]
    fn rejects_invalid_tables() {
        let base = EpAffine::generator();
        for (base, correction) in [
            (EpAffine::identity(), EpAffine::identity()),
            // Top digit zero selects the identity.
            (base, (base * Fq::from(2)).to_affine()),
            // Top digits d and 7 - d have equal x, so x[7] = 0.
            (base, -(base * Fq::from(26)).to_affine()),
        ] {
            assert!(matches!(
                FixedBase::<_, 6>::new(base, correction),
                Err(Error::Initialization(_))
            ));
        }
    }

    /// Scalar 12 is the doubling input for two windows: the prefix and top
    /// entry are both $\[6\]B$. Incomplete addition reads `0/0` there and
    /// accepts any slope; the final addition pins the tangent's.
    #[test]
    fn final_addition_pins_the_doubling_slope() -> Result<()> {
        let table = FixedBase::<_, 6>::new(EpAffine::generator(), EpAffine::identity())?;
        for complete in [false, true] {
            let mut dr = Recorder::<Fp>::new();
            let bits = allocate(&mut dr, bits_of(1))?;
            if complete {
                table.mul(&mut dr, &bits)?;
            } else {
                let (prefix, top) = table.prefix_and_top(&mut dr, &bits)?;
                prefix.add_incomplete(&mut dr, &top, &mut NonzeroBank::new_unchecked())?;
            }
            assert!(constraints_hold(&dr.events, &dr.values));

            // Switch the scalar to 12 and pin the slope, the first wire of the
            // third gate from the end, to zero.
            let (slope, _, _) = gate_from_end(&dr.events, 2);
            let mut fixed: Vec<_> = bits.iter().map(|bit| *bit.wire()).collect();
            for (i, &wire) in fixed.iter().enumerate() {
                dr.values[wire] = Fp::from(u64::from(12 & (1 << i) != 0));
            }
            dr.values[slope] = Fp::ZERO;
            fixed.push(slope);
            repair(&dr.events, &mut dr.values, &fixed);
            assert_eq!(constraints_hold(&dr.events, &dr.values), !complete);
        }
        Ok(())
    }

    /// Scalar zero makes the prefix and top entry opposite, with the identity
    /// as their sum. No assignment completes the final addition there.
    #[test]
    fn final_addition_rejects_opposite_points() -> Result<()> {
        let table = FixedBase::<_, 6>::new(EpAffine::generator(), EpAffine::identity())?;
        let mut dr = Recorder::<Fp>::new();
        let bits = allocate(&mut dr, bits_of(1))?;
        table.mul(&mut dr, &bits)?;
        let fixed: Vec<_> = bits.iter().map(|bit| *bit.wire()).collect();
        for &wire in &fixed {
            dr.values[wire] = Fp::ZERO;
        }
        repair(&dr.events, &mut dr.values, &fixed);
        assert!(!constraints_hold(&dr.events, &dr.values));
        Ok(())
    }

    /// Given the scalar's bits, the constraints pin every other wire, for a
    /// chord and for the doubling input 12. A doubling leaves only the unused
    /// inverse hint inside `is_zero` free.
    #[test]
    fn bits_pin_every_wire() -> Result<()> {
        let table = FixedBase::<_, 6>::new(EpAffine::generator(), EpAffine::identity())?;
        for scalar in [1, 12] {
            let mut dr = Recorder::<Fp>::new();
            let bits = allocate(&mut dr, bits_of(scalar))?;
            table.mul(&mut dr, &bits)?;
            let free: Vec<_> = bits.iter().map(|bit| *bit.wire()).collect();
            // `is_zero`'s second gate, the eighth from the end, holds the hint.
            let (_, inverse, _) = gate_from_end(&dr.events, 7);
            let expected = if scalar == 12 {
                alloc::vec![inverse]
            } else {
                Vec::new()
            };
            assert_eq!(
                underconstrained_derived(&dr.events, &dr.values, &free),
                expected
            );
        }
        Ok(())
    }
}

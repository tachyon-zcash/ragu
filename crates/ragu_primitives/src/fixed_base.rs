//! Unsigned radix-8 fixed-base scalar multiplication with a $+2$ offset.
//!
//! Interior window $i$ selects $\[(k_i + 2) 8^i\]B$; the top selects
//! $\[k_{W-1} 8^{W-1} - o\]B$, where $o = \sum_{i < W-1} 2 \cdot 8^i$.
//! Thus the offsets cancel, giving the binary value of the selected bits.
//!
//! For the prefix scalar before interior window $j$, every Boolean assignment
//! satisfies $0 < A_j \le 9(8^j - 1)/7 < 2 \cdot 8^j \le D_j$. Moreover,
//! $A_j + D_j \le 9(8^{j+1} - 1)/7 < q$: the width bound
//! $3W - 2 \le \mathtt{Scalar::CAPACITY}$ places this below the prime group order $q$.
//! Consequently $\[A_j\]B \ne \pm\[D_j\]B$, so interior additions have distinct
//! x coordinates without nonzero constraints. This uses the prime-order group
//! contract of [`EndomorphismAffine`] and the curve assumptions of [`Point`].
//!
//! Each window's two multiplication gates select its coordinates exactly on
//! all eight Boolean assignments, checked at table construction. Therefore its
//! affine point and nonzero-coordinate contracts follow from the fixed entries.
//! The variable-point join and top addition instead enforce nonzero x
//! differences; their exceptional cases are unsatisfiable.

use alloc::vec::Vec;
use core::array;

use ragu_core::{Error, Result, drivers::Driver, maybe::Maybe};
use udon::{
    curve::{EndomorphismAffine, Projective},
    field::Field,
};

use crate::{
    Boolean, Element, GadgetExt, Nonzero, NonzeroBank, Point, multiadd, multipack,
    vec::{ConstLen, FixedVec},
};

/// Two-gate selection of eight finite points by three little-endian bits.
///
/// For multilinear coordinate coefficients, $q = x_{012} y - y_{012} x$
/// has no cubic term. Its quadratic part factors as
/// $p = (b_0 + \beta b_2)(q_{01} b_1 + q_{02} b_2)$. A second product
/// $c = b_2 (\lambda_0 b_0 + \lambda_1 b_1 + \rho p)$ supplies the remaining
/// terms, making both coordinates affine in $(1, b_0, b_1, b_2, p, c)$.
struct Window<F: Field> {
    left: [F; 3],
    right: [F; 3],
    inner: [F; 3],
    x: [F; 6],
    y: [F; 6],
}

impl<F: Field> Window<F> {
    fn monomials(mut values: [F; 8]) -> [F; 8] {
        for dimension in 0..3 {
            for index in 0..8 {
                if index & (1 << dimension) != 0 {
                    values[index] -= values[index ^ (1 << dimension)];
                }
            }
        }
        values
    }

    fn new(entries: &[(F, F); 8]) -> Result<Self> {
        let degenerate = || Error::Initialization("degenerate fixed-base window".into());
        let x = Self::monomials(entries.map(|entry| entry.0));
        let y = Self::monomials(entries.map(|entry| entry.1));
        let [q01, q02, q12] = [3, 5, 6].map(|mask| x[7] * y[mask] - y[7] * x[mask]);
        let inverse = q01.invert().ok_or_else(degenerate)?;
        let shift = x[3] * inverse;
        let rho = x[7] * inverse;
        let left = [F::ONE, F::ZERO, q12 * inverse];
        let right = [F::ZERO, q01, q02];
        let inner = [x[5] - (shift + rho) * q02, x[6] - (shift + rho) * q12, rho];

        let linear = |coefficients: &[F; 3], terms: [F; 3]| {
            coefficients
                .iter()
                .zip(terms)
                .fold(F::ZERO, |sum, (coefficient, term)| {
                    sum + *coefficient * term
                })
        };
        let basis: [[F; 6]; 8] = array::from_fn(|index| {
            let bits = array::from_fn(|position| F::from(u64::from(index & (1 << position) != 0)));
            let quadratic = linear(&left, bits) * linear(&right, bits);
            let cubic = bits[2] * linear(&inner, [bits[0], bits[1], quadratic]);
            [F::ONE, bits[0], bits[1], bits[2], quadratic, cubic]
        });
        let quadratic = Self::monomials(basis.map(|row| row[4]));
        let cubic = Self::monomials(basis.map(|row| row[5]));
        let cubic_inverse = cubic[7].invert().ok_or_else(degenerate)?;
        let quadratic_inverse = quadratic[3].invert().ok_or_else(degenerate)?;
        let solve = |coordinate: [F; 8]| {
            let gamma = coordinate[7] * cubic_inverse;
            let alpha = (coordinate[3] - gamma * cubic[3]) * quadratic_inverse;
            let rest =
                |mask: usize| coordinate[mask] - alpha * quadratic[mask] - gamma * cubic[mask];
            [rest(0), rest(1), rest(2), rest(4), alpha, gamma]
        };
        let window = Self {
            left,
            right,
            inner,
            x: solve(x),
            y: solve(y),
        };
        for (row, entry) in basis.iter().zip(entries) {
            let evaluate = |coefficients: &[F; 6]| {
                coefficients
                    .iter()
                    .zip(row)
                    .fold(F::ZERO, |sum, (coefficient, term)| {
                        sum + *coefficient * *term
                    })
            };
            if (evaluate(&window.x), evaluate(&window.y)) != *entry {
                return Err(degenerate());
            }
        }
        Ok(window)
    }

    /// Selects an entry in two, one, or zero gates for three, two, or one bits.
    /// Requires between one and three little-endian bits.
    fn select<'dr, D: Driver<'dr, F = F>, C: EndomorphismAffine<Base = F>>(
        &self,
        dr: &mut D,
        bits: &[Boolean<'dr, D>],
    ) -> Result<Point<'dr, D, C>> {
        let elements: [_; 3] = array::from_fn(|index| {
            bits.get(index)
                .map_or_else(|| Element::zero(dr), Boolean::element)
        });
        let quadratic = if bits.len() >= 2 {
            let left = multiadd(dr, &elements[..bits.len()], &self.left[..bits.len()]);
            let right = multiadd(dr, &elements[..bits.len()], &self.right[..bits.len()]);
            left.mul(dr, &right)?
        } else {
            Element::zero(dr)
        };
        let cubic = if bits.len() == 3 {
            let inner = multiadd(
                dr,
                &[elements[0].clone(), elements[1].clone(), quadratic.clone()],
                &self.inner,
            );
            elements[2].mul(dr, &inner)?
        } else {
            Element::zero(dr)
        };
        let [low, middle, high] = elements;
        let basis = [Element::one(), low, middle, high, quadratic, cubic];
        // Missing high bits are zero. Construction checked these assignments too,
        // so the same table derives both coordinate contracts for short windows.
        Ok(Point::new_unchecked(
            Nonzero::new_unchecked(multiadd(dr, &basis, &self.x)),
            Nonzero::new_unchecked(multiadd(dr, &basis, &self.y)),
        ))
    }
}

/// Native constants for a radix-8 multiplication by a fixed, nonidentity base.
///
/// `W` must be at least two and satisfy $3W - 2 \le \mathtt{C::Scalar::CAPACITY}$.
/// The table supports the same curves as [`Point`].
pub struct FixedBaseTable<C: EndomorphismAffine, const W: usize> {
    windows: [Window<C::Base>; W],
}

impl<C: EndomorphismAffine, const W: usize> FixedBaseTable<C, W> {
    /// Constructs the table for `base`, without emitting circuit constraints.
    ///
    /// # Errors
    ///
    /// Returns a setup error if `base` is the identity, a window contains the
    /// identity, or a window does not admit the two-gate coordinate selection.
    pub fn new(base: C) -> Result<Self> {
        const {
            assert!(W >= 2);
            assert!(3 * W - 2 <= C::Scalar::CAPACITY as usize);
        }
        if base.is_identity() {
            return Err(Error::Initialization(
                "fixed base must be nonidentity".into(),
            ));
        }
        let mut power = C::Scalar::ONE;
        let mut offset = C::Scalar::ZERO;
        let mut windows = array::from_fn(|_| None);
        for (index, window) in windows.iter_mut().enumerate() {
            let mut entries = [(C::Base::ZERO, C::Base::ZERO); 8];
            for (digit, entry) in entries.iter_mut().enumerate() {
                let scalar = if index == W - 1 {
                    C::Scalar::from(digit as u64) * power - offset
                } else {
                    C::Scalar::from(digit as u64 + 2) * power
                };
                *entry = (base * scalar).to_affine().coordinates().ok_or_else(|| {
                    Error::Initialization("fixed-base window contains the identity".into())
                })?;
            }
            *window = Some(Window::new(&entries)?);
            offset += C::Scalar::from(2) * power;
            power *= C::Scalar::from(8);
        }
        Ok(Self {
            windows: windows.map(|window| window.expect("every window was initialized")),
        })
    }

    fn prefix_and_top<'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        bits: &[Boolean<'dr, D>],
    ) -> Result<(Point<'dr, D, C>, Point<'dr, D, C>)> {
        let (low, top) = bits.split_at(3 * (W - 1));
        let mut chunks = low.chunks(3);
        let mut prefix = self.windows[0].select(dr, chunks.next().expect("W is at least two"))?;
        // The module's offset argument proves every interior x difference nonzero.
        let mut bank = NonzeroBank::new_unchecked();
        for (window, bits) in self.windows[1..W - 1].iter().zip(chunks) {
            let entry = window.select(dr, bits)?;
            prefix = prefix.add_incomplete(dr, &entry, &mut bank)?;
        }
        Ok((prefix, self.windows[W - 1].select(dr, top)?))
    }

    /// Costs one gate for the nonzero check plus `add_incomplete`'s three.
    fn add_checked<'dr, D: Driver<'dr, F = C::Base>>(
        dr: &mut D,
        left: &Point<'dr, D, C>,
        right: &Point<'dr, D, C>,
    ) -> Result<Point<'dr, D, C>> {
        right.x.sub(dr, &left.x).enforce_nonzero(dr)?;
        // The same x difference folded by add_incomplete was just enforced nonzero.
        left.add_incomplete(dr, right, &mut NonzeroBank::new_unchecked())
    }

    fn multiply<'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        bits: &[Boolean<'dr, D>],
        onto: Option<&Point<'dr, D, C>>,
    ) -> Result<Point<'dr, D, C>> {
        let (mut sum, top) = self.prefix_and_top(dr, bits)?;
        if let Some(onto) = onto {
            sum = Self::add_checked(dr, &sum, onto)?;
        }
        Self::add_checked(dr, &sum, &top)
    }

    /// Multiplies the base by the unsigned little-endian value of `bits`,
    /// optionally adding `onto` before the top window.
    ///
    /// With a full top window this costs $5W - 2$ gates and $10W - 4$
    /// constraints. Each omitted top bit saves one gate and two constraints.
    /// Adding `onto` costs four gates and eight constraints. Bit allocation is extra.
    /// Requires $3(W-1) < N \le 3W$: the top window holds the remaining
    /// $N - 3(W-1)$ bits. The caller owns binding the bits to other inputs;
    /// this method does not require a canonical scalar encoding.
    ///
    /// # Soundness
    ///
    /// Any satisfying assignment makes the returned point represent
    /// $\[\sum_i b_i 2^i\]B + P$, where $B$ is the base and $P$ is `onto`
    /// (or the identity when absent).
    ///
    /// # Exceptional Cases
    ///
    /// The prefix $A$ must differ from $\pm P$, and $A + P$ must differ
    /// from $\pm T$, where $T$ is the top entry. Without `onto`, $A$ must
    /// differ from $\pm T$. These requirements are enforced. In particular,
    /// without `onto`, zero modulo the group order and
    /// $k^* = 2 \cdot 8^{W-1} - 4(8^{W-1}-1)/7$ are excluded.
    /// Joining `onto` before the top permits zero when these conditions hold.
    ///
    /// # Errors
    ///
    /// Returns a witness-generation error when witness input meets an
    /// exceptional addition.
    pub fn mul_bits<'dr, D: Driver<'dr, F = C::Base>, const N: usize>(
        &self,
        dr: &mut D,
        bits: &FixedVec<Boolean<'dr, D>, ConstLen<N>>,
        onto: Option<&Point<'dr, D, C>>,
    ) -> Result<Point<'dr, D, C>> {
        const {
            // Construction already checked the window count and scalar capacity.
            assert!(3 * (W - 1) < N && N <= 3 * W);
        }
        self.multiply(dr, bits, onto)
    }

    /// Multiplies the base by the canonical integer represented by `value`,
    /// optionally adding `onto`.
    ///
    /// Decomposes into $n = \min(3W, \mathtt{C::Base::CAPACITY})$ bits, enforcing
    /// recomposition, with a short top window when needed. Requires
    /// $3W < \mathtt{C::Base::CAPACITY} + 3$. Beyond [`Self::mul_bits`], this costs
    /// $n$ gates and $2n + 1$ constraints.
    ///
    /// # Soundness
    ///
    /// Any satisfying assignment places `value` in $\[0, 2^n)$ and makes the
    /// returned point represent $\[v\]B + P$, where $v$ is `value`, $B$ is the
    /// base, and $P$ is `onto` (or the identity when absent).
    ///
    /// # Completeness
    ///
    /// Field elements in $\[2^{\mathtt{CAPACITY}}, p)$ are rejected. For narrower
    /// tables, elements at least $2^{3W}$ are also rejected. On Pasta, the
    /// full-width range exclusion has density about $2^{-129}$, as with the
    /// existing field decomposition.
    ///
    /// # Exceptional Cases
    ///
    /// A zero value without `onto` is unsatisfiable. All exceptional additions
    /// described in [`Self::mul_bits`]'s Exceptional Cases also apply.
    ///
    /// # Errors
    ///
    /// Returns a witness-generation error for exceptional additions. A checking
    /// driver returns a local-check error for an out-of-range value.
    pub fn mul_element<'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        value: &Element<'dr, D>,
        onto: Option<&Point<'dr, D, C>>,
    ) -> Result<Point<'dr, D, C>> {
        const {
            // Construction already checked the window count and scalar capacity.
            assert!(3 * W < C::Base::CAPACITY as usize + 3);
        }
        let n = core::cmp::min(3 * W, C::Base::CAPACITY as usize);
        let le_bits = value.value().map(|value| value.to_le_bits());
        let bits = (0..n)
            .map(|index| {
                Boolean::alloc(
                    dr,
                    &mut (),
                    le_bits.as_ref().map(|bits| bits.as_ref()[index]),
                )
            })
            .collect::<Result<Vec<_>>>()?;
        // At most CAPACITY bits: recomposition cannot wrap modulo the field.
        multipack(dr, &bits)?[0].enforce_equal(dr, value)?;
        self.multiply(dr, &bits, onto)
    }
}

#[cfg(test)]
mod tests {
    use alloc::{format, vec::Vec};

    use udon::curve::{Affine, EndomorphismProjective};

    use super::*;

    type F = ragu_core::pasta::Fp;
    type S = ragu_core::pasta::Fq;
    type C = ragu_core::pasta::EpAffine;
    type Simulator = crate::Simulator<F>;

    fn scalar(bits: &[bool]) -> S {
        bits.iter()
            .rev()
            .fold(S::ZERO, |acc, bit| acc.double() + S::from(u64::from(*bit)))
    }

    fn alloc_bits<'dr, const N: usize>(
        dr: &mut Simulator,
        bits: [bool; N],
    ) -> Result<FixedVec<Boolean<'dr, Simulator>, ConstLen<N>>> {
        FixedVec::try_from_fn(|index| Boolean::alloc(dr, &mut (), Simulator::just(|| bits[index])))
    }

    fn multiply<const W: usize, const N: usize>(
        table: &FixedBaseTable<C, W>,
        bits: [bool; N],
        onto: Option<C>,
    ) -> Result<C> {
        let mut output = C::identity();
        Simulator::simulate((), |dr, _| {
            let bits = alloc_bits(dr, bits)?;
            let onto = onto.map(|onto| Point::constant(dr, onto)).transpose()?;
            output = table.mul_bits(dr, &bits, onto.as_ref())?.value().take();
            Ok(())
        })?;
        Ok(output)
    }

    #[test]
    fn multiplication_computes_the_binary_value() -> Result<()> {
        let mut patterns = Vec::from([[false; 255], [true; 255]]);
        patterns.extend((0..255).map(|bit| array::from_fn(|index| index == bit)));
        patterns
            .extend((0..8).map(|digit| array::from_fn(|index| digit & (1 << (index % 3)) != 0)));
        patterns.push(array::from_fn(|index| {
            (-S::ONE).to_le_bits().as_ref()[index]
        }));
        patterns.push(array::from_fn(|index| {
            (-F::ONE).to_le_bits().as_ref()[index]
        }));
        for base in [C::generator(), (C::generator() * S::from(7)).to_affine()] {
            let table = FixedBaseTable::<_, 85>::new(base)?;
            for bits in &patterns {
                let expected = (base * scalar(bits)).to_affine();
                let result = multiply(&table, *bits, None);
                if expected.is_identity() {
                    assert!(result.is_err());
                } else {
                    assert_eq!(result?, expected);
                }
            }
            for bits in [
                [true; 254],
                array::from_fn(|index| index % 2 == 0),
                array::from_fn(|index| index == 253),
                array::from_fn(|index| index == 0),
            ] {
                assert_eq!(
                    multiply(&table, bits, None)?,
                    (base * scalar(&bits)).to_affine()
                );
            }
            for bits in [
                [true; 253],
                array::from_fn(|index| index % 2 == 0),
                array::from_fn(|index| index == 252),
                array::from_fn(|index| index == 0),
            ] {
                assert_eq!(
                    multiply(&table, bits, None)?,
                    (base * scalar(&bits)).to_affine()
                );
            }
        }
        // Smallest permitted table exercises the empty interior-add loop.
        let base = C::generator();
        assert_eq!(
            multiply(&FixedBaseTable::<_, 2>::new(base)?, [true; 6], None)?,
            (base * S::from(63)).to_affine()
        );
        Ok(())
    }

    #[test]
    fn exceptional_additions_have_no_satisfying_inverse() -> Result<()> {
        let assert_no_inverse = |dr: &mut Simulator, difference: &Element<'_, Simulator>| {
            assert_eq!(*difference.value().take(), F::ZERO);
            for advice in [F::ZERO, F::ONE, -F::ONE, F::from(7)] {
                let rejection = difference
                    .enforce_invertible_with(dr, Simulator::just(|| advice))
                    .err();
                assert!(
                    rejection.is_some_and(|error| format!("{error}").contains("gate check failed"))
                );
            }
        };
        let power = (0..84).fold(S::ONE, |acc, _| acc * S::from(8));
        let interior = (0..84).fold(S::ZERO, |acc, _| acc * S::from(8) + S::ONE);
        let k_star = power.double() - S::from(4) * interior;
        let doubling_bits = array::from_fn(|index| k_star.to_le_bits().as_ref()[index]);
        for base in [C::generator(), (C::generator() * S::from(7)).to_affine()] {
            let table = FixedBaseTable::<_, 85>::new(base)?;
            for bits in [[false; 255], doubling_bits] {
                assert!(multiply(&table, bits, None).is_err());
                Simulator::simulate((), |dr, _| {
                    let bits = alloc_bits(dr, bits)?;
                    let (prefix, top) = table.prefix_and_top(dr, &bits)?;
                    let difference = top.x.sub(dr, &prefix.x);
                    assert_no_inverse(dr, &difference);
                    Ok(())
                })?;
            }
            let onto = base.to_projective().endomorphism().to_affine();
            assert_eq!(multiply(&table, [false; 255], Some(onto))?, onto);
            let offset = interior.double();
            let prefix = (base * offset).to_affine();
            // A = +/-onto: the join's nonzero check is unsatisfiable.
            for onto in [prefix, -prefix] {
                assert!(multiply(&table, [false; 255], Some(onto)).is_err());
                Simulator::simulate((), |dr, _| {
                    let bits = alloc_bits(dr, [false; 255])?;
                    let (prefix, _) = table.prefix_and_top(dr, &bits)?;
                    let onto = Point::constant(dr, onto)?;
                    let difference = onto.x.sub(dr, &prefix.x);
                    assert_no_inverse(dr, &difference);
                    Ok(())
                })?;
            }
            // For top digit one, arrange A + onto = +/-top after a valid join.
            let mut bits = [false; 255];
            bits[252] = true;
            let top = base * (power - offset);
            for target in [top, -top] {
                let onto = (target - prefix.to_projective()).to_affine();
                assert!(multiply(&table, bits, Some(onto)).is_err());
                Simulator::simulate((), |dr, _| {
                    let bits = alloc_bits(dr, bits)?;
                    let (prefix, top) = table.prefix_and_top(dr, &bits)?;
                    let onto = Point::constant(dr, onto)?;
                    let sum = FixedBaseTable::<C, 85>::add_checked(dr, &prefix, &onto)?;
                    let difference = top.x.sub(dr, &sum.x);
                    assert_no_inverse(dr, &difference);
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    #[test]
    fn element_range_is_enforced() -> Result<()> {
        let base = C::generator();
        let table = FixedBaseTable::<_, 17>::new(base)?;
        for (value, valid) in [
            (F::ZERO, true),
            (F::ONE, true),
            (F::from((1u64 << 51) - 1), true),
            (F::from(1u64 << 51), false),
            (-F::ONE, false),
        ] {
            let result = Simulator::simulate(value, |dr, witness| {
                let value = Element::alloc(dr, &mut (), witness)?;
                let onto = base.to_projective().endomorphism().to_affine();
                let point = Point::constant(dr, onto)?;
                let result = table.mul_element(dr, &value, Some(&point))?;
                let expected = base * scalar(value.value().take().to_le_bits().as_ref())
                    + onto.to_projective();
                assert_eq!(result.value().take(), expected.to_affine());
                Ok(())
            });
            assert_eq!(result.is_ok(), valid);
        }
        let table = FixedBaseTable::<_, 85>::new(base)?;
        let maximum = F::from(2).pow_u64(254) - F::ONE;
        for (value, valid) in [(maximum, true), (-F::ONE, false), (maximum + F::ONE, false)] {
            let result = Simulator::simulate(value, |dr, witness| {
                let value = Element::alloc(dr, &mut (), witness)?;
                let result = table.mul_element(dr, &value, None)?;
                let expected = base * scalar(value.value().take().to_le_bits().as_ref());
                assert_eq!(result.value().take(), expected.to_affine());
                Ok(())
            });
            assert_eq!(result.is_ok(), valid);
        }
        Ok(())
    }

    #[test]
    fn gate_and_constraint_counts() -> Result<()> {
        let base = C::generator();
        let table = FixedBaseTable::<_, 85>::new(base)?;
        for with_onto in [false, true] {
            let sim = Simulator::simulate((), |dr, _| {
                let mut bits = [false; 255];
                bits[0] = true;
                let bits = alloc_bits(dr, bits)?;
                let onto = if with_onto {
                    Some(Point::constant(
                        dr,
                        base.to_projective().endomorphism().to_affine(),
                    )?)
                } else {
                    None
                };
                dr.reset();
                table.mul_bits(dr, &bits, onto.as_ref())?;
                Ok(())
            })?;
            assert_eq!(sim.num_gates(), if with_onto { 427 } else { 423 });
            assert_eq!(sim.num_constraints(), if with_onto { 854 } else { 846 });
            let sim = Simulator::simulate((), |dr, _| {
                let bits = alloc_bits(dr, [true; 254])?;
                let onto = if with_onto {
                    Some(Point::constant(
                        dr,
                        base.to_projective().endomorphism().to_affine(),
                    )?)
                } else {
                    None
                };
                dr.reset();
                table.mul_bits(dr, &bits, onto.as_ref())?;
                Ok(())
            })?;
            assert_eq!(sim.num_gates(), if with_onto { 426 } else { 422 });
            assert_eq!(sim.num_constraints(), if with_onto { 852 } else { 844 });
        }
        Ok(())
    }

    #[test]
    fn construction_rejects_identity_and_degenerate_windows() {
        assert!(FixedBaseTable::<C, 85>::new(C::identity()).is_err());
        assert!(Window::<F>::new(&[(F::ZERO, F::ZERO); 8]).is_err());
    }
}

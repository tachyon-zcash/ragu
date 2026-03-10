use ff::Field;

use core::ops::{Add, Mul};

/// Represents a field element (typically a coefficient) that may have a special
/// value. By representing these cases explicitly, `Coeff` maintains context
/// about field elements that can be leveraged to optimize arithmetic operations
/// (like avoiding unnecessary field multiplications) and improve the efficiency
/// of group arithmetic.
#[derive(Copy, Clone, Debug)]
pub enum Coeff<F: Field> {
    /// Represents `F::ZERO`.
    Zero,
    /// Represents `F::ONE`.
    One,
    /// Represents $2$.
    Two,
    /// Represents `-F::ONE`.
    NegativeOne,
    /// Represents an arbitrary field element.
    Arbitrary(F),
    /// Represents the negation of an arbitrary field element.
    NegativeArbitrary(F),
}

impl<F: Field> Coeff<F> {
    /// Returns `true` if this coefficient represents zero.
    pub fn is_zero(&self) -> bool {
        match self {
            Coeff::Zero => true,
            Coeff::Arbitrary(v) | Coeff::NegativeArbitrary(v) => v.is_zero().into(),
            _ => false,
        }
    }

    /// Compute the actual field element value of this coefficient.
    pub fn value(&self) -> F {
        match self {
            Coeff::Zero => F::ZERO,
            Coeff::One => F::ONE,
            Coeff::Two => F::ONE.double(),
            Coeff::NegativeOne => -F::ONE,
            Coeff::Arbitrary(value) => *value,
            Coeff::NegativeArbitrary(value) => -*value,
        }
    }
}

impl<F: Field> From<F> for Coeff<F> {
    fn from(value: F) -> Self {
        Coeff::Arbitrary(value)
    }
}

impl<F: Field> Mul for Coeff<F> {
    type Output = Coeff<F>;

    fn mul(self, other: Self) -> Self::Output {
        match (self, other) {
            (Coeff::Zero, _) | (_, Coeff::Zero) => Coeff::Zero,
            (Coeff::One, other) | (other, Coeff::One) => other,
            (Coeff::Two, a) | (a, Coeff::Two) => Coeff::Arbitrary(a.value().double()),
            (Coeff::NegativeOne, Coeff::NegativeOne) => Coeff::One,
            (Coeff::NegativeOne, Coeff::Arbitrary(a))
            | (Coeff::Arbitrary(a), Coeff::NegativeOne) => Coeff::NegativeArbitrary(a),
            (Coeff::NegativeOne, Coeff::NegativeArbitrary(a))
            | (Coeff::NegativeArbitrary(a), Coeff::NegativeOne) => Coeff::Arbitrary(a),
            (Coeff::Arbitrary(a), Coeff::Arbitrary(b))
            | (Coeff::NegativeArbitrary(a), Coeff::NegativeArbitrary(b)) => Coeff::Arbitrary(a * b),
            (Coeff::Arbitrary(a), Coeff::NegativeArbitrary(b))
            | (Coeff::NegativeArbitrary(b), Coeff::Arbitrary(a)) => Coeff::NegativeArbitrary(a * b),
        }
    }
}

impl<F: Field> Add for Coeff<F> {
    type Output = Coeff<F>;

    fn add(self, other: Self) -> Self::Output {
        match (self, other) {
            // Zero (additive identity)
            (Coeff::Zero, other) | (other, Coeff::Zero) => other,

            // One + One
            (Coeff::One, Coeff::One) => Coeff::Two,
            (Coeff::One, Coeff::NegativeOne) | (Coeff::NegativeOne, Coeff::One) => Coeff::Zero,
            (Coeff::NegativeOne, Coeff::NegativeOne) => Coeff::Arbitrary(-F::ONE.double()),

            // Two
            (Coeff::Two, Coeff::NegativeOne) | (Coeff::NegativeOne, Coeff::Two) => Coeff::One,
            (Coeff::Two, a) | (a, Coeff::Two) => Coeff::Arbitrary(a.value() + F::ONE.double()),

            // One + Arbitrary
            (Coeff::One, Coeff::Arbitrary(a)) | (Coeff::Arbitrary(a), Coeff::One) => {
                Coeff::Arbitrary(a + F::ONE)
            }
            (Coeff::NegativeOne, Coeff::Arbitrary(a))
            | (Coeff::Arbitrary(a), Coeff::NegativeOne) => Coeff::Arbitrary(a - F::ONE),

            // One + NegativeArbitrary
            (Coeff::One, Coeff::NegativeArbitrary(a))
            | (Coeff::NegativeArbitrary(a), Coeff::One) => Coeff::Arbitrary(F::ONE - a),
            (Coeff::NegativeOne, Coeff::NegativeArbitrary(a))
            | (Coeff::NegativeArbitrary(a), Coeff::NegativeOne) => {
                Coeff::NegativeArbitrary(F::ONE + a)
            }

            // Arbitrary + Arbitrary
            (Coeff::Arbitrary(a), Coeff::Arbitrary(b)) => Coeff::Arbitrary(a + b),
            (Coeff::NegativeArbitrary(a), Coeff::NegativeArbitrary(b)) => {
                Coeff::NegativeArbitrary(a + b)
            }
            (Coeff::Arbitrary(a), Coeff::NegativeArbitrary(b))
            | (Coeff::NegativeArbitrary(b), Coeff::Arbitrary(a)) => Coeff::Arbitrary(a - b),
        }
    }
}

#[cfg(test)]
mod proptests {
    use pasta_curves::Fp as F;
    use proptest::prelude::*;
    use ragu_testing::strategies;

    proptest! {
        #[test]
        fn proptest_coeff_mul(coeff1 in strategies::coeff::<F>(), coeff2 in strategies::coeff::<F>()) {
            let a = coeff1 * coeff2;
            let b = coeff2 * coeff1;
            prop_assert_eq!(a.value(), b.value());
            prop_assert_eq!(a.value(), coeff1.value() * coeff2.value());
        }

        #[test]
        fn proptest_coeff_add(coeff1 in strategies::coeff::<F>(), coeff2 in strategies::coeff::<F>()) {
            let a = coeff1 + coeff2;
            let b = coeff2 + coeff1;
            prop_assert_eq!(a.value(), b.value());
            prop_assert_eq!(a.value(), coeff1.value() + coeff2.value());
        }

        #[test]
        fn proptest_coeff_is_zero(coeff in strategies::coeff::<F>()) {
            use ff::Field;
            prop_assert_eq!(coeff.is_zero(), bool::from(coeff.value().is_zero()));
        }
    }
}

use core::fmt;

use crate::ff::Field;

/// A field that can accumulate products before reducing to a canonical element.
///
/// Implementations may defer reduction across many products for efficiency; call
/// [`reduce`](DeferredField::reduce) to obtain the canonical field element.
pub trait DeferredField: Field {
    /// The accumulator used for unreduced or eagerly-reduced products.
    type Accumulator: Copy + Clone + fmt::Debug + Default;

    /// Multiplies `a` by `b` and adds the product into `acc`.
    fn mul_accumulate(acc: &mut Self::Accumulator, a: &Self, b: &Self);

    /// Squares `a` and adds the product into `acc`.
    fn square_accumulate(acc: &mut Self::Accumulator, a: &Self);

    /// Reduces the accumulator to a canonical field element.
    fn reduce(acc: Self::Accumulator) -> Self;
}

// In modern dependency mode this delegates to `pasta_curves` deferred reduction.
#[cfg(feature = "modern-deps")]
impl<F> DeferredField for F
where
    F: crate::pasta_curves::deferred::DeferredField,
{
    type Accumulator = <F as crate::pasta_curves::deferred::DeferredField>::Accumulator;

    fn mul_accumulate(acc: &mut Self::Accumulator, a: &Self, b: &Self) {
        <F as crate::pasta_curves::deferred::DeferredField>::mul_accumulate(acc, a, b);
    }

    fn square_accumulate(acc: &mut Self::Accumulator, a: &Self) {
        <F as crate::pasta_curves::deferred::DeferredField>::square_accumulate(acc, a);
    }

    fn reduce(acc: Self::Accumulator) -> Self {
        <F as crate::pasta_curves::deferred::DeferredField>::reduce(acc)
    }
}

/// Eager accumulator used when legacy dependencies do not provide deferred reduction.
///
/// Must be `pub`: it is the value of [`DeferredField::Accumulator`], a public
/// associated type, even though the `deferred` module itself is private.
#[cfg(feature = "legacy-deps")]
#[derive(Clone, Copy)]
pub struct EagerAccumulator<F: Field>(F);

#[cfg(feature = "legacy-deps")]
impl<F: Field> Default for EagerAccumulator<F> {
    fn default() -> Self {
        Self(F::ZERO)
    }
}

#[cfg(feature = "legacy-deps")]
impl<F: Field> fmt::Debug for EagerAccumulator<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("EagerAccumulator").finish()
    }
}

// In legacy dependency mode this falls back to ordinary eager field arithmetic.
#[cfg(feature = "legacy-deps")]
impl<F: Field> DeferredField for F {
    type Accumulator = EagerAccumulator<F>;

    fn mul_accumulate(acc: &mut Self::Accumulator, a: &Self, b: &Self) {
        acc.0 += *a * *b;
    }

    fn square_accumulate(acc: &mut Self::Accumulator, a: &Self) {
        acc.0 += a.square();
    }

    fn reduce(acc: Self::Accumulator) -> Self {
        acc.0
    }
}

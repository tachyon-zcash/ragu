//! Arithmetic combinators for [`Maybe<T>`] values.
//!
//! [`MaybeArith`] is a blanket extension trait that lifts standard arithmetic
//! operations (`Add`, `Sub`, `Mul`, `Neg`) into the [`Maybe`] abstraction.
//! For [`Always`] values the operation executes; for [`Empty`] values the
//! closure is dead-code eliminated, exactly like [`Maybe::just`].
//!
//! # Example
//!
//! ```ignore
//! // Before:
//! let sum = D::just(|| *a.snag() + *b.snag());
//!
//! // After:
//! let sum = a.maybe_add(&b);
//! ```
//!
//! [`Always`]: super::Always
//! [`Empty`]: super::Empty

use core::ops::{Add, Mul, Neg, Sub};

use super::{Maybe, MaybeKind, Perhaps};

/// Arithmetic combinators for [`Maybe<T>`] values.
///
/// This trait is automatically implemented for every type that implements
/// [`Maybe<T>`].  It provides convenience methods that combine
/// [`snag`](Maybe::snag) and [`just`](Maybe::just) into a single call for
/// common arithmetic patterns.
pub trait MaybeArith<T: Send>: Maybe<T> {
    /// Element-wise addition of two [`Maybe`] values.
    fn maybe_add(&self, other: &Perhaps<Self::Kind, T>) -> Perhaps<Self::Kind, T>
    where
        T: Add<Output = T> + Copy + Sync;

    /// Element-wise subtraction of two [`Maybe`] values.
    fn maybe_sub(&self, other: &Perhaps<Self::Kind, T>) -> Perhaps<Self::Kind, T>
    where
        T: Sub<Output = T> + Copy + Sync;

    /// Element-wise multiplication of two [`Maybe`] values.
    fn maybe_mul(&self, other: &Perhaps<Self::Kind, T>) -> Perhaps<Self::Kind, T>
    where
        T: Mul<Output = T> + Copy + Sync;

    /// Negation of a [`Maybe`] value.
    fn maybe_neg(&self) -> Perhaps<Self::Kind, T>
    where
        T: Neg<Output = T> + Copy + Sync;
}

impl<T: Send, M: Maybe<T>> MaybeArith<T> for M {
    fn maybe_add(&self, other: &Perhaps<Self::Kind, T>) -> Perhaps<Self::Kind, T>
    where
        T: Add<Output = T> + Copy + Sync,
    {
        Self::Kind::maybe_just(|| *self.snag() + *other.snag())
    }

    fn maybe_sub(&self, other: &Perhaps<Self::Kind, T>) -> Perhaps<Self::Kind, T>
    where
        T: Sub<Output = T> + Copy + Sync,
    {
        Self::Kind::maybe_just(|| *self.snag() - *other.snag())
    }

    fn maybe_mul(&self, other: &Perhaps<Self::Kind, T>) -> Perhaps<Self::Kind, T>
    where
        T: Mul<Output = T> + Copy + Sync,
    {
        Self::Kind::maybe_just(|| *self.snag() * *other.snag())
    }

    fn maybe_neg(&self) -> Perhaps<Self::Kind, T>
    where
        T: Neg<Output = T> + Copy + Sync,
    {
        Self::Kind::maybe_just(|| -*self.snag())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::maybe::{Always, Empty};

    fn check_add<K: MaybeKind>() {
        let a = K::maybe_just(|| 10u64);
        let b = K::maybe_just(|| 3u64);
        let c = a.maybe_add(&b);
        K::maybe_just(|| {
            assert_eq!(*c.snag(), 13);
        });
    }

    fn check_sub<K: MaybeKind>() {
        let a = K::maybe_just(|| 10u64);
        let b = K::maybe_just(|| 3u64);
        let c = a.maybe_sub(&b);
        K::maybe_just(|| {
            assert_eq!(*c.snag(), 7);
        });
    }

    fn check_mul<K: MaybeKind>() {
        let a = K::maybe_just(|| 10u64);
        let b = K::maybe_just(|| 3u64);
        let c = a.maybe_mul(&b);
        K::maybe_just(|| {
            assert_eq!(*c.snag(), 30);
        });
    }

    fn check_neg<K: MaybeKind>() {
        let a = K::maybe_just(|| 5i64);
        let b = a.maybe_neg();
        K::maybe_just(|| {
            assert_eq!(*b.snag(), -5);
        });
    }

    #[test]
    fn always_add() { check_add::<Always<()>>(); }

    #[test]
    fn always_sub() { check_sub::<Always<()>>(); }

    #[test]
    fn always_mul() { check_mul::<Always<()>>(); }

    #[test]
    fn always_neg() { check_neg::<Always<()>>(); }

    #[test]
    fn empty_add() { check_add::<Empty>(); }

    #[test]
    fn empty_sub() { check_sub::<Empty>(); }

    #[test]
    fn empty_mul() { check_mul::<Empty>(); }

    #[test]
    fn empty_neg() { check_neg::<Empty>(); }

    #[test]
    fn empty_closures_not_called() {
        use core::cell::Cell;
        let called = Cell::new(false);
        let a = <Empty as Maybe<u64>>::just(|| { called.set(true); 1 });
        let b = <Empty as Maybe<u64>>::just(|| { called.set(true); 2 });
        let _ = MaybeArith::<u64>::maybe_add(&a, &b);
        let _ = MaybeArith::<u64>::maybe_sub(&a, &b);
        let _ = MaybeArith::<u64>::maybe_mul(&a, &b);
        let c = <Empty as Maybe<i64>>::just(|| { called.set(true); 1 });
        let _ = MaybeArith::<i64>::maybe_neg(&c);
        assert!(!called.get());
    }
}

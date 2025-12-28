//! This is an internal module used to store helper utilities that are not part
//! of the public API (yet).

use arithmetic::Coeff;
use ff::Field;
use ragu_core::maybe::{Maybe, MaybeKind};

use core::borrow::Borrow;

/// Extension trait for `Maybe` that provides helper methods kept internal to
/// this crate.
pub(crate) trait InternalMaybe<T: Send>: Maybe<T> {
    /// Convert a `bool` into a `Field` element.
    fn fe<U, F: Field>(&self) -> <<Self as Maybe<U>>::Kind as MaybeKind>::Rebind<F>
    where
        Self: Maybe<U>,
        U: Borrow<bool> + Send + Sync,
    {
        Maybe::<U>::view(self).map(|b| if *b.borrow() { F::ONE } else { F::ZERO })
    }

    /// Convert a `bool` into a `Coeff`.
    fn coeff<U, F: Field>(&self) -> <<Self as Maybe<U>>::Kind as MaybeKind>::Rebind<Coeff<F>>
    where
        Self: Maybe<U>,
        U: Borrow<bool> + Send + Sync,
    {
        Maybe::<U>::view(self).map(|b| if *b.borrow() { Coeff::One } else { Coeff::Zero })
    }

    /// Convert an arbitrary `Field` element into a `Coeff`.
    fn arbitrary<U, F: Field>(&self) -> <<Self as Maybe<U>>::Kind as MaybeKind>::Rebind<Coeff<F>>
    where
        Self: Maybe<U>,
        U: Borrow<F> + Send + Sync,
    {
        Maybe::<U>::view(self).map(|f| Coeff::Arbitrary(*f.borrow()))
    }

    /// Negate a `bool`.
    fn not<U>(&self) -> <<Self as Maybe<U>>::Kind as MaybeKind>::Rebind<bool>
    where
        Self: Maybe<U>,
        U: Borrow<bool> + Send + Sync,
    {
        Maybe::<U>::view(self).map(|b| !*b.borrow())
    }
}

impl<T: Send, M: Maybe<T>> InternalMaybe<T> for M {}

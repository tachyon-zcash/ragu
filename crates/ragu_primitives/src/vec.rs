//! Provides [`FixedVec`], a wrapper around [`Vec<T>`] with a compile-time
//! length guarantee that allows it to implement [`Gadget`].
//!
//! [`Vec<T>`] cannot implement [`Gadget`] (when `T` implements `Gadget`)
//! because gadgets must be _fungible_: their synthesis behavior must be
//! type-determined, not instance-determined. A `Vec` has dynamic length,
//! meaning different instances could have different wire counts, causing
//! [`GadgetKind::map_gadget`] to behave differently per instance.
//!
//! Ragu provides [`Gadget`] implementations for `[T; N]` and `Box<[T; N]>`
//! where `const N: usize`, but const generics are still [somewhat
//! limited](https://github.com/rust-lang/rust/issues/60551) in Rust.
//!
//! [`FixedVec`] solves this by parameterizing on a [`Len`] type `L` that
//! statically determines the vector's length. All instances of `FixedVec<T, L>`
//! have exactly [`L::len()`](Len::len) elements, making their synthesis
//! behavior type-determined. `FixedVec` implements [`Gadget`] if `T` implements
//! `Gadget`, and can also be serialized via [`Write`] if `T::Kind` implements
//! `Write`.

use ff::Field;
use ragu_core::{
    Error, Result,
    drivers::{Driver, FromDriver},
    gadgets::{Consistent, Gadget, GadgetKind},
};

use alloc::vec::Vec;
use core::{
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

use crate::io::{Buffer, Write};

/// A type that statically determines the length of a [`FixedVec`].
pub trait Len: Send + Sync + 'static {
    /// Returns the length that a vector is guaranteed to have at all times.
    ///
    /// This must always return the same value for a given concrete
    /// implementation.
    fn len() -> usize;

    /// Returns a range from `0` to [`Self::len()`].
    fn range() -> core::ops::Range<usize> {
        0..Self::len()
    }
}

/// Represents a compile-time constant length.
///
/// Use this when the length is known at compile time. For lengths determined
/// by type parameters or other computed values, implement [`Len`] directly.
pub struct ConstLen<const N: usize>;

impl<const N: usize> Len for ConstLen<N> {
    fn len() -> usize {
        N
    }
}

/// A wrapper around a vector that is guaranteed to have a specific length
/// determined by the [`Len`] marker type `L`. Because its length is fixed it
/// implements [`Gadget`] when `T: Gadget`.
///
/// Create a [`FixedVec<T, L>`] by taking a [`Vec<T>`] which has the exact
/// length [`L::len()`](Len::len) and supplying it to [`FixedVec::new`] or
/// [`FixedVec::try_from`], both of which return an error if the length is
/// incorrect. The [`FixedVec::from_fn`] constructor can also be used to
/// construct a vector by initializing each individual element based on its
/// index.
///
/// [`FixedVec<T, L>`] dereferences to a `&[T]` (or `&mut [T]`), which allows
/// you to inspect and modify elements of the vector, but not grow it. You can
/// recover the vector by consuming the [`FixedVec`] using
/// [`FixedVec::into_inner`].
pub struct FixedVec<T, L: Len> {
    v: Vec<T>,
    _marker: PhantomData<L>,
}

impl<T, L: Len> TryFrom<Vec<T>> for FixedVec<T, L> {
    type Error = Error;

    fn try_from(mut v: Vec<T>) -> Result<Self> {
        if v.len() != L::len() {
            Err(Error::VectorLengthMismatch {
                expected: L::len(),
                actual: v.len(),
            })
        } else {
            v.shrink_to_fit();
            Ok(FixedVec {
                v,
                _marker: PhantomData,
            })
        }
    }
}

/// Extension trait for collecting an iterator into a [`FixedVec`].
pub trait CollectFixed: Iterator + Sized {
    /// Collect this iterator into a [`FixedVec`], returning an error if the
    /// length does not match [`L::len()`](Len::len).
    fn collect_fixed<L: Len>(self) -> Result<FixedVec<Self::Item, L>> {
        FixedVec::try_from(self.collect::<Vec<_>>())
    }

    /// Collect this iterator of [`ragu_core::Result`]s into a [`FixedVec`],
    /// short-circuiting on the first error, then returning an error if the
    /// length does not match [`L::len()`](Len::len).
    fn try_collect_fixed<T, L: Len>(self) -> Result<FixedVec<T, L>>
    where
        Self: Iterator<Item = Result<T>>,
    {
        let vec = self.collect::<Result<Vec<_>>>()?;
        FixedVec::try_from(vec)
    }
}

impl<I: Iterator> CollectFixed for I {}

impl<T, L: Len> FixedVec<T, L> {
    /// Creates a new [`FixedVec`] from a vector, returning an error if the
    /// length does not match [`L::len()`](Len::len).
    pub fn new(v: Vec<T>) -> Result<Self> {
        Self::try_from(v)
    }

    /// Initialize a [`FixedVec`] using a closure that initializes each element
    /// based on its index. This function behaves similarly to
    /// [`core::array::from_fn`].
    pub fn from_fn<F>(f: F) -> Self
    where
        F: FnMut(usize) -> T,
    {
        L::range()
            .map(f)
            .collect_fixed()
            .expect("length is correct")
    }

    /// Initialize a [`FixedVec`] using a closure that initializes each element
    /// based on its index, returning an error instead if the closure ever
    /// returns an error.
    pub fn try_from_fn<F>(f: F) -> Result<Self>
    where
        F: FnMut(usize) -> Result<T>,
    {
        L::range().map(f).try_collect_fixed()
    }

    /// Consumes `self` and returns the inner vector, guaranteed to have length
    /// [`L::len()`](Len::len).
    pub fn into_inner(self) -> Vec<T> {
        assert_eq!(self.len(), L::len());
        self.v
    }
}

impl<T: Clone, L: Len> Clone for FixedVec<T, L> {
    fn clone(&self) -> Self {
        assert_eq!(self.len(), L::len());
        FixedVec {
            v: self.v.clone(),
            _marker: PhantomData,
        }
    }
}

impl<F: Field, G: Write<F>, L: Len> Write<F> for FixedVec<PhantomData<G>, L> {
    fn write_gadget<'dr, D: Driver<'dr, F = F>, B: Buffer<'dr, D>>(
        this: &FixedVec<G::Rebind<'dr, D>, L>,
        dr: &mut D,
        buf: &mut B,
    ) -> Result<()> {
        for item in &this.v {
            G::write_gadget(item, dr, buf)?;
        }
        Ok(())
    }
}

impl<T, L: Len> Deref for FixedVec<T, L> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.v
    }
}

impl<T, L: Len> DerefMut for FixedVec<T, L> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.v
    }
}

impl<T, L: Len> IntoIterator for FixedVec<T, L> {
    type Item = T;
    type IntoIter = alloc::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.v.into_iter()
    }
}

impl<'dr, D: Driver<'dr>, G: Gadget<'dr, D>, L: Len> Gadget<'dr, D> for FixedVec<G, L> {
    type Kind = FixedVec<PhantomData<G::Kind>, L>;
}

impl<'dr, D: Driver<'dr>, G: Consistent<'dr, D>, L: Len> Consistent<'dr, D> for FixedVec<G, L> {
    fn enforce_consistent(&self, dr: &mut D) -> Result<()> {
        for item in self.iter() {
            item.enforce_consistent(dr)?;
        }
        Ok(())
    }
}

/// Safety: `G: GadgetKind<D::F>` implies that `G::Rebind<'dr, D>` is `Send`
/// when `D::Wire` is `Send`, by the safety contract of `GadgetKind`. Because
/// `FixedVec<G::Rebind<'dr, D>, L>` only contains `G::Rebind<'dr, D>`, it is
/// also `Send` when `D::Wire` is `Send`.
unsafe impl<F: Field, G: GadgetKind<F>, L: Len> GadgetKind<F> for FixedVec<PhantomData<G>, L> {
    type Rebind<'dr, D: Driver<'dr, F = F>> = FixedVec<G::Rebind<'dr, D>, L>;

    fn map_gadget<'dr, 'new_dr, D: Driver<'dr, F = F>, ND: FromDriver<'dr, 'new_dr, D>>(
        this: &Self::Rebind<'dr, D>,
        ndr: &mut ND,
    ) -> Result<Self::Rebind<'new_dr, ND::NewDriver>> {
        assert_eq!(this.len(), L::len());

        this.iter()
            .map(|g| G::map_gadget(g, ndr))
            .try_collect_fixed()
    }

    fn enforce_equal_gadget<
        'dr,
        D1: Driver<'dr, F = F>,
        D2: Driver<'dr, F = F, Wire = <D1 as Driver<'dr>>::Wire>,
    >(
        dr: &mut D1,
        a: &Self::Rebind<'dr, D2>,
        b: &Self::Rebind<'dr, D2>,
    ) -> Result<()> {
        for (a, b) in a.iter().zip(b.iter()) {
            G::enforce_equal_gadget(dr, a, b)?;
        }
        Ok(())
    }
}

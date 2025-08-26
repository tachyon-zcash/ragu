//! Provides [`FixedVec`], a wrapper around [`Vec<T>`] with a runtime-enforced
//! guarantee about its length that allows it to be safely used as a gadget.
//!
//! [`Vec<G>`] cannot implement [`Gadget<D>`] because [`Vec`] has a dynamic
//! length, which means that its [`GadgetKind::map`] implementation would vary
//! in behavior depending on the state of the gadget. This is disallowed by its
//! API contract. Ragu provides a generic implementation of [`Gadget`] for
//! `Box<[T; N]>` and `[T; N]` where `const N: usize`, but `const` generics are
//! still [somewhat limited](https://github.com/rust-lang/rust/issues/60551) in
//! Rust (as of 1.87).
//!
//! This module provides [`FixedVec`], a wrapper around `Vec` which enforces a
//! fixed length based on a the parameterized [`Len`] type. [`FixedVec<G, L>`]
//! implements [`Gadget`] if `G` implements [`Gadget`].

use ff::Field;
use ragu_core::{
    Error, Result,
    drivers::{Driver, FromDriver},
    gadgets::{Gadget, GadgetKind},
};

use alloc::vec::Vec;
use core::{
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

use crate::serialize::{Buffer, GadgetSerialize};

/// A type that statically determines the length of a [`FixedVec`].
pub trait Len: Send + Sync + 'static {
    /// Returns the length that a vector is guaranteed to have at all times.
    ///
    /// This must always return the same value for a given concrete
    /// implementation.
    fn len() -> usize;
}

/// Represents a length determined at compile time.
pub struct ConstLen<const N: usize>;

impl<const N: usize> Len for ConstLen<N> {
    fn len() -> usize {
        N
    }
}

/// This is a wrapper around a vector that is guaranteed to have a specific
/// length determined by the the [`Len`] marker type `L`. Because its length is
/// fixed it implements [`Gadget`].
pub struct FixedVec<T, L: Len> {
    v: Vec<T>,
    _marker: PhantomData<L>,
}

impl<T, L: Len> TryFrom<Vec<T>> for FixedVec<T, L> {
    type Error = Error;

    fn try_from(v: Vec<T>) -> Result<Self> {
        if v.len() != L::len() {
            Err(Error::VectorLengthMismatch {
                expected: L::len(),
                actual: v.len(),
            })
        } else {
            Ok(FixedVec {
                v,
                _marker: PhantomData,
            })
        }
    }
}

impl<T, L: Len> FixedVec<T, L> {
    /// Creates a new `FixedVec` from a vector, returning an error if the length
    /// does not match `L::len()`.
    pub fn new(v: Vec<T>) -> Result<Self> {
        Self::try_from(v)
    }

    /// Initialize a `FixedVec` using a closure that initializes each element
    /// based on its index. This function behaves similarly to
    /// [`core::array::from_fn`].
    pub fn from_fn<F>(f: F) -> Self
    where
        F: FnMut(usize) -> T,
    {
        FixedVec {
            v: (0..L::len()).map(f).collect(),
            _marker: PhantomData,
        }
    }

    /// Consumes `self` and returns the inner vector, guaranteed to have length
    /// determined by `L`.
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

impl<F: Field, G: GadgetSerialize<F>, L: Len> GadgetSerialize<F> for FixedVec<PhantomData<G>, L> {
    fn serialize_gadget<'dr, D: Driver<'dr, F = F>, B: Buffer<'dr, D>>(
        this: &FixedVec<G::Rebind<'dr, D>, L>,
        dr: &mut D,
        buf: &mut B,
    ) -> Result<()> {
        for item in &this.v {
            G::serialize_gadget(item, dr, buf)?;
        }
        Ok(())
    }
}

impl<T, L: Len> Deref for FixedVec<T, L> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.v[..]
    }
}

impl<T, L: Len> DerefMut for FixedVec<T, L> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.v[..]
    }
}

impl<'dr, D: Driver<'dr>, G: Gadget<'dr, D>, L: Len> Gadget<'dr, D> for FixedVec<G, L> {
    type Kind = FixedVec<PhantomData<G::Kind>, L>;
}

unsafe impl<F: Field, G: GadgetKind<F>, L: Len> GadgetKind<F> for FixedVec<PhantomData<G>, L> {
    type Rebind<'dr, D: Driver<'dr, F = F>> = FixedVec<G::Rebind<'dr, D>, L>;

    fn map<'dr, 'new_dr, D: Driver<'dr, F = F>, ND: FromDriver<'dr, 'new_dr, D>>(
        this: &Self::Rebind<'dr, D>,
        ndr: &mut ND,
    ) -> Result<Self::Rebind<'new_dr, ND::NewDriver>> {
        assert_eq!(this.len(), L::len());
        let v: Result<_> = this.iter().map(|g| G::map(g, ndr)).collect();
        Ok(FixedVec {
            v: v?,
            _marker: PhantomData,
        })
    }

    fn enforce_equal<
        'dr,
        D1: Driver<'dr, F = F>,
        D2: Driver<'dr, F = F, Wire = <D1 as Driver<'dr>>::Wire>,
    >(
        dr: &mut D1,
        a: &Self::Rebind<'dr, D2>,
        b: &Self::Rebind<'dr, D2>,
    ) -> Result<()> {
        for (a, b) in a.iter().zip(b.iter()) {
            G::enforce_equal(dr, a, b)?;
        }
        Ok(())
    }
}

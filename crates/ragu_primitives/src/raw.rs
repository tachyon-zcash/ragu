//! Gadgets that contain non-witness values.
//!
//! ## Overview
//!
//! Gadgets must be _fungible_: a gadget's behavior during circuit synthesis
//! must be fully determined by its type, not by any particular instance's
//! state. The automatic derivation of [`Gadget`] enforces this by only allowing
//! wires (`D::Wire`), witness values (`DriverValue<D, T>`), `PhantomData`, and
//! nested gadgets within a struct.
//!
//! However, gadgets sometimes need runtime data that is neither a wire nor
//! witness. This module provides [`Raw<T, S>`], which can contain such data
//! while preserving fungibility, provided the data is _stable_: every instance
//! of `S` must dereference to the same `T` value.
//!
//! Because `S` determines `T` (not any particular instance), all `Raw<T, S>`
//! instances are semantically equivalent, satisfying fungibility.
//!
//! ## Usage
//!
//! Implement the [`Stable<T>`] trait for your type to indicate that it will not
//! vary in its underlying value in practice. Then, you can construct a [`Raw<T,
//! S>`] that contains an `S` value that implements [`Stable<T>`]. The `Raw`
//! gadget will dereference to the underlying `T` value, and satisfies the
//! fungibility guarantee due to the stability of `S`.

use ff::Field;
use ragu_core::{
    Result,
    drivers::{Driver, FromDriver},
    gadgets::{Gadget, GadgetKind},
};

use core::{marker::PhantomData, ops::Deref};

use crate::io::{Buffer, Write};

/// Containers guaranteed to dereference to the same `T` value regardless of
/// instance.
///
/// Implementing `Stable<T>` for a type `S` asserts that every instance of `S`
/// dereferences to an equivalent `T`. This makes `S` suitable for use in
/// [`Raw<T, S>`], satisfying fungibility because the value is type-determined.
pub trait Stable<T: Send + Sync + Copy + 'static>:
    Deref<Target = T> + Send + Sync + Copy + 'static
{
}

/// Gadget containing a non-witness value that satisfies fungibility.
///
/// `Raw<T, S>` wraps a [`Stable<T>`] container `S` and dereferences to its `T`
/// value. Because `S: Stable<T>` guarantees all instances dereference to the
/// same value, `Raw` satisfies fungibility: its synthesis behavior is
/// type-determined, not instance-determined.
pub struct Raw<'dr, D: Driver<'dr>, T: Send + Sync + Copy + 'static, S: Stable<T>> {
    value: S,
    _marker: PhantomData<(T, &'dr (), D)>,
}

impl<'dr, D: Driver<'dr>, T: Send + Sync + Copy + 'static, S: Stable<T>> Raw<'dr, D, T, S> {
    /// Creates a new [`Raw`] gadget with the given value.
    pub fn new(value: S) -> Self {
        Self {
            value,
            _marker: PhantomData,
        }
    }
}

impl<'dr, D: Driver<'dr>, T: Send + Sync + Copy + 'static, S: Stable<T>> Clone
    for Raw<'dr, D, T, S>
{
    fn clone(&self) -> Self {
        Self {
            value: self.value,
            _marker: PhantomData,
        }
    }
}

impl<'dr, D: Driver<'dr>, T: Send + Sync + Copy + 'static, S: Stable<T>> Deref
    for Raw<'dr, D, T, S>
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

/// Fungibility: All instances of `Raw` are semantically equivalent by the
/// guarantee that `S` dereferences to the same `T` value.
impl<'dr, D: Driver<'dr>, T: Send + Sync + Copy + 'static, S: Stable<T>> Gadget<'dr, D>
    for Raw<'dr, D, T, S>
{
    type Kind = Raw<'static, PhantomData<D::F>, T, S>;

    fn map<'new_dr, ND: FromDriver<'dr, 'new_dr, D>>(
        &self,
        ndr: &mut ND,
    ) -> Result<<Self::Kind as GadgetKind<D::F>>::Rebind<'new_dr, ND::NewDriver>> {
        Self::Kind::map_gadget(self, ndr)
    }

    fn enforce_equal<D2: Driver<'dr, F = D::F, Wire = D::Wire>>(
        &self,
        dr: &mut D2,
        other: &Self,
    ) -> Result<()> {
        Self::Kind::enforce_equal_gadget::<D2, D>(dr, self, other)
    }
}

/// Safety: `Raw<T, S>` contains no wires, only `S: Send` and `PhantomData<T>`.
/// Therefore `Raw` is unconditionally `Send`, satisfying the requirement that
/// `Rebind<'dr, D>: Send` when `D::Wire: Send`.
unsafe impl<F: Field, T: Send + Sync + Copy + 'static, S: Stable<T>> GadgetKind<F>
    for Raw<'static, PhantomData<F>, T, S>
{
    type Rebind<'dr, D: Driver<'dr, F = F>> = Raw<'dr, D, T, S>;

    fn map_gadget<'dr, 'new_dr, D: Driver<'dr, F = F>, ND: FromDriver<'dr, 'new_dr, D>>(
        this: &Self::Rebind<'dr, D>,
        _: &mut ND,
    ) -> Result<Self::Rebind<'new_dr, ND::NewDriver>> {
        // There are no wires or witness values in a `Raw` gadget.
        Ok(Raw {
            value: this.value,
            _marker: PhantomData,
        })
    }

    fn enforce_equal_gadget<
        'dr,
        D1: Driver<'dr, F = F>,
        D2: Driver<'dr, F = F, Wire = <D1 as Driver<'dr>>::Wire>,
    >(
        _: &mut D1,
        _: &Self::Rebind<'dr, D2>,
        _: &Self::Rebind<'dr, D2>,
    ) -> Result<()> {
        // By the definition of `Stable<T>`, all instances of `S` will
        // dereference to the same `T` value. Therefore, all instances of `Raw`
        // are equivalent.
        Ok(())
    }
}

impl<F: Field, T: Send + Sync + Copy + 'static, S: Stable<T>> Write<F>
    for Raw<'static, PhantomData<F>, T, S>
{
    fn write_gadget<'dr, D: Driver<'dr, F = F>, B: Buffer<'dr, D>>(
        _: &Self::Rebind<'dr, D>,
        _: &mut D,
        _: &mut B,
    ) -> Result<()> {
        // There are no wires in a `Raw` gadget.
        Ok(())
    }
}

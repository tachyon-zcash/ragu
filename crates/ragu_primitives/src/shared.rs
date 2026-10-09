//! Fixed, typed connections between application circuits.

use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_core::{
    Error, Result,
    drivers::Driver,
    gadgets::{Bound, Gadget, GadgetKind, Kind},
};
use udon::field::Field;

use crate::{
    Element,
    vec::{FixedVec, Len},
};

/// The element buffer used by the `Shared` derive.
#[doc(hidden)]
pub type Values<'dr, D> = Vec<Element<'dr, D>>;

/// The wire schema of a connection shared by application fragments.
///
/// Derive this together with [`Gadget`] on a named struct containing elements,
/// fixed vectors of elements, or other shared gadgets. The derivation includes
/// every gadget field; skipped fields, raw wires, and witness-only fields are
/// refused. Field order defines the common layout, and the size is derived
/// from the fields rather than declared separately by each fragment.
///
/// The application adapter binds *every wire* visited by [`GadgetKind::map_gadget`] to
/// the common committed stage. The values collected here only determine the
/// honest witness for that stage: collecting the wrong values cannot remove
/// those circuit constraints.
pub trait Shared<F: Field>: GadgetKind<F> {
    /// Returns the number of shared wires, checking size arithmetic.
    fn num_values() -> Result<usize>;

    /// Collects one element per wire in canonical gadget traversal order.
    ///
    /// Implementations must visit all wires in the same order as
    /// [`GadgetKind::map_gadget`]. The adapter checks the count and constrains
    /// every actual gadget wire, independently of this witness collection.
    fn write_shared<'dr, D: Driver<'dr, F = F>>(
        this: &Bound<'dr, D, Self>,
        values: &mut Vec<Element<'dr, D>>,
    ) -> Result<()>;
}

/// Derives a fixed shared-wire schema for a named gadget struct.
///
/// All gadget fields must themselves implement [`Shared`]. Only phantom
/// fields may be omitted. The macro derives checked size arithmetic and
/// witness collection in declaration order; it does not derive the
/// application's mathematical constraints.
///
/// ```
/// use ragu_core::{drivers::Driver, gadgets::{Gadget, Kind}, pasta::Fp};
/// use ragu_primitives::{Element, shared::Shared};
///
/// #[derive(Gadget, Shared)]
/// struct Connection<'dr, D: Driver<'dr>> {
///     input: Element<'dr, D>,
///     intermediate_state: Element<'dr, D>,
/// }
///
/// type ConnectionKind = Kind![Fp; Connection<'_, _>];
/// assert_eq!(ConnectionKind::num_values().unwrap(), 2);
/// ```
pub use ragu_macros::Shared;

impl<F: Field> Shared<F> for () {
    fn num_values() -> Result<usize> {
        Ok(0)
    }

    fn write_shared<'dr, D: Driver<'dr, F = F>>(
        _: &(),
        _: &mut Vec<Element<'dr, D>>,
    ) -> Result<()> {
        Ok(())
    }
}

impl<F: Field> Shared<F> for Kind![F; @Element<'_, _>] {
    fn num_values() -> Result<usize> {
        Ok(1)
    }

    fn write_shared<'dr, D: Driver<'dr, F = F>>(
        this: &Element<'dr, D>,
        values: &mut Vec<Element<'dr, D>>,
    ) -> Result<()> {
        values.push(this.clone());
        Ok(())
    }
}

impl<F: Field, G: Shared<F>, L: Len> Shared<F> for FixedVec<PhantomData<G>, L> {
    fn num_values() -> Result<usize> {
        let len = L::len();
        if len == 0 {
            return Ok(0);
        }
        G::num_values()?.checked_mul(len).ok_or_else(size_overflow)
    }

    fn write_shared<'dr, D: Driver<'dr, F = F>>(
        this: &FixedVec<Bound<'dr, D, G>, L>,
        values: &mut Vec<Element<'dr, D>>,
    ) -> Result<()> {
        for value in this.iter() {
            G::write_shared(value, values)?;
        }
        Ok(())
    }
}

/// Supports type inference for the `Shared` derive without constructing a gadget.
#[doc(hidden)]
pub fn field_size<F: Field, T, G>(_: fn(&T) -> &G) -> Result<usize>
where
    G: Gadget<'static, PhantomData<F>>,
    G::Kind: Shared<F>,
{
    <G::Kind as Shared<F>>::num_values()
}

/// Supports nested gadget fields in the `Shared` derive.
#[doc(hidden)]
pub fn write_field<'dr, D: Driver<'dr>, G: Gadget<'dr, D>>(
    field: &G,
    values: &mut Vec<Element<'dr, D>>,
) -> Result<()>
where
    G::Kind: Shared<D::F>,
{
    <G::Kind as Shared<D::F>>::write_shared(field, values)
}

/// Adds derived shared-field counts with overflow checking.
#[doc(hidden)]
pub fn add_sizes(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or_else(size_overflow)
}

fn size_overflow() -> Error {
    Error::Initialization("the shared gadget's wire count overflows usize".into())
}

#[cfg(test)]
mod tests {
    use ragu_core::{
        drivers::emulator::{Emulator, Wireless},
        maybe::{Always, Maybe},
        pasta::Fp,
    };

    use super::*;
    use crate::vec::{CollectFixed, ConstLen};

    type Emu = Emulator<Wireless<Always<()>, Fp>>;

    #[derive(Gadget, Shared)]
    struct Connection<'dr, D: Driver<'dr>> {
        input: Element<'dr, D>,
        state: Element<'dr, D>,
    }

    #[derive(Gadget, Shared)]
    struct Nested<'dr, D: Driver<'dr>, const N: usize> {
        connection: Connection<'dr, D>,
        rest: FixedVec<Element<'dr, D>, ConstLen<N>>,
    }

    #[derive(Gadget, Shared)]
    struct Overflow<'dr, D: Driver<'dr>> {
        enormous: FixedVec<Element<'dr, D>, ConstLen<{ usize::MAX }>>,
        extra: Element<'dr, D>,
    }

    #[test]
    fn named_and_nested_shared_layouts_include_every_wire_in_order() -> Result<()> {
        let mut dr = Emu::execute();
        let gadget = Nested::<_, 3> {
            connection: Connection {
                input: Element::alloc(&mut dr, &mut (), Emu::just(|| Fp::from(7)))?,
                state: Element::alloc(&mut dr, &mut (), Emu::just(|| Fp::from(9)))?,
            },
            rest: (11..14)
                .map(|n| Element::alloc(&mut dr, &mut (), Emu::just(|| Fp::from(n))))
                .try_collect_fixed()?,
        };
        type Schema = Kind![Fp; Nested<'_, _, 3>];
        assert_eq!(Schema::num_values()?, gadget.num_wires()?);
        let mut values = Vec::new();
        Schema::write_shared(&gadget, &mut values)?;
        let values: Vec<_> = values.iter().map(|e| *e.value().take()).collect();
        assert_eq!(values, [7, 9, 11, 12, 13].map(Fp::from));
        assert_eq!(<Kind![Fp; Nested<'_, _, 0>]>::num_values()?, 2);
        assert_eq!(<() as Shared<Fp>>::num_values()?, 0);
        Ok(())
    }

    #[test]
    fn shared_layout_arithmetic_is_checked_without_constructing_a_gadget() {
        assert!(<Kind![Fp; Overflow<'_, _>]>::num_values().is_err());
        type Huge =
            Kind![Fp; FixedVec<FixedVec<Element<'_, _>, ConstLen<{ usize::MAX }>>, ConstLen<2>>];
        assert!(Huge::num_values().is_err());
        type EmptyHuge = Kind![Fp; FixedVec<FixedVec<FixedVec<Element<'_, _>, ConstLen<{ usize::MAX }>>, ConstLen<2>>, ConstLen<0>>];
        assert_eq!(EmptyHuge::num_values().unwrap(), 0);
    }
}

//! Fixed, typed connections between application circuits.

#[doc(hidden)]
pub use alloc::vec::Vec;
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

/// The wire schema of a connection shared by application fragments.
///
/// Derive together with [`Gadget`] on a named struct of elements, fixed vectors,
/// or other shared gadgets. All gadget fields participate, in declaration order;
/// skipped fields, raw wires, and witness-only fields are refused.
///
/// This describes the wires, not the mathematical constraints on their values.
/// Real PCD binds every actual gadget wire to its committed application stage.
/// The mock does not construct that recursive stage.
pub trait Shared<F: Field>: GadgetKind<F> {
    /// Returns the number of shared wires, checking size arithmetic.
    fn num_values() -> Result<usize>;

    /// Collects one element per wire in canonical gadget traversal order.
    ///
    /// Implementations must match [`GadgetKind::map_gadget`]'s order.
    fn write_shared<'dr, D: Driver<'dr, F = F>>(
        this: &Bound<'dr, D, Self>,
        values: &mut Vec<Element<'dr, D>>,
    ) -> Result<()>;
}

/// Derives a fixed shared-wire schema for a named gadget struct.
///
/// Every gadget field must implement [`Shared`]; only phantom fields may be
/// omitted. This derives checked size arithmetic and witness collection, not
/// the application's mathematical constraints.
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
        if L::len() == 0 {
            return Ok(0);
        }
        G::num_values()?.checked_mul(L::len()).ok_or_else(|| {
            Error::Initialization("the shared gadget's wire count overflows usize".into())
        })
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
    a.checked_add(b).ok_or_else(|| {
        Error::Initialization("the shared gadget's wire count overflows usize".into())
    })
}

#[cfg(test)]
mod tests {
    use ragu_core::{
        drivers::Driver,
        gadgets::{Gadget, Kind},
        maybe::Maybe,
        pasta::Fp,
    };

    use super::Shared;
    use crate::{
        Element, Simulator,
        vec::{CollectFixed, ConstLen, FixedVec},
    };

    #[derive(Gadget, Shared)]
    struct Pair<'dr, D: Driver<'dr>> {
        first: Element<'dr, D>,
        second: Element<'dr, D>,
    }

    #[derive(Gadget, Shared)]
    struct Nested<'dr, D: Driver<'dr>, const N: usize> {
        pair: Pair<'dr, D>,
        rest: FixedVec<Element<'dr, D>, ConstLen<N>>,
    }

    #[test]
    fn derived_nested_layout_preserves_every_value_in_order() {
        let mut dr = Simulator::<Fp>::new();
        let first =
            Element::alloc(&mut dr, &mut (), Simulator::<Fp>::just(|| Fp::from(1u64))).unwrap();
        let second =
            Element::alloc(&mut dr, &mut (), Simulator::<Fp>::just(|| Fp::from(2u64))).unwrap();
        let nested = Nested::<_, 3> {
            pair: Pair { first, second },
            rest: (3u64..=5)
                .map(|value| {
                    Element::alloc(&mut dr, &mut (), Simulator::<Fp>::just(|| Fp::from(value)))
                        .unwrap()
                })
                .collect_fixed()
                .unwrap(),
        };
        assert_eq!(<Kind![Fp; Nested<'_, _, 3>]>::num_values().unwrap(), 5);
        let mut values = alloc::vec::Vec::new();
        <Kind![Fp; Nested<'_, _, 3>]>::write_shared(&nested, &mut values).unwrap();
        assert_eq!(
            values
                .iter()
                .map(|e| *e.value().take())
                .collect::<alloc::vec::Vec<_>>(),
            (1u64..=5).map(Fp::from).collect::<alloc::vec::Vec<_>>()
        );
        assert_eq!(<Kind![Fp; Nested<'_, _, 0>]>::num_values().unwrap(), 2);
        assert_eq!(
            <Kind![Fp; FixedVec<Element<'_, _>, ConstLen<0>>]>::num_values().unwrap(),
            0
        );
        assert!(super::add_sizes(usize::MAX, 1).is_err());
        assert!(<Kind![Fp; FixedVec<Pair<'_, _>, ConstLen<{usize::MAX}>>]>::num_values().is_err());
    }
}

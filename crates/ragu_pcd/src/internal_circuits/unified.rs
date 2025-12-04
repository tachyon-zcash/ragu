//! Unified instance/output interface
//!
//! Many internal circuits involved in the core protocol will share a common set
//! of public inputs so that k(Y) does not need to be evaluated many times, and
//! to make it easier to reconfigure the roles of individual circuits later.

use arithmetic::Cycle;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{Element, Point, io::Write};

#[allow(type_alias_bounds)]
pub type OutputKind<C: Cycle> = Kind![C::CircuitField; Output<'_, _, C>];

#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, C: Cycle> {
    #[ragu(gadget)]
    pub nested_preamble_commitment: Point<'dr, D, C::NestedCurve>,
    #[ragu(gadget)]
    pub w: Element<'dr, D>,

    /// This is used to ensure k(Y) has a zero coefficient for the linear term.
    #[ragu(gadget)]
    zero: Element<'dr, D>,
}

pub struct Instance<C: Cycle> {
    pub nested_preamble_commitment: C::NestedCurve,
    pub w: C::CircuitField,
}

/// An entry in the shared public inputs for an internal circuit.
pub struct Slot<'a, 'dr, D: Driver<'dr>, T, C: Cycle> {
    value: Option<T>,
    alloc: fn(&mut D, &DriverValue<D, &'a Instance<C>>) -> T,
    _marker: core::marker::PhantomData<&'dr ()>,
}

impl<'a, 'dr, D: Driver<'dr>, T: Clone, C: Cycle> Slot<'a, 'dr, D, T, C> {
    pub(super) fn new(alloc: fn(&mut D, &DriverValue<D, &'a Instance<C>>) -> T) -> Self {
        Slot {
            value: None,
            alloc,
            _marker: core::marker::PhantomData,
        }
    }

    pub fn get(&mut self, dr: &mut D, instance: &DriverValue<D, &'a Instance<C>>) -> T {
        assert!(self.value.is_none(), "Slot::get: slot already filled");
        let value = (self.alloc)(dr, instance);
        self.value = Some(value.clone());
        value
    }

    pub fn set(&mut self, value: T) {
        assert!(self.value.is_none(), "Slot::set: slot already filled");
        self.value = Some(value);
    }

    fn unwrap(self, dr: &mut D, instance: &DriverValue<D, &'a Instance<C>>) -> T {
        self.value.unwrap_or_else(|| (self.alloc)(dr, instance))
    }
}

pub struct OutputBuilder<'a, 'dr, D: Driver<'dr>, C: Cycle> {
    pub nested_preamble_commitment: Slot<'a, 'dr, D, Point<'dr, D, C::NestedCurve>, C>,
    pub w: Slot<'a, 'dr, D, Element<'dr, D>, C>,
}

impl<'a, 'dr, D: Driver<'dr, F = C::CircuitField>, C: Cycle> OutputBuilder<'a, 'dr, D, C> {
    pub fn new() -> Self {
        macro_rules! point_slot {
            ($field:ident) => {
                Slot::new(|dr, i: &DriverValue<D, &'a Instance<C>>| {
                    Point::alloc(dr, i.view().map(|i| i.$field)).unwrap()
                })
            };
        }
        macro_rules! element_slot {
            ($field:ident) => {
                Slot::new(|dr, i: &DriverValue<D, &'a Instance<C>>| {
                    Element::alloc(dr, i.view().map(|i| i.$field)).unwrap()
                })
            };
        }
        OutputBuilder {
            nested_preamble_commitment: point_slot!(nested_preamble_commitment),
            w: element_slot!(w),
        }
    }

    pub fn finish(
        self,
        dr: &mut D,
        instance: &DriverValue<D, &'a Instance<C>>,
    ) -> Result<Output<'dr, D, C>> {
        Ok(Output {
            nested_preamble_commitment: self.nested_preamble_commitment.unwrap(dr, instance),
            w: self.w.unwrap(dr, instance),
            zero: Element::zero(dr),
        })
    }
}

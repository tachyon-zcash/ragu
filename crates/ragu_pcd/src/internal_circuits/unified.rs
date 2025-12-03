use arithmetic::Cycle;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Gadget,
    maybe::Maybe,
};
use ragu_primitives::{Element, Point, io::Write};

#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, C: Cycle> {
    #[ragu(gadget)]
    pub nested_preamble_commitment: Point<'dr, D, C::NestedCurve>,
    #[ragu(gadget)]
    pub w: Element<'dr, D>,
    #[ragu(gadget)]
    pub nested_s_prime_commitment: Point<'dr, D, C::NestedCurve>,
    #[ragu(gadget)]
    pub y: Element<'dr, D>,
    #[ragu(gadget)]
    pub z: Element<'dr, D>,
    #[ragu(gadget)]
    pub nested_s_doubleprime_commitment: Point<'dr, D, C::NestedCurve>,
    #[ragu(gadget)]
    pub nested_error_commitment: Point<'dr, D, C::NestedCurve>,
    #[ragu(gadget)]
    pub mu: Element<'dr, D>,
    #[ragu(gadget)]
    pub nu: Element<'dr, D>,
    #[ragu(gadget)]
    pub nested_ab_commitment: Point<'dr, D, C::NestedCurve>,
    #[ragu(gadget)]
    pub nested_s_commitment: Point<'dr, D, C::NestedCurve>,
    #[ragu(gadget)]
    pub nested_query_commitment: Point<'dr, D, C::NestedCurve>,
    #[ragu(gadget)]
    pub alpha: Element<'dr, D>,
    #[ragu(gadget)]
    pub nested_f_commitment: Point<'dr, D, C::NestedCurve>,
    #[ragu(gadget)]
    pub u: Element<'dr, D>,
    #[ragu(gadget)]
    pub nested_eval_commitment: Point<'dr, D, C::NestedCurve>,
    #[ragu(gadget)]
    pub beta: Element<'dr, D>,
    #[ragu(gadget)]
    zero: Element<'dr, D>,
}

pub struct Instance<C: Cycle> {
    pub nested_preamble_commitment: C::NestedCurve,
    pub w: C::CircuitField,
    pub nested_s_prime_commitment: C::NestedCurve,
    pub y: C::CircuitField,
    pub z: C::CircuitField,
    pub nested_s_doubleprime_commitment: C::NestedCurve,

    pub nested_error_commitment: C::NestedCurve,
    pub mu: C::CircuitField,
    pub nu: C::CircuitField,
    pub nested_ab_commitment: C::NestedCurve,
    pub nested_s_commitment: C::NestedCurve,
    pub nested_query_commitment: C::NestedCurve,
    pub alpha: C::CircuitField,
    pub nested_f_commitment: C::NestedCurve,
    pub u: C::CircuitField,
    pub nested_eval_commitment: C::NestedCurve,
    pub beta: C::CircuitField,
}

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
        assert!(self.value.is_none(), "slot already accessed");
        let value = (self.alloc)(dr, instance);
        self.value = Some(value.clone());
        value
    }

    pub fn set(&mut self, value: T) {
        assert!(self.value.is_none(), "slot already accessed");
        self.value = Some(value);
    }

    fn take_or(self, dr: &mut D, instance: &DriverValue<D, &'a Instance<C>>) -> T {
        self.value.unwrap_or_else(|| (self.alloc)(dr, instance))
    }
}

pub struct OutputBuilder<'a, 'dr, D: Driver<'dr>, C: Cycle> {
    pub nested_preamble_commitment: Slot<'a, 'dr, D, Point<'dr, D, C::NestedCurve>, C>,
    pub w: Slot<'a, 'dr, D, Element<'dr, D>, C>,
    pub nested_s_prime_commitment: Slot<'a, 'dr, D, Point<'dr, D, C::NestedCurve>, C>,
    pub y: Slot<'a, 'dr, D, Element<'dr, D>, C>,
    pub z: Slot<'a, 'dr, D, Element<'dr, D>, C>,
    pub nested_s_doubleprime_commitment: Slot<'a, 'dr, D, Point<'dr, D, C::NestedCurve>, C>,
    pub nested_error_commitment: Slot<'a, 'dr, D, Point<'dr, D, C::NestedCurve>, C>,
    pub mu: Slot<'a, 'dr, D, Element<'dr, D>, C>,
    pub nu: Slot<'a, 'dr, D, Element<'dr, D>, C>,
    pub nested_ab_commitment: Slot<'a, 'dr, D, Point<'dr, D, C::NestedCurve>, C>,
    pub nested_s_commitment: Slot<'a, 'dr, D, Point<'dr, D, C::NestedCurve>, C>,
    pub nested_query_commitment: Slot<'a, 'dr, D, Point<'dr, D, C::NestedCurve>, C>,
    pub alpha: Slot<'a, 'dr, D, Element<'dr, D>, C>,
    pub nested_f_commitment: Slot<'a, 'dr, D, Point<'dr, D, C::NestedCurve>, C>,
    pub u: Slot<'a, 'dr, D, Element<'dr, D>, C>,
    pub nested_eval_commitment: Slot<'a, 'dr, D, Point<'dr, D, C::NestedCurve>, C>,
    pub beta: Slot<'a, 'dr, D, Element<'dr, D>, C>,
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
            nested_s_prime_commitment: point_slot!(nested_s_prime_commitment),
            y: element_slot!(y),
            z: element_slot!(z),
            nested_s_doubleprime_commitment: point_slot!(nested_s_doubleprime_commitment),
            nested_error_commitment: point_slot!(nested_error_commitment),
            mu: element_slot!(mu),
            nu: element_slot!(nu),
            nested_ab_commitment: point_slot!(nested_ab_commitment),
            nested_s_commitment: point_slot!(nested_s_commitment),
            nested_query_commitment: point_slot!(nested_query_commitment),
            alpha: element_slot!(alpha),
            nested_f_commitment: point_slot!(nested_f_commitment),
            u: element_slot!(u),
            nested_eval_commitment: point_slot!(nested_eval_commitment),
            beta: element_slot!(beta),
        }
    }

    pub fn finish(
        self,
        dr: &mut D,
        instance: &DriverValue<D, &'a Instance<C>>,
    ) -> Result<Output<'dr, D, C>> {
        Ok(Output {
            nested_preamble_commitment: self.nested_preamble_commitment.take_or(dr, instance),
            w: self.w.take_or(dr, instance),
            nested_s_prime_commitment: self.nested_s_prime_commitment.take_or(dr, instance),
            y: self.y.take_or(dr, instance),
            z: self.z.take_or(dr, instance),
            nested_s_doubleprime_commitment: self
                .nested_s_doubleprime_commitment
                .take_or(dr, instance),
            nested_error_commitment: self.nested_error_commitment.take_or(dr, instance),
            mu: self.mu.take_or(dr, instance),
            nu: self.nu.take_or(dr, instance),
            nested_ab_commitment: self.nested_ab_commitment.take_or(dr, instance),
            nested_s_commitment: self.nested_s_commitment.take_or(dr, instance),
            nested_query_commitment: self.nested_query_commitment.take_or(dr, instance),
            alpha: self.alpha.take_or(dr, instance),
            nested_f_commitment: self.nested_f_commitment.take_or(dr, instance),
            u: self.u.take_or(dr, instance),
            nested_eval_commitment: self.nested_eval_commitment.take_or(dr, instance),
            beta: self.beta.take_or(dr, instance),
            zero: Element::zero(dr),
        })
    }
}

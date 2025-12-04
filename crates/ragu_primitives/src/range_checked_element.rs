use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe,
};
use ragu_macros::Gadget;
use crate::Element;

/// Represents a range-checked element of the CircuitField
/// For now, it's just u8 values
/// we perform the range check of an integer x in [0, BOUND) like this:
/// x(x-1)(x-2)...(x-BOUND) = 0
#[derive(Gadget)]
pub struct RangeCheckedElement<'dr, D: Driver<'dr>, const BOUND: u8> {
    #[ragu(gadget)]
    element: Element<'dr, D>,

    #[ragu(value)]
    value: DriverValue<D, u8>,
}

impl<'dr, D: Driver<'dr>, const BOUND: u8> RangeCheckedElement<'dr, D, BOUND> {
    /// Allocates a new range-checked element.
    pub fn alloc(dr: &mut D, value: DriverValue<D, u8>) -> Result<Self>
    where
        D::F: From<u8>,
    {
        let field_value = D::just(|| D::F::from(*value.snag()));
        let element = Element::alloc(dr, field_value)?;
        let mut current_product = element.clone();
        for i in 1..BOUND {
            let i = Element::constant(dr, D::F::from(i));
            let element_minus_i = element.sub(dr, &i);
            current_product = element_minus_i.mul(dr, &current_product)?;
        }
        dr.enforce_zero(|_| current_product.wire())?;
        /*let one = Element::constant(dr, D::F::from(1));
        let element_minus_1 = element.sub(dr, &one);*/
        Ok(Self { element, value })
    }
}
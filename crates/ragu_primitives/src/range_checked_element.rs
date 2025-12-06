use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe,
};
use ragu_macros::Gadget;
use crate::Element;

/// Represents a range-checked element of the CircuitField
/// For now, it's just u64 values
/// we perform the range check of an integer x in [0, BOUND) like this:
/// x(x-1)(x-2)...(x-(BOUND-1)) = 0
/// So if BOUND = 256, we check that x(x-1)(x-2)...(x-255) = 0
#[derive(Gadget)]
pub struct RangeCheckedElement<'dr, D: Driver<'dr>, const BOUND: u64> {
    #[ragu(gadget)]
    element: Element<'dr, D>,

    #[ragu(value)]
    value: DriverValue<D, u64>,
}

impl<'dr, D: Driver<'dr>, const BOUND: u64> RangeCheckedElement<'dr, D, BOUND> {
    /// Allocates a new range-checked element.
    pub fn alloc(dr: &mut D, value: DriverValue<D, u64>) -> Result<Self>
    where
        D::F: From<u64>,
    {
        let element = Element::alloc(dr, value.view().map(|f| D::F::from(*f)))?;
        let mut current_product = element.clone();
        let mut current_term = element.clone();
        for _ in 1..BOUND {
            current_term = current_term.sub(dr, &Element::one());
            current_product = current_product.mul(dr, &current_term)?;
        }
        current_product.enforce_zero(dr)?;
        /*let one = Element::constant(dr, D::F::from(1));
        let element_minus_1 = element.sub(dr, &one);*/
        Ok(Self { element, value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ragu_pasta::{Fp};
    use ragu_core::maybe::{Always, MaybeKind};
    use ragu_core::Error;
    #[test]
    fn test_valid_range_checked_element() {
        let mut simulator = crate::Simulator::<Fp>::new();
        let value = 100;
        let _range_checked_element: RangeCheckedElement<'_, crate::Simulator<Fp>, 256> = RangeCheckedElement::alloc(&mut simulator, Always::maybe_just(|| value))
            .unwrap();
        assert!(simulator.num_multiplications() == 255);
        assert!(simulator.num_linear_constraints() == 511);
    }

    #[test]
    fn test_invalid_range_checked_element() {
        let mut simulator = crate::Simulator::<Fp>::new();
        let value = 256;
        let result: Result<RangeCheckedElement<'_, crate::Simulator<Fp>, 256>> = RangeCheckedElement::alloc(&mut simulator, Always::maybe_just(|| value));
        assert!(matches!(result, Err(Error::InvalidWitness(_))));
    }

    #[test]
    fn test_zero_range_checked_element() {
        let mut simulator = crate::Simulator::<Fp>::new();
        let value = 0;
        let _range_checked_element: RangeCheckedElement<'_, crate::Simulator<Fp>, 256> = RangeCheckedElement::alloc(&mut simulator, Always::maybe_just(|| value))
            .unwrap();
        assert!(simulator.num_multiplications() == 255);
        assert!(simulator.num_linear_constraints() == 511);
    }

    #[test]
    fn test_max_value_range_checked_element() {
        let mut simulator = crate::Simulator::<Fp>::new();
        let value = 255;
        let _range_checked_element: RangeCheckedElement<'_, crate::Simulator<Fp>, 256> = RangeCheckedElement::alloc(&mut simulator, Always::maybe_just(|| value))
            .unwrap();
        assert!(simulator.num_multiplications() == 255);
        assert!(simulator.num_linear_constraints() == 511);
    }
}
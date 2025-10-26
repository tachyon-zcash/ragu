use ff::Field;
use ragu_circuits::Circuit;
use ragu_core::gadgets::{GadgetKind, Kind};
use ragu_core::maybe::Maybe;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
};
use ragu_primitives::Element;

#[derive(Clone)]
pub struct SquaringCircuit(pub usize);

impl<F: Field> Circuit<F> for SquaringCircuit {
    type Instance<'source> = F;
    type Witness<'source> = F;
    type Output = Kind![F; Element<'_, _>];
    type Aux<'source> = F;
    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>> {
        Element::alloc(dr, instance)
    }
    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<(
        <Self::Output as GadgetKind<F>>::Rebind<'dr, D>,
        DriverValue<D, Self::Aux<'source>>,
    )> {
        let mut cur = Element::alloc(dr, witness)?;

        for _ in 0..self.0 {
            cur = cur.square(dr)?;
        }

        let cur_value = cur.value().map(|v| *v);

        Ok((cur, D::just(|| cur_value.take())))
    }
}

pub struct Circuits {
    pub(crate) s3: SquaringCircuit,
    pub(crate) s4: SquaringCircuit,
    pub(crate) s10: SquaringCircuit,
    pub(crate) s19: SquaringCircuit,
}

impl Circuits {
    pub fn new() -> Self {
        Self {
            s3: SquaringCircuit(3),
            s4: SquaringCircuit(4),
            s10: SquaringCircuit(10),
            s19: SquaringCircuit(19),
        }
    }
}

use ff::Field;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{GadgetKind, Kind},
};
use ragu_primitives::Element;

pub const CIRCUIT_ID: usize = super::DUMMY_CIRCUIT_ID;

/// The dummy circuit for trivial proofs. Outputs a single `1` element
/// representing the trivial header prefix, which sits in the lowest degree
/// term of k(y) after reversal in the adapter.
pub struct Circuit;

impl<F: Field> ragu_circuits::Circuit<F> for Circuit {
    type Instance<'source> = ();
    type Witness<'source> = ();
    type Output = Kind![F; Element<'_, _>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>> {
        Ok(Element::one())
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<(
        <Self::Output as GadgetKind<F>>::Rebind<'dr, D>,
        DriverValue<D, Self::Aux<'source>>,
    )> {
        Ok((Element::one(), D::just(|| ())))
    }
}

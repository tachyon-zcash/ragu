//! Trivial circuit implementation.
//!
//! Provides an implementation of [`Circuit`] for the unit type `()`,
//! which creates zero constraints. Useful for testing and placeholders.

use crate::Circuit;
use ff::Field;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Bound,
};

impl<F: Field> Circuit<F> for () {
    type Instance = ();
    type Witness = ();
    type Output = ();
    type Aux = ();

    fn instance<'dr, D: Driver<'dr, F = F>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr,
    {
        Ok(())
    }

    fn witness<'dr, D: Driver<'dr, F = F>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Witness>,
    ) -> Result<(Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux>)>
    where
        Self: 'dr,
    {
        Ok(((), D::unit()))
    }
}

#[cfg(test)]
mod tests {
    use crate::Circuit;
    use ragu_core::drivers::emulator::{Emulator, Wired};
    use ragu_core::maybe::{Always, MaybeKind};
    use ragu_pasta::Fp;

    #[test]
    fn test_trivial() {
        let circuit = ();
        let mut dr = Emulator::<Wired<Fp>>::extractor();

        assert!(circuit.instance(&mut dr, Always::maybe_just(|| ())).is_ok());

        assert!(circuit.witness(&mut dr, Always::maybe_just(|| ())).is_ok());
    }
}

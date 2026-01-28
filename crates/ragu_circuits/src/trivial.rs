//! Trivial circuit implementation.
//!
//! Provides an implementation of [`Circuit`] for the unit type `()`,
//! which creates zero constraints. Useful for testing and placeholders.

use crate::Circuit;
use ff::Field;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::GadgetKind,
};

impl<F: Field> Circuit<F> for () {
    type Instance<'source> = ();
    type Witness<'source> = ();
    type Output = ();
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        Ok(())
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<(
        <Self::Output as GadgetKind<F>>::Rebind<'dr, D>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        Ok(((), D::just(|| ())))
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
        let instance = ();
        let mut dr = Emulator::<Wired<Fp>>::extractor();

        assert!(
            circuit
                .instance(&mut dr, Always::maybe_just(|| instance))
                .is_ok()
        );

        assert!(
            circuit
                .witness(&mut dr, Always::maybe_just(|| instance))
                .is_ok()
        );
    }
}

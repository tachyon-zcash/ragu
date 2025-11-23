use ff::Field;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{GadgetKind, Kind},
    maybe::Maybe,
    routines::{Prediction, Routine},
};
use ragu_primitives::{Boolean, Element};

/// Vaidates omega is valid 2^k root of unity for the domain size.
///
/// Checks that omega^(2^k) = 1, where k = log2_domain_size.
#[derive(Clone)]
pub struct ValidateOmega {
    log2_domain_size: u32,
}

impl ValidateOmega {
    pub fn _new(log2_domain_size: u32) -> Self {
        Self { log2_domain_size }
    }
}

impl<F: Field> Routine<F> for ValidateOmega {
    type Input = Kind![F; Element<'_, _>];
    type Output = Kind![F; Boolean<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        omega: <Self::Input as GadgetKind<F>>::Rebind<'dr, D>,
        _: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>> {
        // Compute omega^(2^k) by squaring k times.
        let mut value = omega;
        for _ in 0..self.log2_domain_size {
            value = value.square(dr)?;
        }

        let one = Element::one();
        let diff = value.sub(dr, &one);

        Boolean::alloc(dr, D::with(|| Ok(*diff.value().take() == F::ZERO))?)
    }

    fn predict<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        omega: &<Self::Input as GadgetKind<F>>::Rebind<'dr, D>,
    ) -> Result<
        Prediction<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>, DriverValue<D, Self::Aux<'dr>>>,
    > {
        let output = Boolean::alloc(
            dr,
            D::with(|| {
                let mut value = *omega.value().take();
                for _ in 0..self.log2_domain_size {
                    value = value.square();
                }

                Ok(value == F::ONE)
            })?,
        )?;

        Ok(Prediction::Known(output, D::just(|| ())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::PrimeField;
    use ragu_core::maybe::MaybeKind;
    use ragu_pasta::Fp;
    use ragu_primitives::Simulator;

    #[test]
    fn test_validate_omega_valid() -> Result<()> {
        let log2_domain_size = 8;

        // Maximal primitive 2^S-th root of unity.
        let omega = Fp::ROOT_OF_UNITY;

        // Reduce to 2^log2_domain_size-th root of unity.
        let reduced = Fp::S - log2_domain_size;
        let omega = omega.pow([1 << reduced]);

        let validator = ValidateOmega::_new(log2_domain_size);

        let _ = Simulator::simulate(omega, |dr, witness| {
            let omega = Element::alloc(dr, witness)?;
            let result = dr.routine(validator, omega)?;

            assert_eq!(*result.wire(), Fp::ONE);

            Ok(())
        });

        Ok(())
    }

    #[test]
    fn test_invalidate_omega_valid() -> Result<()> {
        let log2_domain_size = 8;

        // Maximal primitive 2^S-th root of unity.
        let omega = Fp::from(123456789u64);

        // Reduce to 2^log2_domain_size-th root of unity.
        let reduced = Fp::S - log2_domain_size;
        let omega = omega.pow([1 << reduced]);

        let validator = ValidateOmega::_new(log2_domain_size);

        let _ = Simulator::simulate(omega, |dr, witness| {
            let omega = Element::alloc(dr, witness)?;
            let result = dr.routine(validator, omega)?;

            assert_eq!(*result.wire(), Fp::ZERO);

            Ok(())
        });

        Ok(())
    }

    #[test]
    fn test_omega_match() -> Result<()> {
        // Verifies predict and execute yield the same result.
        use ragu_core::{maybe::Always, routines::Prediction};

        let log2_domain_size = 8;
        let validator = ValidateOmega::_new(log2_domain_size);

        {
            let omega = Fp::ROOT_OF_UNITY;
            let reduced = Fp::S - log2_domain_size;
            let omega = omega.pow([1 << reduced]);

            Simulator::simulate(omega, |dr, witness| {
                let omega_element = Element::alloc(dr, witness)?;

                // Invoke routine prediction.
                let prediction = validator.predict(dr, &omega_element)?;
                let predicted_value = match prediction {
                    Prediction::Known(output, _) => *output.wire(),
                    Prediction::Unknown(_) => panic!("Expected Known prediction"),
                };

                // Invoke routine execution.
                dr.reset();
                let executed = validator.execute(dr, omega_element, Always::maybe_just(|| ()))?;
                let executed_value = *executed.wire();

                assert_eq!(
                    predicted_value, executed_value,
                    "predict and execute should yield the same result"
                );
                assert_eq!(predicted_value, Fp::ONE, "valid omega should return true");

                Ok(())
            })?;
        }

        Ok(())
    }
}

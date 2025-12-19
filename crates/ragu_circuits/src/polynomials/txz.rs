//! Evaluation of the $t(X, Z)$ polynomial.

use ff::Field;
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::{GadgetKind, Kind},
    maybe::Maybe,
    routines::{Prediction, Routine},
};
use ragu_primitives::Element;

/// Routine for evaluating the TXZ polynomial, t(x, z).
#[derive(Clone)]
pub struct Evaluate {
    log2_n: u32,
    n: u64,
}

impl Evaluate {
    /// Creates a new evaluator for the given log-domain size.
    pub fn new(log2_n: u32) -> Self {
        let n = 1 << log2_n;

        Self { log2_n, n }
    }
}

impl<F: Field> Routine<F> for Evaluate {
    type Input = Kind![F; (Element<'_, _>, Element<'_, _>)];
    type Output = Kind![F; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        input: <Self::Input as GadgetKind<F>>::Rebind<'dr, D>,
        _: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>> {
        let x = input.0;
        let z = input.1;

        let mut xn = x.clone();
        for _ in 0..self.log2_n {
            xn = xn.square(dr)?;
        }
        let x2n = xn.square(dr)?;
        let x4n = x2n.square(dr)?;
        let mut zn = z.clone();
        for _ in 0..self.log2_n {
            zn = zn.square(dr)?;
        }
        let z2n = zn.square(dr)?;
        let x_inv = x.invert(dr)?;
        let x4n_minus_1 = x4n.mul(dr, &x_inv)?;
        let z_inv = z.invert(dr)?;
        let mut l = x4n_minus_1.mul(dr, &z2n)?;
        let mut r = l.clone();
        let mut xz_step = x_inv.mul(dr, &z)?;
        let mut xzinv_step = x_inv.mul(dr, &z_inv)?;
        for _ in 0..self.log2_n {
            let l_mul = l.mul(dr, &xz_step)?;
            l = l.add(dr, &l_mul);
            let r_mul = r.mul(dr, &xzinv_step)?;
            r = r.add(dr, &r_mul);
            xz_step = xz_step.square(dr)?;
            xzinv_step = xzinv_step.square(dr)?;
        }
        let r_zinv = r.mul(dr, &z_inv)?;
        let sum = l.add(dr, &r_zinv);
        Ok(sum.negate(dr))
    }

    fn predict<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        input: &<Self::Input as GadgetKind<F>>::Rebind<'dr, D>,
    ) -> Result<
        Prediction<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>, DriverValue<D, Self::Aux<'dr>>>,
    > {
        // TODO(ebfull): This prediction would be more helpful if the inversions
        // were laundered out through the auxiliary data.
        let output = Element::alloc(
            dr,
            D::with(|| {
                let x = *input.0.value().take();
                let z = *input.1.value().take();

                let xinv = x
                    .invert()
                    .into_option()
                    .ok_or_else(|| Error::InvalidWitness("division by zero".into()))?;
                let zinv = z
                    .invert()
                    .into_option()
                    .ok_or_else(|| Error::InvalidWitness("division by zero".into()))?;
                let mut xz_step = xinv * z;
                let mut xzinv_step = xinv * zinv;
                let mut l = x.pow([4 * self.n - 1]) * z.pow([2 * self.n]);
                let mut r = l;

                // This is computed efficiently as a geometric series.
                for _ in 0..self.log2_n {
                    l += l * xz_step;
                    r += r * xzinv_step;
                    xz_step = xz_step.square();
                    xzinv_step = xzinv_step.square();
                }

                Ok(-(l + r * zinv))
            })?,
        )?;

        Ok(Prediction::Known(output, D::just(|| ())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ragu_pasta::Fp;
    use ragu_primitives::Simulator;
    use rand::thread_rng;

    #[test]
    fn simulate_txz() -> Result<()> {
        let x = Fp::random(thread_rng());
        let z = Fp::random(thread_rng());
        let log2_n = 11; // Small value for testing
        let evaluator = Evaluate::new(log2_n);

        Simulator::simulate((x, z), |dr, witness| {
            let (x, z) = witness.cast();
            let x = Element::alloc(dr, x)?;
            let z = Element::alloc(dr, z)?;

            dr.reset();
            dr.routine(evaluator, (x, z))?;

            assert_eq!(dr.num_allocations(), 0);
            assert_eq!(dr.num_multiplications(), 76);
            assert_eq!(dr.num_linear_constraints(), 152);

            Ok(())
        })?;

        Ok(())
    }
}

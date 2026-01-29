//! Evaluation of the $t(X, Z)$ polynomial.

use ff::Field;
use ragu_core::{
    Error, Result,
    drivers::{
        Driver, DriverValue,
        emulator::{Emulator, Wireless},
    },
    gadgets::{GadgetKind, Kind},
    maybe::{Empty, Maybe},
    routines::{Prediction, Routine, RoutineShape},
};
use ragu_primitives::Element;

use core::marker::PhantomData;

use super::Rank;

/// Routine for evaluating the TXZ polynomial, t(x, z).
#[derive(Clone)]
pub struct Evaluate<R> {
    _marker: PhantomData<R>,
}

impl<R: Rank> Default for Evaluate<R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: Rank> Evaluate<R> {
    /// Creates a new evaluator for the given rank.
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<F: Field, R: Rank> Routine<F> for Evaluate<R> {
    type Input = Kind![F; (Element<'_, _>, Element<'_, _>)];
    type Output = Kind![F; Element<'_, _>];
    type Aux<'dr> = (F, F);

    fn shape(&self) -> RoutineShape {
        Emulator::derive_shape(|dr: &mut Emulator<Wireless<Empty, F>>| {
            let x = Element::zero(dr);
            let z = Element::zero(dr);
            let aux = Empty;
            let _ = self.execute(dr, (x, z), aux);
        })
    }

    fn execute<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        input: <Self::Input as GadgetKind<F>>::Rebind<'dr, D>,
        aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>> {
        let x = input.0;
        let z = input.1;

        let mut xn = x.clone();
        for _ in 0..R::log2_n() {
            xn = xn.square(dr)?;
        }
        let x2n = xn.square(dr)?;
        let x4n = x2n.square(dr)?;
        let mut zn = z.clone();
        for _ in 0..R::log2_n() {
            zn = zn.square(dr)?;
        }
        let z2n = zn.square(dr)?;

        // Use precomputed inversions from aux to avoid redundant computation
        let (x_inv_val, z_inv_val) = aux.cast();
        let x_inv = x.invert_with(dr, x_inv_val)?;
        let z_inv = z.invert_with(dr, z_inv_val)?;

        let x4n_minus_1 = x4n.mul(dr, &x_inv)?;
        let mut l = x4n_minus_1.mul(dr, &z2n)?;
        let mut r = l.clone();
        let mut xz_step = x_inv.mul(dr, &z)?;
        let mut xzinv_step = x_inv.mul(dr, &z_inv)?;
        for _ in 0..R::log2_n() {
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
        let n = 1u64 << R::log2_n();

        // Compute inversions once and store as aux data to accelerate execution
        let aux = D::with(|| {
            let x = *input.0.value().take();
            let z = *input.1.value().take();

            let x_inv = x
                .invert()
                .into_option()
                .ok_or_else(|| Error::InvalidWitness("division by zero".into()))?;
            let z_inv = z
                .invert()
                .into_option()
                .ok_or_else(|| Error::InvalidWitness("division by zero".into()))?;

            Ok((x_inv, z_inv))
        })?;

        // Compute output using the precomputed inversions
        let output = Element::alloc(
            dr,
            D::with(|| {
                let x = *input.0.value().take();
                let z = *input.1.value().take();
                let (x_inv, z_inv) = *aux.snag();

                let mut xz_step = x_inv * z;
                let mut xz_inv_step = x_inv * z_inv;
                let mut l = x.pow([4 * n - 1]) * z.pow([2 * n]);
                let mut r = l;

                // This is computed efficiently as a geometric series.
                for _ in 0..R::log2_n() {
                    l += l * xz_step;
                    r += r * xz_inv_step;
                    xz_step = xz_step.square();
                    xz_inv_step = xz_inv_step.square();
                }

                Ok(-(l + r * z_inv))
            })?,
        )?;

        Ok(Prediction::Known(output, aux))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::polynomials::R;
    use ragu_core::routines::Routine;
    use ragu_pasta::Fp;
    use ragu_primitives::Simulator;
    use rand::thread_rng;

    #[test]
    fn simulate_txz() -> Result<()> {
        // R<13> has log2_n = 11
        type TestRank = R<13>;

        let x = Fp::random(thread_rng());
        let z = Fp::random(thread_rng());
        let evaluator = Evaluate::<TestRank>::new();

        // Verify shape() matches actual execution
        let shape = <Evaluate<TestRank> as Routine<Fp>>::shape(&evaluator);
        assert_eq!(shape.num_multiplications, 76);
        assert_eq!(shape.num_constraints, 152);

        Simulator::simulate((x, z), |dr, witness| {
            let (x, z) = witness.cast();
            let x = Element::alloc(dr, x)?;
            let z = Element::alloc(dr, z)?;

            dr.reset();
            dr.routine(evaluator.clone(), (x, z))?;

            assert_eq!(dr.num_allocations(), 0);
            assert_eq!(dr.num_multiplications(), shape.num_multiplications);
            assert_eq!(dr.num_linear_constraints(), shape.num_constraints);

            Ok(())
        })?;

        Ok(())
    }
}

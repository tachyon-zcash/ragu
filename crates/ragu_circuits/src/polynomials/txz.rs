//! In-circuit evaluation of the gate polynomial
//! $$t(x, z) = -\sum_{i=0}^{n - 1} x^{4n - 1 - i} (z^{2n - 1 - i} + z^{2n + i})$$
//! as a [`Routine`].

use core::marker::PhantomData;

use ragu_arithmetic::{ff::Field, geosum};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
    routines::{Prediction, Routine},
};
use ragu_primitives::{Element, Invertible};

use super::Rank;

/// [`Routine`] evaluating $t(x, z)$ at rank `R`.
///
/// Takes $x$ and $z$ as [`Invertible`]s so the inversion is performed by the
/// caller, where $x^{-1}$ and $z^{-1}$ can be shared with other code that needs
/// them.
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
    /// Creates the routine.
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<F: Field, R: Rank> Routine<F> for Evaluate<R> {
    type Input = Kind![F; (Invertible<'_, _>, Invertible<'_, _>)];
    type Output = Kind![F; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let (x, z) = input;

        let mut xn = x.element().clone();
        for _ in 0..R::log2_n() {
            xn = xn.square(dr)?;
        }
        let x2n = xn.square(dr)?;
        let x4n = x2n.square(dr)?;
        let mut zn = z.element().clone();
        for _ in 0..R::log2_n() {
            zn = zn.square(dr)?;
        }
        let z2n = zn.square(dr)?;

        let x4n_minus_1 = x4n.mul(dr, x.inverse())?;
        let mut l = x4n_minus_1.mul(dr, &z2n)?.into_inner();
        let mut r = l.clone();
        let mut xz_step = x.inverse().mul(dr, z.element())?;
        let mut xzinv_step = x.inverse().mul(dr, z.inverse())?;
        for _ in 0..R::log2_n() {
            let l_mul = l.mul(dr, &xz_step)?;
            l = l.add(dr, &l_mul);
            let r_mul = r.mul(dr, &xzinv_step)?;
            r = r.add(dr, &r_mul);
            xz_step = xz_step.square(dr)?;
            xzinv_step = xzinv_step.square(dr)?;
        }
        let r_zinv = r.mul(dr, z.inverse())?;
        let sum = l.add(dr, &r_zinv);
        Ok(sum.negate(dr))
    }

    fn predict<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        let n = 1u64 << R::log2_n();

        let output = Element::alloc(
            dr,
            &mut (),
            D::just(|| {
                let x = *input.0.element().value().take();
                let z = *input.1.element().value().take();
                let x_inv = *input.0.inverse().value().take();
                let z_inv = *input.1.inverse().value().take();

                // Splitting $(z^{2n - 1 - i} + z^{2n + i})$ gives two geometric
                // sums sharing the prefactor $l_0 = x^{4n - 1} z^{2n}$; the
                // first picks up an extra $z^{-1}$, applied below.
                let l0 = x.pow([4 * n - 1]) * z.pow([2 * n]);
                let l = l0 * geosum(x_inv * z, n as usize);
                let r = l0 * geosum(x_inv * z_inv, n as usize);

                -(l + r * z_inv)
            }),
        )?;

        Ok(Prediction::Known(output, D::unit()))
    }
}

#[cfg(test)]
mod tests {
    use ragu_pasta::Fp;
    use ragu_primitives::Simulator;

    use super::*;
    use crate::polynomials::ProductionRank;

    #[test]
    fn simulate_txz() -> Result<()> {
        // ProductionRank (R<13>) has log2_n = 11
        type TestRank = ProductionRank;

        let x = Fp::random(&mut ragu_arithmetic::rand::rng());
        let z = Fp::random(&mut ragu_arithmetic::rand::rng());
        let evaluator = Evaluate::<TestRank>::new();

        Simulator::simulate((x, z), |dr, witness| {
            let (x, z) = witness.cast();
            let x = Invertible::alloc(dr, x)?;
            let z = Invertible::alloc(dr, z)?;

            dr.reset();
            dr.routine(evaluator.clone(), (x, z))?;
            assert_eq!(dr.num_gates(), 74);
            assert_eq!(dr.num_constraints(), 148);

            Ok(())
        })?;

        Ok(())
    }
}

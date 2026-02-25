//! Test fixtures for ragu_circuits tests and benchmarks.
//!
//! This module provides reusable circuit implementations for testing and benchmarking.
//!
//! - [`MySimpleCircuit`]: Proves knowledge of a and b such that a^5 = b^2 and outputs c = a+b, d = a-b.
//! - [`SquareCircuit`]: Parameterized circuit that squares an input `times` times.
//! - [`HeavyRoutineCircuit`]: Circuit using routines for memoization benchmarks.

use ff::Field;
use ragu_circuits::Circuit;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue, LinearExpression},
    gadgets::{Bound, Kind},
    maybe::Maybe,
    routines::{Prediction, Routine},
};
use ragu_primitives::Element;

/// A simple circuit that proves knowledge of a and b such that a^5 = b^2
/// and a + b = c and a - b = d where c and d are public inputs.
pub struct MySimpleCircuit;

impl<F: Field> Circuit<F> for MySimpleCircuit {
    type Instance<'instance> = (F, F); // Public inputs: c and d
    type Output = Kind![F; (Element<'_, _>, Element<'_, _>)];
    type Witness<'witness> = (F, F); // Witness: a and b
    type Aux<'witness> = ();

    fn instance<'dr, 'instance: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'instance>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let c = Element::alloc(dr, instance.view().map(|v| v.0))?;
        let d = Element::alloc(dr, instance.view().map(|v| v.1))?;

        Ok((c, d))
    }

    fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'witness>>,
    ) -> Result<(
        Bound<'dr, D, Self::Output>,
        DriverValue<D, Self::Aux<'witness>>,
    )> {
        let a = Element::alloc(dr, witness.view().map(|w| w.0))?;
        let b = Element::alloc(dr, witness.view().map(|w| w.1))?;

        let a2 = a.square(dr)?;
        let a4 = a2.square(dr)?;
        let a5 = a4.mul(dr, &a)?;

        let b2 = b.square(dr)?;

        dr.enforce_zero(|lc| lc.add(a5.wire()).sub(b2.wire()))?;

        let c = a.add(dr, &b);
        let d = a.sub(dr, &b);

        Ok(((c, d), D::just(|| ())))
    }
}

/// A parameterized circuit that squares an input element a configurable number of times.
///
/// Given witness `w`, this circuit computes `w^(2^times)` and returns it as output.
/// The number of multiplication constraints is equal to `times`.
pub struct SquareCircuit {
    /// The number of times to square the input.
    pub times: usize,
}

impl<F: Field> Circuit<F> for SquareCircuit {
    type Instance<'instance> = F;
    type Output = Kind![F; Element<'_, _>];
    type Witness<'witness> = F;
    type Aux<'witness> = ();

    fn instance<'dr, 'instance: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'instance>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, instance)
    }

    fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'witness>>,
    ) -> Result<(
        Bound<'dr, D, Self::Output>,
        DriverValue<D, Self::Aux<'witness>>,
    )> {
        let mut a = Element::alloc(dr, witness)?;

        for _ in 0..self.times {
            a = a.square(dr)?;
        }

        Ok((a, D::just(|| ())))
    }
}

/// A routine that performs repeated squaring for memoization benchmarks.
///
/// This routine is intentionally "heavy" to make memoization savings visible.
#[derive(Clone)]
pub struct HeavyRoutine {
    /// Number of squaring iterations per routine call.
    pub iterations: usize,
}

impl<F: Field> Routine<F> for HeavyRoutine {
    type Input = Kind![F; Element<'_, _>];
    type Output = Kind![F; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let mut a = input;
        for _ in 0..self.iterations {
            a = a.square(dr)?;
        }
        Ok(a)
    }

    fn predict<'dr, D: Driver<'dr, F = F>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

/// A circuit that invokes heavy routines for memoization benchmarks.
///
/// Uses 8 calls to [`HeavyRoutine`] to exercise inter-circuit memoization.
pub struct HeavyRoutineCircuit {
    /// Number of routine calls.
    pub num_calls: usize,
    /// Number of squaring iterations per routine call.
    pub iterations_per_call: usize,
}

impl<F: Field> Circuit<F> for HeavyRoutineCircuit {
    type Instance<'instance> = F;
    type Output = Kind![F; Element<'_, _>];
    type Witness<'witness> = F;
    type Aux<'witness> = ();

    fn instance<'dr, 'instance: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'instance>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, instance)
    }

    fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'witness>>,
    ) -> Result<(
        Bound<'dr, D, Self::Output>,
        DriverValue<D, Self::Aux<'witness>>,
    )> {
        let routine = HeavyRoutine {
            iterations: self.iterations_per_call,
        };

        let mut a = Element::alloc(dr, witness)?;

        for _ in 0..self.num_calls {
            a = dr.routine(routine.clone(), a)?;
        }

        Ok((a, D::just(|| ())))
    }
}

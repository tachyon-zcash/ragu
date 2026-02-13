//! Circuit constraint analysis and metrics collection.
//!
//! This module provides constraint system analysis by simulating circuit
//! execution without computing actual values, counting the number of
//! multiplication and linear constraints a circuit requires.

use ff::Field;
use ragu_arithmetic::Coeff;
use ragu_core::{
    Result,
    drivers::{Driver, DriverTypes, emulator::Emulator},
    gadgets::GadgetKind,
    maybe::Empty,
    routines::{Routine, RoutineShape},
};
use ragu_primitives::GadgetExt;

use core::marker::PhantomData;

use super::{Circuit, FreshB};

/// Performs full constraint system analysis, capturing basic details about a circuit's topology through simulation.
pub struct CircuitMetrics {
    /// The number of linear constraints, including those for public inputs.
    pub num_linear_constraints: usize,

    /// The number of multiplication constraints, including those used for allocations.
    pub num_multiplication_constraints: usize,

    /// The degree of the public input polynomial.
    // TODO(ebfull): not sure if we'll need this later
    #[allow(dead_code)]
    pub degree_ky: usize,
}

/// A driver that counts multiplication and linear constraints without computing values.
///
/// Used internally for shape analysis of routines and circuits.
pub struct ShapeCounter<F> {
    available_b: bool,
    num_linear_constraints: usize,
    num_multiplication_constraints: usize,
    _marker: PhantomData<F>,
}

impl<F: Field> FreshB<bool> for ShapeCounter<F> {
    fn available_b(&mut self) -> &mut bool {
        &mut self.available_b
    }
}

impl<F: Field> DriverTypes for ShapeCounter<F> {
    type MaybeKind = Empty;
    type ImplField = F;
    type ImplWire = ();
    type LCadd = ();
    type LCenforce = ();
}

impl<'dr, F: Field> Driver<'dr> for ShapeCounter<F> {
    type F = F;
    type Wire = ();
    const ONE: Self::Wire = ();

    fn alloc(&mut self, _: impl Fn() -> Result<Coeff<Self::F>>) -> Result<Self::Wire> {
        if self.available_b {
            self.available_b = false;
            Ok(())
        } else {
            self.available_b = true;
            self.mul(|| unreachable!())?;

            Ok(())
        }
    }

    fn mul(
        &mut self,
        _: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(Self::Wire, Self::Wire, Self::Wire)> {
        self.num_multiplication_constraints += 1;

        Ok(((), (), ()))
    }

    fn add(&mut self, _: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {}

    fn enforce_zero(&mut self, _: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        self.num_linear_constraints += 1;
        Ok(())
    }

    fn routine<Ro: Routine<Self::F> + 'dr>(
        &mut self,
        routine: Ro,
        input: <Ro::Input as GadgetKind<Self::F>>::Rebind<'dr, Self>,
    ) -> Result<<Ro::Output as GadgetKind<Self::F>>::Rebind<'dr, Self>> {
        self.with_fresh_b(|this| {
            let mut dummy = Emulator::wireless();
            let dummy_input = Ro::Input::map_gadget(&input, &mut dummy)?;
            let aux = routine.predict(&mut dummy, &dummy_input)?.into_aux();
            routine.execute(this, input, aux)
        })
    }
}

/// Derives the shape of a routine by running it through a constraint counter.
///
/// The closure should execute the routine logic. This is used internally
/// to determine routine shapes without exposing shape computation on the
/// `Routine` trait.
pub fn derive_shape<F: Field>(f: impl FnOnce(&mut ShapeCounter<F>)) -> RoutineShape {
    let mut counter = ShapeCounter {
        available_b: false,
        num_linear_constraints: 0,
        num_multiplication_constraints: 0,
        _marker: PhantomData,
    };
    f(&mut counter);
    RoutineShape::new(
        counter.num_multiplication_constraints,
        counter.num_linear_constraints,
    )
}

/// Evaluates a circuit to collect constraint metrics.
///
/// Runs the circuit through a counter driver to count multiplications
/// and linear constraints without computing actual values.
pub fn eval<F: Field, C: Circuit<F>>(circuit: &C) -> Result<CircuitMetrics> {
    let mut collector = ShapeCounter {
        available_b: false,
        num_linear_constraints: 0,
        num_multiplication_constraints: 0,
        _marker: PhantomData,
    };
    let mut degree_ky = 0usize;
    collector.mul(|| Ok((Coeff::One, Coeff::One, Coeff::One)))?;
    let (io, _) = circuit.witness(&mut collector, Empty)?;
    io.write(&mut collector, &mut degree_ky)?;

    Ok(CircuitMetrics {
        num_linear_constraints: collector.num_linear_constraints + degree_ky + 2,
        num_multiplication_constraints: collector.num_multiplication_constraints,
        degree_ky,
    })
}

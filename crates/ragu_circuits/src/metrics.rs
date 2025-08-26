use arithmetic::Coeff;
use ff::Field;
use ragu_core::{
    Result,
    drivers::{Driver, DriverTypes},
    maybe::Empty,
};
use ragu_primitives::GadgetExt;

use core::marker::PhantomData;

use crate::Circuit;

/// Contains basic details about a circuit that are computed by simulating it.
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

struct Counter<F> {
    available_b: bool,
    num_linear_constraints: usize,
    num_multiplication_constraints: usize,
    _marker: PhantomData<F>,
}

impl<F: Field> DriverTypes for Counter<F> {
    type MaybeKind = Empty;
    type ImplField = F;
    type ImplWire = ();
    type LCadd = ();
    type LCenforce = ();
}

impl<F: Field> Driver<'_> for Counter<F> {
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
}

pub fn eval<F: Field, C: Circuit<F>>(circuit: &C) -> Result<CircuitMetrics> {
    let mut collector = Counter {
        available_b: false,
        num_linear_constraints: 0,
        num_multiplication_constraints: 0,
        _marker: PhantomData,
    };
    let mut degree_ky = 0usize;
    collector.mul(|| Ok((Coeff::One, Coeff::One, Coeff::One)))?;
    let (io, _) = circuit.witness(&mut collector, Empty)?;
    io.serialize(&mut collector, &mut degree_ky)?;

    Ok(CircuitMetrics {
        num_linear_constraints: collector.num_linear_constraints + degree_ky + 1,
        num_multiplication_constraints: collector.num_multiplication_constraints,
        degree_ky,
    })
}

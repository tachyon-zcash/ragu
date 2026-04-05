//! Simulation driver for testing and constraint verification.
//!
//! Provides a [`Simulator`] driver that fully executes circuit synthesis,
//! tracking constraint counts and enforcing constraint satisfaction.

use ff::Field;
use ragu_arithmetic::Coeff;
use ragu_core::{
    Error, Result,
    drivers::{DirectSum, Driver, DriverTypes, emulator::Emulator},
    gadgets::Bound,
    maybe::{Always, MaybeKind},
    routines::Routine,
};

/// A driver that fully simulates circuit synthesis, enforcing constraint
/// satisfaction and tracking allocation, gate, and constraint
/// counts. Primarily used for testing.
#[derive(Clone)]
pub struct Simulator<F: Field> {
    num_allocations: usize,
    num_gates: usize,
    num_constraints: usize,
    _marker: core::marker::PhantomData<F>,
}

impl<F: Field> Default for Simulator<F> {
    fn default() -> Self {
        Simulator::new()
    }
}

impl<F: Field> Simulator<F> {
    /// Creates a new `Simulator` driver.
    pub fn new() -> Self {
        Simulator {
            num_allocations: 0,
            num_gates: 0,
            num_constraints: 0,
            _marker: core::marker::PhantomData,
        }
    }

    /// Reset the metrics of the simulator.
    pub fn reset(&mut self) {
        self.num_allocations = 0;
        self.num_gates = 0;
        self.num_constraints = 0;
    }

    /// Returns the number of `alloc` calls made.
    pub fn num_allocations(&self) -> usize {
        self.num_allocations
    }

    /// Returns the number of gates (i.e., [`Driver::mul`] calls made).
    ///
    /// [`Driver::mul`]: ragu_core::drivers::Driver::mul
    pub fn num_gates(&self) -> usize {
        self.num_gates
    }

    /// Returns the number of constraints (i.e., [`Driver::enforce_zero`] calls made).
    ///
    /// [`Driver::enforce_zero`]: ragu_core::drivers::Driver::enforce_zero
    pub fn num_constraints(&self) -> usize {
        self.num_constraints
    }

    /// Execute the provided closure with a fresh `Simulator` driver.
    pub fn simulate<W: Send>(
        witness: W,
        f: impl FnOnce(&mut Self, Always<W>) -> Result<()>,
    ) -> Result<Self> {
        let mut dr = Self::new();
        let witness = Always::maybe_just(|| witness);
        f(&mut dr, witness)?;

        Ok(dr)
    }
}

impl<F: Field> DriverTypes for Simulator<F> {
    type ImplField = F;
    type ImplWire = F;
    type MaybeKind = Always<()>;
    type LCadd = DirectSum<F>;
    type LCenforce = DirectSum<F>;

    fn gate(
        &mut self,
        values: impl Fn() -> Result<(
            Coeff<Self::ImplField>,
            Coeff<Self::ImplField>,
            Coeff<Self::ImplField>,
            Coeff<Self::ImplField>,
        )>,
    ) -> Result<(
        Self::ImplWire,
        Self::ImplWire,
        Self::ImplWire,
        Self::ImplWire,
    )> {
        let (a, b, c, d) = values()?;

        let a = a.value();
        let b = b.value();
        let c = c.value();
        let d = d.value();

        if a * b != c {
            return Err(Error::InvalidWitness("gate check failed".into()));
        }

        if c * d != F::ZERO {
            return Err(Error::InvalidWitness("auxiliary constraint failed".into()));
        }

        self.num_gates += 1;
        Ok((a, b, c, d))
    }
}

impl<'dr, F: Field> Driver<'dr> for Simulator<F> {
    type F = F;
    type Wire = F;
    const ONE: Self::Wire = F::ONE;

    fn alloc(&mut self, value: impl Fn() -> Result<Coeff<Self::F>>) -> Result<F> {
        let value = value()?;
        self.num_allocations += 1;
        Ok(value.value())
    }

    fn constant(&mut self, value: Coeff<Self::F>) -> Self::Wire {
        value.value()
    }

    fn add(&mut self, lc: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {
        let lc = lc(DirectSum::default());
        lc.value()
    }

    fn enforce_zero(&mut self, lc: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        let lc = lc(DirectSum::default());

        if lc.value() != F::ZERO {
            return Err(Error::InvalidWitness("constraint failed".into()));
        }

        self.num_constraints += 1;
        Ok(())
    }

    fn routine<R: Routine<Self::F> + 'dr>(
        &mut self,
        routine: R,
        input: Bound<'dr, Self, R::Input>,
    ) -> Result<Bound<'dr, Self, R::Output>> {
        let aux = Emulator::predict(&routine, &input)?.into_aux();
        routine.execute(self, input, aux)
    }
}

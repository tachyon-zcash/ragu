use arithmetic::Coeff;
use ff::Field;
use ragu_core::{
    Error, Result,
    drivers::{DirectSum, Driver, DriverTypes},
    gadgets::{Gadget, GadgetKind},
    maybe::{Always, MaybeKind},
    routines::{Prediction, Routine},
};

/// A driver that fully simulates everything that happens during synthesis,
/// primarily for testing purposes.
#[derive(Clone)]
pub struct Simulator<F: Field> {
    num_allocations: usize,
    num_multiplications: usize,
    num_linear_constraints: usize,
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
            num_multiplications: 0,
            num_linear_constraints: 0,
            _marker: core::marker::PhantomData,
        }
    }

    /// Reset the metrics of the simulator.
    pub fn reset(&mut self) {
        self.num_allocations = 0;
        self.num_multiplications = 0;
        self.num_linear_constraints = 0;
    }

    /// Returns the number of `alloc` calls made.
    pub fn num_allocations(&self) -> usize {
        self.num_allocations
    }

    /// Returns the number of `mul` calls made.
    pub fn num_multiplications(&self) -> usize {
        self.num_multiplications
    }

    /// Returns the number of `enforce_zero` calls made.
    pub fn num_linear_constraints(&self) -> usize {
        self.num_linear_constraints
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

    fn mul(
        &mut self,
        values: impl Fn() -> Result<(Coeff<Self::F>, Coeff<Self::F>, Coeff<Self::F>)>,
    ) -> Result<(Self::Wire, Self::Wire, Self::Wire)> {
        let (a, b, c) = values()?;

        let a = a.value();
        let b = b.value();
        let c = c.value();

        if a * b != c {
            return Err(Error::InvalidWitness(
                "multiplication constraint failed".into(),
            ));
        }

        self.num_multiplications += 1;
        Ok((a, b, c))
    }

    fn add(&mut self, lc: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {
        let lc = lc(DirectSum::default());
        lc.value
    }

    fn enforce_zero(&mut self, lc: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        let lc = lc(DirectSum::default());
        self.num_linear_constraints += 1;

        if lc.value != F::ZERO {
            return Err(Error::InvalidWitness("linear constraint failed".into()));
        }

        Ok(())
    }

    fn routine<R: Routine<Self::F> + 'dr>(
        &mut self,
        routine: R,
        input: <R::Input as GadgetKind<Self::F>>::Rebind<'dr, Self>,
    ) -> Result<<R::Output as GadgetKind<Self::F>>::Rebind<'dr, Self>> {
        let mut tmp = self.clone();
        match routine.predict(&mut tmp, &input)? {
            Prediction::Known(output, aux) => {
                // Even if the output is known, we still need to execute the
                // routine to ensure consistency with the prediction.
                let expected = routine.execute(self, input, aux)?;
                // Assert equality without creating constraints in the main
                // simulator by running the check on a disposable clone.
                output.enforce_equal(&mut self.clone(), &expected)?;
                Ok(output)
            }
            Prediction::Unknown(aux) => routine.execute(self, input, aux),
        }
    }
}

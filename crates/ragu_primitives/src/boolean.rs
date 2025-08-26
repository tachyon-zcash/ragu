use arithmetic::Coeff;
use ff::{Field, PrimeField};
use ragu_core::{
    Result,
    drivers::{Driver, LinearExpression, Witness},
    gadgets::{Gadget, Kind},
    maybe::Maybe,
};

use alloc::{vec, vec::Vec};

use crate::{
    Element, GadgetExt,
    demoted::DemotedDriver,
    serialize::{Buffer, GadgetSerialize},
    util::InternalMaybe,
};

/// Represents a wire that is constrained to be zero or one, along with its
/// corresponding [`bool`] value.
#[derive(Gadget)]
pub struct Boolean<'dr, D: Driver<'dr>> {
    /// The wire that has a value of either `0` or `1`.
    #[ragu(wire)]
    wire: D::Wire,

    /// The witness value for the value of this boolean.
    #[ragu(witness)]
    value: Witness<D, bool>,
}

impl<'dr, D: Driver<'dr>> Boolean<'dr, D> {
    /// Allocates a boolean with the provided witness value.
    ///
    /// This costs one multiplication constraint and two linear constraints.
    pub fn alloc(dr: &mut D, value: Witness<D, bool>) -> Result<Self> {
        let (a, b, c) = dr.mul(|| {
            let value = value.coeff().take();
            Ok((value, value, value))
        })?;

        // enforces a = b  =>  c = a^2
        dr.enforce_equal(&a, &b)?;

        // enforces a = c  =>  a = a^2
        //                 =>  (a - 0) * (a - 1) = 0
        //                 =>  (a = 0) OR (a = 1)
        dr.enforce_equal(&a, &c)?;

        // NB: We can take any of the three wires we want.
        Ok(Boolean { value, wire: c })
    }

    /// Computes the NOT of this boolean. This is "free" in the circuit model.
    pub fn not(&self, dr: &mut D) -> Self {
        // The wire w is transformed into 1 - w, its logical NOT.
        let wire = dr.add(|lc| lc.add(&D::ONE).sub(self.wire()));
        let value = D::just(|| !self.value.snag());
        Boolean { wire, value }
    }

    /// Computes the AND of two booleans. This costs one multiplication
    /// constraint and two linear constraints.
    pub fn and(&self, dr: &mut D, other: &Self) -> Result<Self> {
        let result = D::just(|| self.value.snag() & other.value.snag());
        let (a, b, c) = dr.mul(|| {
            let a = self.value.coeff().take();
            let b = other.value.coeff().take();
            let c = result.coeff().take();
            Ok((a, b, c))
        })?;

        dr.enforce_equal(&a, self.wire())?;
        dr.enforce_equal(&b, other.wire())?;

        Ok(Boolean {
            value: result,
            wire: c,
        })
    }

    /// Returns the witness value of this boolean.
    pub fn value(&self) -> Witness<D, bool> {
        self.value.clone()
    }

    /// Returns the wire associated with this boolean.
    pub fn wire(&self) -> &D::Wire {
        &self.wire
    }

    /// Converts this boolean into an [`Element`].
    pub fn element(&self) -> Element<'dr, D> {
        Element::promote(self.wire.clone(), self.value().fe())
    }
}

impl<'dr, D: Driver<'dr>> Boolean<'dr, DemotedDriver<'dr, D>> {
    /// Promotes a demoted boolean.
    pub fn promote(&self, value: Witness<D, bool>) -> Boolean<'dr, D> {
        Boolean {
            value,
            wire: self.wire.clone(),
        }
    }
}

impl<F: Field> GadgetSerialize<F> for Kind![F; @Boolean<'_, _>] {
    fn serialize_gadget<'dr, D: Driver<'dr, F = F>, B: Buffer<'dr, D>>(
        this: &Boolean<'dr, D>,
        dr: &mut D,
        buf: &mut B,
    ) -> Result<()> {
        this.element().serialize(dr, buf)
    }
}

/// Packs boolean slices into values depending on the capacity of the prime
/// field to store data.
pub fn multipack<'dr, D: Driver<'dr, F: ff::PrimeField>>(
    dr: &mut D,
    bits: &[Boolean<'dr, D>],
) -> Result<Vec<Element<'dr, D>>> {
    let mut v = vec![];
    for chunk in bits.chunks(D::F::CAPACITY as usize) {
        let value = D::just(|| {
            // The witness value here is computed in an MSB-first add-and-double
            // algorithm for efficiency. This is different from the constraint
            // evaluation logic below, which is LSB-first. The reason is that
            // `LinearExpression` instances cannot always be efficiently scaled.
            // Instead, a `LinearExpression::gain` operation is used to scale
            // _future_ terms added to an expression.
            let mut value = D::F::ZERO;
            for bit in chunk.iter().rev() {
                value = value.double();
                if bit.value().take() {
                    value += D::F::ONE;
                }
            }
            value
        });

        let wire = dr.add(|mut lc| {
            for bit in chunk.iter() {
                lc = lc.add(bit.wire());
                lc = lc.gain(Coeff::Two);
            }
            lc
        });

        v.push(Element::promote(wire, value));
    }

    Ok(v)
}

#[test]
fn test_boolean_alloc() -> Result<()> {
    type F = ragu_pasta::Fp;
    type Simulator = ragu_core::drivers::Simulator<F>;

    let alloc = |bit: bool| {
        let sim = Simulator::simulate(bit, |dr, bit| {
            let allocated_bit = Boolean::alloc(dr, bit.clone())?;

            assert_eq!(allocated_bit.value().take(), bit.clone().take());
            assert_eq!(*allocated_bit.wire(), bit.fe().take());

            Ok(())
        })?;

        assert_eq!(sim.num_allocations(), 0);
        assert_eq!(sim.num_multiplications(), 1);
        assert_eq!(sim.num_linear_constraints(), 2);
        Ok(())
    };

    alloc(false)?;
    alloc(true)?;

    Ok(())
}

#[test]
fn test_multipack() -> Result<()> {
    use alloc::vec::Vec;

    type F = ragu_pasta::Fp;
    type Simulator = ragu_core::drivers::Simulator<F>;

    let bits = (0..1000).map(|i| i % 2 == 0).collect::<Vec<_>>();

    Simulator::simulate(bits, |dr, bits| {
        let bits = (0..1000)
            .map(|i| Boolean::alloc(dr, bits.view().map(|b| b[i])))
            .collect::<Result<Vec<_>>>()?;

        let vals = multipack(dr, &bits)?;
        assert_eq!(vals.len(), 4);

        for val in vals {
            assert_eq!(val.value().take(), val.wire());
        }

        Ok(())
    })?;

    Ok(())
}

#[test]
fn test_multipack_vector() -> Result<()> {
    use alloc::vec::Vec;

    type F = ragu_pasta::Fp;
    type Simulator = ragu_core::drivers::Simulator<F>;

    let bits = vec![false, true, true, false, true]; // 0b10110 = 22
    Simulator::simulate(bits, |dr, bits| {
        let mut bits = bits.map(|b| b.into_iter());
        let bits = (0..5)
            .map(|_| Boolean::alloc(dr, bits.view_mut().map(|v| v.next().unwrap())))
            .collect::<Result<Vec<_>>>()?;

        let vals = multipack(dr, &bits)?;
        assert_eq!(vals.len(), 1);
        assert_eq!(*vals[0].value().take(), F::from(22));
        assert_eq!(*vals[0].wire(), F::from(22));

        Ok(())
    })?;

    Ok(())
}

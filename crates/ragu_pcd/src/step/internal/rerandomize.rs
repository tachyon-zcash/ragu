//! Rerandomization step for PCDs.
//!
//! This is a simple step: it takes a header-carrying proof and folds it with the
//! application's cached seeded unit proof, producing the same header. To keep
//! the circuit identical no matter what the left header is, we use a _uniform_
//! encoding — which makes every left/output header slot, including the suffix,
//! a witness wire rather than a constant. The right header is the unit header
//! carried by the cached proof.
//!
//! The output proof's polynomials are copies of the left input proof's, which
//! the circuit holds equal at $\zeta$ slot by slot: the parent sees only
//! the output slots, so a copy alone would let a rerandomizing prover swap
//! the polynomial.
//!
//! That witnessed suffix is the one input suffix outside the bootstrap step
//! that a prover chooses, and so the one place a prover could try to
//! present the [`Dummy`] suffix and take the base case: the decompression
//! step witnesses its output's suffix, but its inputs are constants. Two
//! things stop it. The left input and output are the *same* wires, so the
//! output header is pinned equal to the input (no relabelling on the way
//! through); `test_rerandomize_consistency` pins that structurally. And the
//! right input is the constant unit header, so both inputs cannot be `Dummy`.
//! [`Encoded::new_uniform`] additionally constrains the witnessed suffix away
//! from `Dummy`.
//!
//! [`Dummy`]: crate::header::Dummy
//! [`Encoded::new_uniform`]: crate::step::Encoded::new_uniform

use core::marker::PhantomData;

use ragu_core::{
    Cycle, Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe,
};
use ragu_primitives::{GadgetExt, allocator::Standard};

use super::super::{Encoded, HeaderInput, Index, Oracles, Prepared, Step};
pub(crate) use crate::step::InternalStepIndex::Rerandomize as INTERNAL_ID;
use crate::{Header, header::NUM_ONLINE_FP_POLYS};

pub(crate) struct Rerandomize<H> {
    _marker: PhantomData<H>,
}

impl<H> Rerandomize<H> {
    pub fn new() -> Self {
        Rerandomize {
            _marker: PhantomData,
        }
    }
}

impl<C: Cycle, H: Header<C::CircuitField>> Step<C> for Rerandomize<H> {
    const INDEX: Index = Index::internal(INTERNAL_ID);

    type Witness<'source> = ();
    type Aux<'source> = ();

    type Left = H;
    type Right = ();
    type Output = H;

    /// The output carries copies of the left input's polynomials, every
    /// slot's, whatever the header names. A copy here is prover data, not
    /// a constraint: the parent sees only the output slots, so
    /// [`witness`](Step::witness) proves each output polynomial equals the
    /// left one at $\zeta$.
    fn prepare<'source>(
        &self,
        _: &Self::Witness<'source>,
        left: HeaderInput<'_, C::CircuitField, H>,
        _: HeaderInput<'_, C::CircuitField, ()>,
    ) -> Result<Prepared<C::CircuitField, H>> {
        Ok(Prepared::from_polynomials(left.polynomials().clone()))
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D, C, Self>,
        _: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, H::Data>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )> {
        let allocator = &mut Standard::new();

        // Uniform encoding keeps this circuit identical across left header
        // types and constrains the witnessed suffix away from `Dummy` (see
        // `Encoded::new_uniform`). The output reuses the left input's wires;
        // the right input is the standard unit encoding carried by the cached
        // seeded proof.
        let left_encoded = Encoded::new_uniform(dr, allocator, left.clone())?;
        let right_encoded = Encoded::new(dr, allocator, right)?;

        // The output polynomials are the left input's: open both slots of
        // each at zeta and hold them equal. The right input's slots, the
        // unit header's, go unqueried.
        let zeta = oracles.zeta().clone();
        for i in 0..NUM_ONLINE_FP_POLYS {
            let left = oracles.left_at(i).open(dr, &zeta)?;
            let output = oracles.output_at(i).open(dr, &zeta)?;
            output.enforce_equal(dr, &left)?;
        }

        // TODO(ebfull): It's possible that the witness for this step needs to
        // be populated with some random data, for actual re-randomization
        // (zero-knowledge), though it's not certain at this stage in
        // development. Note that random wires here would only randomize this
        // step's own application polynomial, which is already blinded; the
        // folded accumulator of the resulting proof is a deterministic function
        // of the input proof, cached seeded proof, and public challenges, so
        // hiding it would need a fold-level randomizer claim rather than extra
        // witness here.

        // Return left's data as the output data - this preserves it!
        Ok((
            (left_encoded.clone(), right_encoded, left_encoded),
            left,
            D::unit(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rerandomize_consistency() {
        use ragu_circuits::polynomials;
        use ragu_core::{
            Result,
            drivers::{Driver, DriverValue},
            gadgets::{Bound, Kind},
            maybe::Maybe,
            pasta::{Fp, Pasta},
        };
        use ragu_primitives::{Element, allocator::Allocator};
        use ragu_testing::registry::TestRegistryBuilder;

        use crate::header::{Header, Padding, Suffix};

        const HEADER_SIZE: usize = 4;
        type R = polynomials::TestRank;

        struct Single;
        impl Header<Fp> for Single {
            const SUFFIX: Suffix = Suffix::new(0);
            type OnlinePolyCommit = (Padding, Padding);
            type Data = Fp;
            type Output = Kind![Fp; Element<'_, _>];
            fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
                dr: &mut D,
                allocator: &mut A,
                witness: DriverValue<D, Self::Data>,
            ) -> Result<Bound<'dr, D, Self::Output>> {
                Element::alloc(dr, allocator, witness)
            }
        }

        struct Pair;
        impl Header<Fp> for Pair {
            const SUFFIX: Suffix = Suffix::new(1);
            type OnlinePolyCommit = (Padding, Padding);
            type Data = (Fp, Fp);
            type Output = Kind![Fp; (Element<'_, _>, Element<'_, _>)];
            fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
                dr: &mut D,
                allocator: &mut A,
                witness: DriverValue<D, Self::Data>,
            ) -> Result<Bound<'dr, D, Self::Output>> {
                let (a, b) = witness.cast();
                let a = Element::alloc(dr, allocator, a)?;
                let b = Element::alloc(dr, allocator, b)?;

                Ok((a, b))
            }
        }

        let circuit_single =
            super::super::adapter::Adapter::<Pasta, Rerandomize<Single>, R, HEADER_SIZE>::new(
                Rerandomize::new(),
            );
        let circuit_pair =
            super::super::adapter::Adapter::<Pasta, Rerandomize<Pair>, R, HEADER_SIZE>::new(
                Rerandomize::new(),
            );

        // `Rerandomize<()>` is the instantiation `finalize` actually registers.
        let circuit_unit =
            super::super::adapter::Adapter::<Pasta, Rerandomize<()>, R, HEADER_SIZE>::new(
                Rerandomize::new(),
            );

        // A frozen twin of `Rerandomize`, written from primitives: one uniform
        // wire set shared by the left input and output, plus the standard unit
        // encoding for the right input. `Rerandomize` must stay
        // wiring-identical to this; separately encoding the output would let a
        // prover relabel the header on the way through.
        struct UnitRight;
        impl Step<Pasta> for UnitRight {
            const INDEX: Index = Index::internal(INTERNAL_ID);
            type Witness<'source> = ();
            type Aux<'source> = ();
            type Left = ();
            type Right = ();
            type Output = ();
            fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
                &self,
                dr: &mut D,
                oracles: &mut Oracles<'_, 'dr, D, Pasta, Self>,
                _: DriverValue<D, ()>,
                left: DriverValue<D, ()>,
                right: DriverValue<D, ()>,
            ) -> Result<(
                (
                    Encoded<'dr, D, (), HS>,
                    Encoded<'dr, D, (), HS>,
                    Encoded<'dr, D, (), HS>,
                ),
                DriverValue<D, ()>,
                DriverValue<D, ()>,
            )> {
                let allocator = &mut ragu_primitives::allocator::Standard::new();
                let left_encoded =
                    Encoded::<'dr, D, (), HS>::new_uniform(dr, allocator, left.clone())?;
                let right_encoded = Encoded::<'dr, D, (), HS>::new(dr, allocator, right)?;
                let zeta = oracles.zeta().clone();
                for i in 0..NUM_ONLINE_FP_POLYS {
                    let left = oracles.left_at(i).open(dr, &zeta)?;
                    let output = oracles.output_at(i).open(dr, &zeta)?;
                    output.enforce_equal(dr, &left)?;
                }
                Ok((
                    (left_encoded.clone(), right_encoded, left_encoded),
                    left,
                    D::unit(),
                ))
            }
        }
        let circuit_twin =
            super::super::adapter::Adapter::<Pasta, UnitRight, R, HEADER_SIZE>::new(UnitRight);

        let mut builder: TestRegistryBuilder<'_, _, R> = TestRegistryBuilder::new();
        let single_h = builder.register_circuit(circuit_single).unwrap();
        let pair_h = builder.register_circuit(circuit_pair).unwrap();
        let unit_h = builder.register_circuit(circuit_unit).unwrap();
        let twin_h = builder.register_circuit(circuit_twin).unwrap();
        let registry = builder.finalize().unwrap();

        let x = Fp::from(5u64);
        let y = Fp::from(17u64);

        assert_eq!(registry.xy(single_h, x, y), registry.xy(pair_h, x, y));
        assert_eq!(registry.xy(single_h, x, y), registry.xy(unit_h, x, y));
        assert_eq!(
            registry.xy(unit_h, x, y),
            registry.xy(twin_h, x, y),
            "Rerandomize must share its left/output wire set and use a standard unit right header"
        );
    }
}

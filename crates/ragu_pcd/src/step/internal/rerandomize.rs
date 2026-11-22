//! Rerandomization step for PCDs.
//!
//! This step folds a header-carrying proof with the application's bootstrap
//! proof. Ordinary rerandomization preserves the header and online polynomials.
//! Publication advances the suffix one reserved range and outputs two constant
//! one polynomials. The same circuit handles both modes and all header types.
//! Its uniform encoding makes the header fields witness wires; the output
//! shares the input's data wires and adds a Boolean-gated suffix offset.
//!
//! The step's circuit hides nothing by itself: its witness is the header,
//! which the output shows. What keeps the output from revealing its input
//! is the fuse around the step, run twice (see
//! [`Application::rerandomize`](crate::Application::rerandomize)).
//!
//! At $\zeta$, the circuit holds each output polynomial equal to the left
//! input's in ordinary mode or to one in publication mode. The suffix
//! difference binds the mode to the public input and output headers.
//!
//! A witnessed input suffix could try to present [`Dummy`] and take the base
//! case. [`Encoded::new_uniform`] constrains it away from `Dummy` and zero,
//! and the right input has the constant unit suffix, so both inputs cannot be
//! `Dummy`. A publication suffix cannot be made by an application step.
//!
//! [`Dummy`]: crate::header::Dummy
//! [`Encoded::new_uniform`]: crate::step::Encoded::new_uniform

use core::marker::PhantomData;

use ragu_core::{
    Coeff, Cycle, Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe,
};
use ragu_primitives::{Element, GadgetExt, allocator::Standard};

use super::super::{Encoded, HeaderInput, Index, Oracles, Prepared, Step};
pub(crate) use crate::step::InternalStepIndex::Rerandomize as INTERNAL_ID;
use crate::{
    Header,
    header::{NUM_ONLINE_FP_POLYS, PUBLICATION_OFFSET},
};

pub(crate) struct Rerandomize<H, O = H, const ADVANCE: bool = false> {
    _marker: PhantomData<(H, O)>,
}

impl<H, O, const ADVANCE: bool> Rerandomize<H, O, ADVANCE> {
    pub fn new() -> Self {
        Rerandomize {
            _marker: PhantomData,
        }
    }
}

impl<
    C: Cycle,
    H: Header<C::CircuitField>,
    O: Header<C::CircuitField, Data = H::Data>,
    const ADVANCE: bool,
> Step<C> for Rerandomize<H, O, ADVANCE>
{
    const INDEX: Index = Index::internal(INTERNAL_ID);

    type Witness<'source> = ();
    type Aux<'source> = ();

    type Left = H;
    type Right = ();
    type Output = O;

    /// Ordinary mode copies the left input's polynomials. Publication mode
    /// prepares constant one in each output slot. The circuit checks both
    /// modes at $\zeta$.
    fn prepare<'source>(
        &self,
        _: &Self::Witness<'source>,
        left: HeaderInput<'_, C::CircuitField, H>,
        _: HeaderInput<'_, C::CircuitField, ()>,
    ) -> Result<Prepared<C::CircuitField, O>> {
        if ADVANCE {
            Ok(Prepared::new())
        } else {
            Ok(Prepared::from_polynomials(left.polynomials().clone()))
        }
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
        // types and constrains the witnessed suffix away from `Dummy` and from
        // zero (see `Encoded::new_uniform`). The output reuses the left input's wires;
        // the right input is the standard unit encoding carried by the
        // bootstrap proof.
        let left_encoded = Encoded::new_uniform(dr, allocator, left.clone())?;
        let right_encoded = Encoded::new(dr, allocator, right)?;

        // The mode is a witness wire in both versions of this step. Its
        // Boolean constraint and the public suffix difference bind it to
        // zero for ordinary rerandomization or one for publication.
        let advance = Element::alloc(
            dr,
            &mut (),
            D::just(|| C::CircuitField::from(u64::from(ADVANCE))),
        )?;
        let advance_minus_one = advance.sub(dr, &Element::one());
        advance.mul(dr, &advance_minus_one)?.enforce_zero(dr)?;
        let suffix_offset = advance.scale(
            dr,
            Coeff::Arbitrary(C::CircuitField::from(PUBLICATION_OFFSET)),
        );
        let output_encoded = left_encoded.with_suffix_offset::<O>(dr, &suffix_offset);

        // Each output slot copies the left slot when mode is zero and is one
        // when mode is one. Both modes emit exactly the same circuit.
        let zeta = oracles.zeta().clone();
        for i in 0..NUM_ONLINE_FP_POLYS {
            let left = oracles.left_at(i).open(dr, &zeta)?;
            let output = oracles.output_at(i).open(dr, &zeta)?;
            let difference = Element::one().sub(dr, &left);
            let delta = advance.mul(dr, &difference)?;
            let expected = left.add(dr, &delta);
            output.enforce_equal(dr, &expected)?;
        }

        // Return left's data as the output data - this preserves it!
        Ok((
            (left_encoded, right_encoded, output_encoded),
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
        let circuit_publishing = super::super::adapter::Adapter::<
            Pasta,
            Rerandomize<Single, crate::header::Publishing<Single>, true>,
            R,
            HEADER_SIZE,
        >::new(Rerandomize::new());
        let circuit_published = super::super::adapter::Adapter::<
            Pasta,
            Rerandomize<crate::header::Publishing<Single>, crate::header::Published<Single>, true>,
            R,
            HEADER_SIZE,
        >::new(Rerandomize::new());

        let mut builder: TestRegistryBuilder<'_, _, R> = TestRegistryBuilder::new();
        let single_h = builder.register_circuit(circuit_single).unwrap();
        let pair_h = builder.register_circuit(circuit_pair).unwrap();
        let unit_h = builder.register_circuit(circuit_unit).unwrap();
        let publishing_h = builder.register_circuit(circuit_publishing).unwrap();
        let published_h = builder.register_circuit(circuit_published).unwrap();
        let registry = builder.finalize().unwrap();

        let x = Fp::from(5u64);
        let y = Fp::from(17u64);

        assert_eq!(registry.xy(single_h, x, y), registry.xy(pair_h, x, y));
        assert_eq!(registry.xy(single_h, x, y), registry.xy(unit_h, x, y));
        assert_eq!(registry.xy(unit_h, x, y), registry.xy(publishing_h, x, y));
        assert_eq!(registry.xy(unit_h, x, y), registry.xy(published_h, x, y));
    }
}

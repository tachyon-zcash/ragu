//! Rerandomization step for PCDs.
//!
//! This is a simple step: it takes any left header and combines it with the
//! trivial header `()` to produce the same left header. In order to ensure that
//! this rerandomization step synthesizes the same circuit no matter what the
//! left header is, we use a _uniform_ encoding of the left header.

use core::marker::PhantomData;

use ragu_arithmetic::Cycle;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe,
};
use ragu_primitives::allocator::Standard;

use super::super::{Encoded, Index, Step};
use crate::Header;
pub(crate) use crate::step::InternalStepIndex::Rerandomize as INTERNAL_ID;

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

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
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
        // Use uniform encoding for left to ensure circuit uniformity across header types
        let left_encoded = Encoded::new_uniform(dr, allocator, left.clone())?;
        // Use standard encoding for right (trivial header)
        let right = Encoded::new(dr, allocator, right)?;

        // TODO(ebfull): It's possible that the witness for this step needs to
        // be populated with some random data, for actual re-randomization
        // (zero-knowledge), though it's not certain at this stage in
        // development. It's possible some other component(s) of the proof being
        // randomized is sufficient, which would be nice since it would avoid
        // extra work here. It would also be complicated to add random wires
        // here if the amount of wires needed depended on HEADER_SIZE and R:
        // Rank, both of which are not in scope here.

        // Return left's data as the output data - this preserves it!
        Ok(((left_encoded.clone(), right, left_encoded), left, D::unit()))
    }
}

#[test]
fn test_rerandomize_consistency() {
    use ragu_circuits::polynomials;
    use ragu_core::{
        Result,
        drivers::{Driver, DriverValue},
        gadgets::{Bound, Kind},
        maybe::Maybe,
    };
    use ragu_pasta::{Fp, Pasta};
    use ragu_primitives::{Element, allocator::Allocator};
    use ragu_testing::registry::TestRegistryBuilder;

    use crate::header::{Header, Suffix};

    const HEADER_SIZE: usize = 4;
    type R = polynomials::TestRank;

    struct Single;
    impl Header<Fp> for Single {
        const SUFFIX: Suffix = Suffix::new(0);
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

    let circuit_single = super::adapter::Adapter::<Pasta, Rerandomize<Single>, R, HEADER_SIZE>::new(
        Rerandomize::new(),
    );
    let circuit_pair = super::adapter::Adapter::<Pasta, Rerandomize<Pair>, R, HEADER_SIZE>::new(
        Rerandomize::new(),
    );

    let mut builder: TestRegistryBuilder<'_, _, R> = TestRegistryBuilder::new();
    let single_h = builder.register_circuit(circuit_single).unwrap();
    let pair_h = builder.register_circuit(circuit_pair).unwrap();
    let registry = builder.finalize().unwrap();

    let x = Fp::from(5u64);
    let y = Fp::from(17u64);

    assert_eq!(registry.xy(single_h, x, y), registry.xy(pair_h, x, y),);
}

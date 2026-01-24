//! Rerandomization step for PCDs.
//!
//! This is a simple step: it takes any left header and combines it with the
//! trivial header `()` to produce the same left header. In order to ensure that
//! this rerandomization step synthesizes the same circuit no matter what the
//! left header is, we use a _uniform_ encoding of the left header.

use arithmetic::Cycle;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
};

use core::marker::PhantomData;

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
        left: DriverValue<D, H::Data<'source>>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, Self::Aux<'source>>,
    )> {
        // Use uniform encoding for left to ensure circuit uniformity across header types
        let left = Encoded::new_uniform(dr, left)?;
        // Use standard encoding for right (trivial header)
        let right = Encoded::new(dr, right)?;

        // TODO(ebfull): It's possible that the witness for this step needs to
        // be populated with some random data, for actual re-randomization
        // (zero-knowledge), though it's not certain at this stage in
        // development. It's possible some other component(s) of the proof being
        // randomized is sufficient, which would be nice since it would avoid
        // extra work here. It would also be complicated to add random wires
        // here if the amount of wires needed depended on HEADER_SIZE and R:
        // Rank, both of which are not in scope here.

        Ok(((left.clone(), right, left), D::just(|| ())))
    }
}

#[test]
fn test_rerandomize_consistency() {
    use crate::header::{Header, Suffix};
    use ragu_circuits::{CircuitExt, polynomials, registry};
    use ragu_core::{
        Result,
        drivers::{Driver, DriverValue},
        gadgets::{GadgetKind, Kind},
        maybe::Maybe,
    };
    use ragu_pasta::{Fp, Pasta};
    use ragu_primitives::Element;

    const HEADER_SIZE: usize = 4;
    type R = polynomials::R<8>;

    struct Single;
    impl Header<Fp> for Single {
        const SUFFIX: Suffix = Suffix::new(0);
        type Data<'source> = Fp;
        type Output = Kind![Fp; Element<'_, _>];
        fn encode<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            dr: &mut D,
            witness: DriverValue<D, Self::Data<'source>>,
        ) -> Result<<Self::Output as GadgetKind<Fp>>::Rebind<'dr, D>> {
            Element::alloc(dr, witness)
        }
    }

    struct Pair;
    impl Header<Fp> for Pair {
        const SUFFIX: Suffix = Suffix::new(1);
        type Data<'source> = (Fp, Fp);
        type Output = Kind![Fp; (Element<'_, _>, Element<'_, _>)];
        fn encode<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            dr: &mut D,
            witness: DriverValue<D, Self::Data<'source>>,
        ) -> Result<<Self::Output as GadgetKind<Fp>>::Rebind<'dr, D>> {
            let (a, b) = witness.cast();
            let a = Element::alloc(dr, a)?;
            let b = Element::alloc(dr, b)?;

            Ok((a, b))
        }
    }

    let circuit_single =
        super::adapter::Adapter::<Pasta, Rerandomize<Single>, R, HEADER_SIZE>::new(
            Rerandomize::new(),
        )
        .into_object::<R>()
        .unwrap();
    let circuit_pair = super::adapter::Adapter::<Pasta, Rerandomize<Pair>, R, HEADER_SIZE>::new(
        Rerandomize::new(),
    )
    .into_object::<R>()
    .unwrap();

    let x = Fp::from(5u64);
    let y = Fp::from(17u64);
    let key = registry::Key::default();

    let eval_single = circuit_single.sxy(x, y, &key);
    let eval_pair = circuit_pair.sxy(x, y, &key);

    assert_eq!(eval_single, eval_pair,);
}

//! Test fixture: a Step that opens a polynomial commitment and chains the
//! commitment into a Poseidon-hash digest of the previous step's hash.

use ff::Field;
use ragu_arithmetic::{CurveAffine, Cycle};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_pcd::{
    header::{Header, Suffix},
    poly_query::PolyQueryClaim,
    step::{Encoded, Index, Step},
};
use ragu_primitives::{
    Element, GadgetExt, Point,
    allocator::{Allocator, Standard},
    poseidon::Sponge,
};

pub struct HashedOpening;

impl<F: Field> Header<F> for HashedOpening {
    const SUFFIX: Suffix = Suffix::new(0);
    type Data = F;
    type Output = Kind![F; Element<'_, _>];

    fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, allocator, witness)
    }
}

pub struct OpenAndHash<'params, C: Cycle> {
    pub poseidon_params: &'params C::CircuitPoseidon,
}

pub struct OpenAndHashWitness<C: CurveAffine> {
    pub com: C,
    pub x: C::Base,
    pub y: C::Base,
}

impl<C: Cycle> Step<C> for OpenAndHash<'_, C> {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = OpenAndHashWitness<C::NestedCurve>;
    type Aux<'source> = ();
    type Left = HashedOpening;
    type Right = ();
    type Output = HashedOpening;

    fn witness<'dr, 'source: 'dr, D, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, C::CircuitField>,
        _right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
        Vec<PolyQueryClaim<'dr, D, C::NestedCurve>>,
    )>
    where
        D: Driver<'dr, F = C::CircuitField>,
        Self: 'dr,
    {
        let allocator = &mut Standard::new();

        let left = Encoded::new(dr, allocator, left)?;

        let com_witness = witness.as_ref().map(|w| w.com);
        let x_witness = witness.as_ref().map(|w| w.x);
        let y_witness = witness.as_ref().map(|w| w.y);

        let com = Point::alloc(dr, com_witness)?;
        let x = Element::alloc(dr, allocator, x_witness)?;
        let y = Element::alloc(dr, allocator, y_witness)?;

        let mut sponge = Sponge::new(dr, self.poseidon_params);
        sponge.absorb(dr, left.as_gadget())?;
        com.write(dr, &mut sponge)?;
        let output = sponge.squeeze(dr)?;
        let output_data = output.value().map(|v| *v);
        let output_encoded = Encoded::from_gadget(output);

        Ok((
            (left, Encoded::from_gadget(()), output_encoded),
            output_data,
            D::unit(),
            vec![PolyQueryClaim { com, x, y }],
        ))
    }
}

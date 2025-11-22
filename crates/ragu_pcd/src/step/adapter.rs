use arithmetic::Cycle;
use ragu_circuits::{Circuit, polynomials::Rank};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element,
    vec::{FixedVec, Len},
};

use alloc::vec::Vec;
use core::marker::PhantomData;

use super::{Encoder, Header, Step};

/// Represents triple a length determined at compile time.
pub struct TripleConstLen<const N: usize>;

impl<const N: usize> Len for TripleConstLen<N> {
    fn len() -> usize {
        N * 3
    }
}

pub(crate) struct Adapter<C, S, R, const HEADER_SIZE: usize> {
    step: S,
    _marker: PhantomData<(C, R)>,
}

impl<C: Cycle, S: Step<C>, R: Rank, const HEADER_SIZE: usize> Adapter<C, S, R, HEADER_SIZE> {
    pub fn new(step: S) -> Self {
        Adapter {
            step,
            _marker: PhantomData,
        }
    }
}

impl<C: Cycle, S: Step<C>, R: Rank, const HEADER_SIZE: usize> Circuit<C::CircuitField>
    for Adapter<C, S, R, HEADER_SIZE>
{
    type Instance<'source> = ();
    type Witness<'source> = (
        <S::Left as Header<C::CircuitField>>::Data<'source>,
        <S::Right as Header<C::CircuitField>>::Data<'source>,
        S::Witness<'source>,
    );
    type Output = Kind![C::CircuitField; FixedVec<Element<'_, _>, TripleConstLen<HEADER_SIZE>>];
    type Aux<'source> = (
        (Vec<C::CircuitField>, Vec<C::CircuitField>),
        S::Aux<'source>,
    );

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<<Self::Output as GadgetKind<C::CircuitField>>::Rebind<'dr, D>> {
        unreachable!("instance method is not used by the Adapter")
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<(
        <Self::Output as GadgetKind<C::CircuitField>>::Rebind<'dr, D>,
        DriverValue<D, Self::Aux<'source>>,
    )> {
        let (left, right, witness) = witness.cast();

        let left = Encoder::new(left);
        let right = Encoder::new(right);

        let ((left, right, output), aux) = self
            .step
            .witness::<_, HEADER_SIZE>(dr, witness, left, right)?;

        let mut elements = Vec::with_capacity(HEADER_SIZE * 3);
        output.write(dr, &mut elements)?;
        left.write(dr, &mut elements)?;
        right.write(dr, &mut elements)?;

        let aux = D::just(|| {
            let left_header = elements[HEADER_SIZE..HEADER_SIZE * 2]
                .iter()
                .map(|e| *e.value().take())
                .collect();

            let right_header = elements[HEADER_SIZE * 2..HEADER_SIZE * 3]
                .iter()
                .map(|e| *e.value().take())
                .collect();

            ((left_header, right_header), aux.take())
        });

        Ok((FixedVec::try_from(elements).expect("correct length"), aux))
    }
}

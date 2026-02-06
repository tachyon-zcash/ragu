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
    vec::{CollectFixed, ConstLen, FixedVec, Len},
};

use alloc::vec::Vec;
use core::marker::PhantomData;

use super::super::Step;
use crate::Header;

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
    type Instance<'source> = (
        FixedVec<C::CircuitField, ConstLen<HEADER_SIZE>>,
        FixedVec<C::CircuitField, ConstLen<HEADER_SIZE>>,
        <S::Output as Header<C::CircuitField>>::Data<'source>,
    );
    type Witness<'source> = (
        <S::Left as Header<C::CircuitField>>::Data<'source>,
        <S::Right as Header<C::CircuitField>>::Data<'source>,
        S::Witness<'source>,
    );
    type Output = Kind![C::CircuitField; FixedVec<Element<'_, _>, TripleConstLen<HEADER_SIZE>>];
    type Aux<'source> = (
        (
            FixedVec<C::CircuitField, ConstLen<HEADER_SIZE>>,
            FixedVec<C::CircuitField, ConstLen<HEADER_SIZE>>,
        ),
        S::Aux<'source>,
    );

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<<Self::Output as GadgetKind<C::CircuitField>>::Rebind<'dr, D>> {
        unreachable!("k(Y) is computed manually for ragu_pcd circuit implementations")
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<(
        <Self::Output as GadgetKind<C::CircuitField>>::Rebind<'dr, D>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let (left, right, witness) = witness.cast();

        let ((left, right, output), aux) = self
            .step
            .witness::<_, HEADER_SIZE>(dr, witness, left, right)?;

        let mut elements = Vec::with_capacity(HEADER_SIZE * 3);
        left.write(dr, &mut elements)?;
        right.write(dr, &mut elements)?;
        output.write(dr, &mut elements)?;

        let aux = D::with(|| {
            let left_header = elements[0..HEADER_SIZE]
                .iter()
                .map(|e| *e.value().take())
                .collect_fixed()?;

            let right_header = elements[HEADER_SIZE..HEADER_SIZE * 2]
                .iter()
                .map(|e| *e.value().take())
                .collect_fixed()?;

            Ok(((left_header, right_header), aux.take()))
        })?;

        Ok((FixedVec::try_from(elements)?, aux))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{Header, Suffix};
    use crate::step::{Encoded, Index, Step};
    use ragu_circuits::polynomials::R;
    use ragu_core::{
        drivers::emulator::Emulator,
        gadgets::Kind,
        maybe::{Always, Maybe, MaybeKind},
    };
    use ragu_pasta::{Fp, Pasta};

    type TestR = R<8>;
    const HEADER_SIZE: usize = 4;

    struct TestHeader;

    impl Header<Fp> for TestHeader {
        const SUFFIX: Suffix = Suffix::new(50);
        type Data<'source> = Fp;
        type Output = Kind![Fp; Element<'_, _>];

        fn encode<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            dr: &mut D,
            witness: DriverValue<D, Self::Data<'source>>,
        ) -> Result<<Self::Output as GadgetKind<Fp>>::Rebind<'dr, D>> {
            Element::alloc(dr, witness)
        }
    }

    struct TestStep;

    impl Step<Pasta> for TestStep {
        const INDEX: Index = Index::new(0);
        type Witness<'source> = ();
        type Aux<'source> = Fp;
        type Left = TestHeader;
        type Right = TestHeader;
        type Output = TestHeader;

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
            &self,
            dr: &mut D,
            _: DriverValue<D, ()>,
            left: DriverValue<D, Fp>,
            right: DriverValue<D, Fp>,
        ) -> Result<(
            (
                Encoded<'dr, D, Self::Left, HS>,
                Encoded<'dr, D, Self::Right, HS>,
                Encoded<'dr, D, Self::Output, HS>,
            ),
            DriverValue<D, Fp>,
        )> {
            // Allocate elements for left and right
            let left_elem = Element::alloc(dr, left)?;
            let right_elem = Element::alloc(dr, right)?;

            // Output is sum of left and right
            let output_elem = left_elem.add(dr, &right_elem);
            let output_val = output_elem.value().map(|v| *v);

            let left_enc = Encoded::from_gadget(left_elem);
            let right_enc = Encoded::from_gadget(right_elem);
            let output_enc = Encoded::from_gadget(output_elem);

            Ok(((left_enc, right_enc, output_enc), output_val))
        }
    }

    #[test]
    fn triple_const_len_returns_3n() {
        assert_eq!(TripleConstLen::<1>::len(), 3);
        assert_eq!(TripleConstLen::<4>::len(), 12);
        assert_eq!(TripleConstLen::<10>::len(), 30);
    }

    #[test]
    fn adapter_witness_produces_correct_output_size() {
        let mut dr = Emulator::execute();
        let dr = &mut dr;

        let adapter = Adapter::<Pasta, TestStep, TestR, HEADER_SIZE>::new(TestStep);
        let witness = Always::maybe_just(|| (Fp::from(10u64), Fp::from(20u64), ()));

        let (output, _aux) = adapter
            .witness(dr, witness)
            .expect("witness should succeed");

        // Output should have 3 * HEADER_SIZE elements (left + right + output headers)
        assert_eq!(output.len(), HEADER_SIZE * 3);
    }

    #[test]
    fn adapter_witness_extracts_aux_correctly() {
        let mut dr = Emulator::execute();
        let dr = &mut dr;

        let adapter = Adapter::<Pasta, TestStep, TestR, HEADER_SIZE>::new(TestStep);
        let witness = Always::maybe_just(|| (Fp::from(10u64), Fp::from(20u64), ()));

        let (_output, aux) = adapter
            .witness(dr, witness)
            .expect("witness should succeed");

        let ((left_header, right_header), step_aux) = aux.take();

        // Left header should start with 10
        assert_eq!(left_header[0], Fp::from(10u64));
        // Right header should start with 20
        assert_eq!(right_header[0], Fp::from(20u64));
        // Step aux should be 10 + 20 = 30
        assert_eq!(step_aux, Fp::from(30u64));
    }
}

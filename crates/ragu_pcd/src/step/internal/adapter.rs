use ragu_arithmetic::Cycle;
use ragu_circuits::{Circuit, WithAux, polynomials::Rank};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element,
    vec::{CollectFixed, FixedVec, Len},
};

use alloc::vec::Vec;
use core::marker::PhantomData;

use super::super::Step;
use crate::{Header, PcdConfig};

/// Represents triple a [`Len`] type.
pub struct TripleLen<L: Len>(PhantomData<L>);

impl<L: Len> Len for TripleLen<L> {
    fn len() -> usize {
        L::len() * 3
    }
}

pub(crate) struct Adapter<C, S, R, Cfg: PcdConfig> {
    step: S,
    _marker: PhantomData<(C, R, Cfg)>,
}

impl<C: Cycle, S: Step<C>, R: Rank, Cfg: PcdConfig> Adapter<C, S, R, Cfg> {
    pub fn new(step: S) -> Self {
        Adapter {
            step,
            _marker: PhantomData,
        }
    }
}

impl<C: Cycle, S: Step<C>, R: Rank, Cfg: PcdConfig> Circuit<C::CircuitField>
    for Adapter<C, S, R, Cfg>
{
    type Instance<'source> = (
        FixedVec<C::CircuitField, Cfg::HeaderSize>,
        FixedVec<C::CircuitField, Cfg::HeaderSize>,
        <S::Output as Header<C::CircuitField>>::Data,
    );
    type Witness<'source> = (
        <S::Left as Header<C::CircuitField>>::Data,
        <S::Right as Header<C::CircuitField>>::Data,
        S::Witness<'source>,
    );
    type Output = Kind![C::CircuitField; FixedVec<Element<'_, _>, TripleLen<Cfg::HeaderSize>>];
    type Aux<'source> = (
        (
            FixedVec<C::CircuitField, Cfg::HeaderSize>,
            FixedVec<C::CircuitField, Cfg::HeaderSize>,
        ),
        <S::Output as Header<C::CircuitField>>::Data,
        S::Aux<'source>,
    );

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        unreachable!("k(Y) is computed manually for ragu_pcd circuit implementations")
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        let header_size = Cfg::HeaderSize::len();
        let (left, right, witness) = witness.cast();

        let ((left, right, output), output_data, step_aux) = self
            .step
            .witness::<_, Cfg::HeaderSize>(dr, witness, left, right)?;

        let mut elements = Vec::with_capacity(header_size * 3);
        left.write(dr, &mut elements)?;
        right.write(dr, &mut elements)?;
        output.write(dr, &mut elements)?;

        let adapter_aux = D::try_just(|| {
            let left_header = elements[0..header_size]
                .iter()
                .map(|e| *e.value().take())
                .collect_fixed()?;

            let right_header = elements[header_size..header_size * 2]
                .iter()
                .map(|e| *e.value().take())
                .collect_fixed()?;

            Ok((
                (left_header, right_header),
                output_data.take(),
                step_aux.take(),
            ))
        })?;

        Ok(WithAux::new(FixedVec::try_from(elements)?, adapter_aux))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{Header, Suffix};
    use crate::step::{Encoded, Index, Step};
    use ragu_circuits::polynomials::TestRank;
    use ragu_core::{
        drivers::emulator::Emulator,
        gadgets::{Bound, Kind},
        maybe::{Always, Maybe, MaybeKind},
    };
    use ragu_pasta::{Fp, Pasta};
    use ragu_primitives::vec::ConstLen;

    type TestR = TestRank;
    type HS = ConstLen<4>;
    const HEADER_SIZE: usize = 4;

    struct TestCfg;
    impl PcdConfig for TestCfg { type HeaderSize = HS; }

    struct TestHeader;

    impl Header<Fp> for TestHeader {
        const SUFFIX: Suffix = Suffix::new(50);
        type Data = Fp;
        type Output = Kind![Fp; Element<'_, _>];

        fn encode<'dr, D: Driver<'dr, F = Fp>>(
            dr: &mut D,
            witness: DriverValue<D, Self::Data>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            Element::alloc(dr, witness)
        }
    }

    struct TestStep;

    impl Step<Pasta> for TestStep {
        const INDEX: Index = Index::new(0);
        type Witness<'source> = ();
        type Aux<'source> = ();
        type Left = TestHeader;
        type Right = TestHeader;
        type Output = TestHeader;

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, HeaderSize: Len>(
            &self,
            dr: &mut D,
            _: DriverValue<D, ()>,
            left: DriverValue<D, Fp>,
            right: DriverValue<D, Fp>,
        ) -> Result<(
            (
                Encoded<'dr, D, Self::Left, HeaderSize>,
                Encoded<'dr, D, Self::Right, HeaderSize>,
                Encoded<'dr, D, Self::Output, HeaderSize>,
            ),
            DriverValue<D, Fp>,
            DriverValue<D, ()>,
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

            Ok(((left_enc, right_enc, output_enc), output_val, D::unit()))
        }
    }

    #[test]
    fn triple_len_returns_3n() {
        assert_eq!(TripleLen::<ConstLen<1>>::len(), 3);
        assert_eq!(TripleLen::<ConstLen<4>>::len(), 12);
        assert_eq!(TripleLen::<ConstLen<10>>::len(), 30);
    }

    #[test]
    fn adapter_witness_produces_correct_output_size() {
        let mut dr = Emulator::execute();
        let dr = &mut dr;

        let adapter = Adapter::<Pasta, TestStep, TestR, TestCfg>::new(TestStep);
        let witness = Always::maybe_just(|| (Fp::from(10u64), Fp::from(20u64), ()));

        let output = adapter
            .witness(dr, witness)
            .expect("witness should succeed")
            .into_output();

        // Output should have 3 * HEADER_SIZE elements (left + right + output headers)
        assert_eq!(output.len(), HEADER_SIZE * 3);
    }

    #[test]
    fn adapter_witness_extracts_aux_correctly() {
        let mut dr = Emulator::execute();
        let dr = &mut dr;

        let adapter = Adapter::<Pasta, TestStep, TestR, TestCfg>::new(TestStep);
        let witness = Always::maybe_just(|| (Fp::from(10u64), Fp::from(20u64), ()));

        let aux = adapter
            .witness(dr, witness)
            .expect("witness should succeed")
            .into_aux();

        let ((left_header, right_header), output_data, _step_aux) = aux.take();

        // Left header should start with 10
        assert_eq!(left_header[0], Fp::from(10u64));
        // Right header should start with 20
        assert_eq!(right_header[0], Fp::from(20u64));
        // Step aux should be 10 + 20 = 30
        assert_eq!(output_data, Fp::from(30u64));
    }
}

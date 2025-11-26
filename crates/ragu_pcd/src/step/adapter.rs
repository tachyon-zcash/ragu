use arithmetic::Cycle;
use ragu_circuits::{Circuit, polynomials::Rank};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element, GadgetExt,
    vec::{ConstLen, FixedVec, Len},
};

use alloc::vec::Vec;
use core::marker::PhantomData;

use super::{Encoder, Header, Step, padded};

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
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<<Self::Output as GadgetKind<C::CircuitField>>::Rebind<'dr, D>> {
        let (left_header, right_header, output) = instance.cast();

        let output_gadget = S::Output::encode(dr, output)?;
        let output_gadget = padded::for_header::<S::Output, HEADER_SIZE, _>(dr, output_gadget)?;

        let mut elements = Vec::with_capacity(HEADER_SIZE * 3);
        output_gadget.write(dr, &mut elements)?;

        for i in 0..HEADER_SIZE {
            elements.push(Element::alloc(dr, D::just(|| left_header.snag()[i]))?);
        }

        for i in 0..HEADER_SIZE {
            elements.push(Element::alloc(dr, D::just(|| right_header.snag()[i]))?);
        }

        Ok(FixedVec::try_from(elements).expect("correct length"))
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
                .collect::<Vec<_>>();
            let left_header = FixedVec::try_from(left_header).expect("correct length");

            let right_header = elements[HEADER_SIZE * 2..HEADER_SIZE * 3]
                .iter()
                .map(|e| *e.value().take())
                .collect::<Vec<_>>();
            let right_header = FixedVec::try_from(right_header).expect("correct length");

            ((left_header, right_header), aux.take())
        });

        Ok((FixedVec::try_from(elements).expect("correct length"), aux))
    }
}

/// Test that k(Y) computed via witness path matches k(Y) computed via VerifyAdapter.
/// This ensures the polynomial identity check will work correctly.
#[test]
fn test_ky_consistency_witness_vs_verify_adapter() {
    use crate::header::{Header, Prefix};
    use ff::Field;
    use ragu_circuits::{CircuitExt, polynomials};
    use ragu_core::{
        Result,
        drivers::{Driver, DriverValue, emulator::Emulator},
        gadgets::{GadgetKind, Kind},
        maybe::{Always, Maybe, MaybeKind},
    };
    use ragu_pasta::{Fp, Pasta};

    use super::{Encoded, Encoder, Index, verify_adapter::VerifyAdapter};

    const HEADER_SIZE: usize = 4;
    type R = polynomials::R<8>;

    // Simple header that encodes a single field element
    struct SimpleHeader;
    impl Header<Fp> for SimpleHeader {
        const PREFIX: Prefix = Prefix::new(0);
        type Data<'source> = Fp;
        type Output = Kind![Fp; Element<'_, _>];
        fn encode<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            dr: &mut D,
            witness: DriverValue<D, Self::Data<'source>>,
        ) -> Result<<Self::Output as GadgetKind<Fp>>::Rebind<'dr, D>> {
            Element::alloc(dr, witness)
        }
    }

    // Simple step that takes trivial inputs and produces SimpleHeader output
    struct SimpleStep;
    impl Step<Pasta> for SimpleStep {
        const INDEX: Index = Index::new(0);
        type Witness<'source> = Fp;
        type Aux<'source> = Fp;
        type Left = ();
        type Right = ();
        type Output = SimpleHeader;

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, Self::Witness<'source>>,
            _left: Encoder<'dr, 'source, D, Self::Left, HS>,
            _right: Encoder<'dr, 'source, D, Self::Right, HS>,
        ) -> Result<(
            (
                Encoded<'dr, D, Self::Left, HS>,
                Encoded<'dr, D, Self::Right, HS>,
                Encoded<'dr, D, Self::Output, HS>,
            ),
            DriverValue<D, Self::Aux<'source>>,
        )>
        where
            Self: 'dr,
        {
            let output = Element::alloc(dr, witness.clone())?;
            let output_value = witness;

            Ok((
                (
                    Encoded::from_gadget(()),
                    Encoded::from_gadget(()),
                    Encoded::from_gadget(output),
                ),
                output_value,
            ))
        }
    }

    // Create adapter for SimpleStep
    let adapter = Adapter::<Pasta, SimpleStep, R, HEADER_SIZE>::new(SimpleStep);

    // Run witness synthesis
    let mut dr: Emulator<_> = Emulator::execute();
    let witness_value = Fp::from(42u64);
    let witness_data = ((), (), witness_value);

    let (elements, aux) = adapter
        .witness(&mut dr, Always::maybe_just(|| witness_data))
        .expect("witness should succeed");

    // Extract values from witness result
    let output_header: Vec<Fp> = elements.as_ref()[0..HEADER_SIZE]
        .iter()
        .map(|e| *e.value().take())
        .collect();
    let output_header =
        FixedVec::<_, ConstLen<HEADER_SIZE>>::try_from(output_header).expect("correct length");

    let ((left_header, right_header), output_data) = aux.take();

    // Compute k(Y) via witness path - manually construct what ky() would return
    let mut ky_witness: Vec<Fp> = output_header.as_ref().to_vec();
    ky_witness.extend(left_header.as_ref());
    ky_witness.extend(right_header.as_ref());
    ky_witness.push(Fp::ONE);
    ky_witness.reverse();

    // Compute k(Y) via VerifyAdapter
    let verify_adapter =
        Adapter::<Pasta, VerifyAdapter<SimpleHeader>, R, HEADER_SIZE>::new(VerifyAdapter::new());
    let instance = (left_header, right_header, output_data);
    let ky_verify = verify_adapter.ky(instance).expect("ky should succeed");

    // They should match
    assert_eq!(
        ky_witness, ky_verify,
        "k(Y) from witness path should match k(Y) from VerifyAdapter"
    );
}

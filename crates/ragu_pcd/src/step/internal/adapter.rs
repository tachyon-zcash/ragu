use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_circuits::{Circuit, WithAux, polynomials::Rank, staging};
use ragu_core::{
    Coeff, Cycle, Error, Result,
    convert::WireMap,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element,
    allocator::{Allocator, Standard},
    shared::Shared,
    vec::{CollectFixed, ConstLen, FixedVec, Len},
};

use super::super::Step;
use crate::Header;

/// Represents triple a length determined at compile time.
pub struct TripleConstLen<const N: usize>;

impl<const N: usize> Len for TripleConstLen<N> {
    fn len() -> usize {
        N * 3
    }
}

/// The circuit of an application [`Step`]: the step's constraints over the
/// proof's application stage, with the three headers as its public inputs.
///
/// The application stage occupies the first gates of every step circuit,
/// reserved by [`reserve_shared_stage`]: the step's own trace is zero there
/// and the committed stage polynomial supplies those wires, as for a staged
/// circuit. Its size is the largest [`Step::Shared`] layout registered in the
/// application, derived from every registered step before constructing the
/// circuits, so the block is reserved here rather than through a type-level
/// stage.
pub(crate) struct Adapter<C, S, R, const HEADER_SIZE: usize> {
    step: S,
    /// The application stage size, in field elements.
    shared_size: usize,
    _marker: PhantomData<(C, R)>,
}

impl<C: Cycle, S: Step<C>, R: Rank, const HEADER_SIZE: usize> Adapter<C, S, R, HEADER_SIZE> {
    /// The circuit of `step` over an application stage of `shared_size`
    /// elements.
    ///
    /// # Errors
    ///
    /// Returns an initialization error if the step's [`Step::Shared`] gadget
    /// has more wires than the stage holds; registration sizes the stage from
    /// every step, so this guards the prover's own calls.
    pub fn new(step: S, shared_size: usize) -> Result<Self> {
        if S::Shared::num_values()? > shared_size {
            return Err(Error::Initialization(
                "the step's shared gadget has more wires than the application stage holds".into(),
            ));
        }
        Ok(Adapter {
            step,
            shared_size,
            _marker: PhantomData,
        })
    }
}

/// Reserves the application stage's gates at the start of the circuit, as a
/// stage builder would, and returns its reserved wires.
///
/// The reserved wires are zero in the circuit's own trace; the committed
/// stage polynomial supplies their values, and the application final mask
/// holds the own trace to zero there. Every step circuit reserves the block,
/// including the internal bootstrap and rerandomization steps, so one pair of
/// masks covers every proof. See the cost note on
/// [`ApplicationBuilder::register`](crate::ApplicationBuilder::register) for
/// the gates this takes in each step.
///
/// Invariant: the adapter only binds the returned gadget to the block's `a`
/// and `d` wires. The final mask holds all four wire slots of each reserved
/// gate to zero in the step's own trace. The stage mask does not force the
/// block's `b` and `c` wires or an odd-sized stage's padding wire to zero in
/// the stage polynomial, so those wires must remain unexposed. The SYSTEM gate
/// is not part of the stage.
fn reserve_shared_stage<'dr, D: Driver<'dr>>(dr: &mut D, size: usize) -> Result<Vec<D::Wire>> {
    // Allocate whole gates, two wires each, so the step's own gates start
    // after the block; the padding wire of an odd-sized stage is unused.
    let allocator = &mut Standard::new();
    let mut shared = Vec::with_capacity(size);
    for i in 0..2 * staging::stage_gates(size) {
        let wire = allocator.alloc(dr, || Ok(Coeff::Zero))?;
        if i < size {
            shared.push(wire);
        }
    }
    Ok(shared)
}

/// Binds every actual gadget wire, independently of shared witness collection.
/// Neither omitted values nor incorrect cached element values can omit a
/// connecting constraint. No padding or multiplication wires are exposed.
pub(crate) fn bind_shared<'dr, D: Driver<'dr>, G: Gadget<'dr, D>>(
    dr: &mut D,
    gadget: &G,
    stage_wires: &[D::Wire],
) -> Result<()> {
    struct Binder<'a, 'dr, D: Driver<'dr>> {
        dr: &'a mut D,
        wires: core::slice::Iter<'a, D::Wire>,
    }

    impl<'dr, D: Driver<'dr>> WireMap<D::F> for Binder<'_, 'dr, D> {
        type Src = D;
        type Dst = PhantomData<D::F>;

        fn convert_wire(&mut self, wire: &D::Wire) -> Result<()> {
            let stage_wire = self.wires.next().ok_or_else(|| {
                Error::Initialization("the shared gadget has more wires than its layout".into())
            })?;
            self.dr.enforce_equal(wire, stage_wire)
        }
    }

    let mut binder = Binder {
        dr,
        wires: stage_wires.iter(),
    };
    G::Kind::map_gadget(gadget, &mut binder)?;
    if binder.wires.next().is_some() {
        return Err(Error::Initialization(
            "the shared gadget has fewer wires than its layout".into(),
        ));
    }
    Ok(())
}

impl<C: Cycle, S: Step<C>, R: Rank, const HEADER_SIZE: usize> Circuit<C::CircuitField>
    for Adapter<C, S, R, HEADER_SIZE>
{
    type Instance<'source> = (
        FixedVec<C::CircuitField, ConstLen<HEADER_SIZE>>,
        FixedVec<C::CircuitField, ConstLen<HEADER_SIZE>>,
        <S::Output as Header<C::CircuitField>>::Data,
    );
    type Witness<'source> = (
        <S::Left as Header<C::CircuitField>>::Data,
        <S::Right as Header<C::CircuitField>>::Data,
        S::Witness<'source>,
    );
    type Output = Kind![C::CircuitField; FixedVec<Element<'_, _>, TripleConstLen<HEADER_SIZE>>];
    type Aux<'source> = (
        (
            FixedVec<C::CircuitField, ConstLen<HEADER_SIZE>>,
            FixedVec<C::CircuitField, ConstLen<HEADER_SIZE>>,
        ),
        <S::Output as Header<C::CircuitField>>::Data,
        S::Aux<'source>,
        Vec<C::CircuitField>,
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
        let stage_wires = reserve_shared_stage(dr, self.shared_size)?;
        let (left, right, witness) = witness.cast();

        let ((left, right, output), shared, output_data, step_aux) = self
            .step
            .witness::<_, HEADER_SIZE>(dr, witness, left, right)?;

        let size = S::Shared::num_values()?;
        let wires = stage_wires.get(..size).ok_or_else(|| {
            Error::Initialization("the shared gadget exceeds the reserved layout".into())
        })?;
        bind_shared(dr, &shared, wires)?;
        let mut shared_values = Vec::with_capacity(size);
        S::Shared::write_shared(&shared, &mut shared_values)?;
        if shared_values.len() != size {
            return Err(Error::Initialization(
                "the shared gadget's witness count differs from its layout".into(),
            ));
        }

        let mut elements = Vec::with_capacity(HEADER_SIZE * 3);
        left.write(dr, &mut elements)?;
        right.write(dr, &mut elements)?;
        output.write(dr, &mut elements)?;

        let adapter_aux = D::try_just(|| {
            let left_header = elements[0..HEADER_SIZE]
                .iter()
                .map(|e| *e.value().take())
                .collect_fixed()?;

            let right_header = elements[HEADER_SIZE..HEADER_SIZE * 2]
                .iter()
                .map(|e| *e.value().take())
                .collect_fixed()?;

            Ok((
                (left_header, right_header),
                output_data.take(),
                step_aux.take(),
                shared_values.iter().map(|e| *e.value().take()).collect(),
            ))
        })?;

        Ok(WithAux::new(FixedVec::try_from(elements)?, adapter_aux))
    }
}

#[cfg(test)]
mod tests {
    use ragu_circuits::{CircuitExt, polynomials::TestRank};
    use ragu_core::{
        drivers::emulator::Emulator,
        gadgets::{Bound, Kind},
        maybe::{Always, Maybe, MaybeKind},
        pasta::{Fp, Pasta},
    };
    use ragu_primitives::allocator::{Allocator, Standard};

    use super::*;
    use crate::{
        header::{Header, Suffix},
        step::{Encoded, Index, Step},
    };

    type TestR = TestRank;
    const HEADER_SIZE: usize = 4;
    const SHARED_SIZE: usize = 2;

    struct TestHeader;

    impl Header<Fp> for TestHeader {
        const SUFFIX: Suffix = Suffix::new(50);
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

    struct TestStep;

    impl Step<Pasta> for TestStep {
        const INDEX: Index = Index::new(0);
        type Shared = ();
        type Witness<'source> = ();
        type Aux<'source> = ();
        type Left = TestHeader;
        type Right = TestHeader;
        type Output = TestHeader;

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
            &self,
            dr: &mut D,
            _witness: DriverValue<D, Self::Witness<'source>>,
            left: DriverValue<D, Fp>,
            right: DriverValue<D, Fp>,
        ) -> Result<(
            (
                Encoded<'dr, D, Self::Left, HS>,
                Encoded<'dr, D, Self::Right, HS>,
                Encoded<'dr, D, Self::Output, HS>,
            ),
            (),
            DriverValue<D, Fp>,
            DriverValue<D, ()>,
        )> {
            let allocator = &mut Standard::new();
            let left_elem = Element::alloc(dr, allocator, left)?;
            let right_elem = Element::alloc(dr, allocator, right)?;

            // Output = left + right
            let output_elem = left_elem.add(dr, &right_elem);
            let output_val = output_elem.value().map(|v| *v);

            let left_enc = Encoded::from_gadget(left_elem);
            let right_enc = Encoded::from_gadget(right_elem);
            let output_enc = Encoded::from_gadget(output_elem);

            Ok(((left_enc, right_enc, output_enc), (), output_val, D::unit()))
        }
    }

    #[derive(Gadget, Shared)]
    struct Pair<'dr, D: Driver<'dr>> {
        a: Element<'dr, D>,
        b: Element<'dr, D>,
    }

    /// A step whose output is the sum of its two staged circuit values.
    struct SharedSum;

    impl Step<Pasta> for SharedSum {
        const INDEX: Index = Index::new(1);
        type Shared = Kind![Fp; Pair<'_, _>];
        type Witness<'source> = [Fp; 2];
        type Aux<'source> = ();
        type Left = TestHeader;
        type Right = TestHeader;
        type Output = TestHeader;

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, Self::Witness<'source>>,
            left: DriverValue<D, Fp>,
            right: DriverValue<D, Fp>,
        ) -> Result<(
            (
                Encoded<'dr, D, Self::Left, HS>,
                Encoded<'dr, D, Self::Right, HS>,
                Encoded<'dr, D, Self::Output, HS>,
            ),
            Bound<'dr, D, Self::Shared>,
            DriverValue<D, Fp>,
            DriverValue<D, ()>,
        )> {
            let allocator = &mut Standard::new();
            let left = Element::alloc(dr, allocator, left)?;
            let right = Element::alloc(dr, allocator, right)?;
            let shared = Pair {
                a: Element::alloc(dr, allocator, witness.as_ref().map(|w| w[0]))?,
                b: Element::alloc(dr, allocator, witness.map(|w| w[1]))?,
            };
            let output = shared.a.add(dr, &shared.b);
            let value = output.value().map(|v| *v);
            Ok((
                (
                    Encoded::from_gadget(left),
                    Encoded::from_gadget(right),
                    Encoded::from_gadget(output),
                ),
                shared,
                value,
                D::unit(),
            ))
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

        let adapter =
            Adapter::<Pasta, TestStep, TestR, HEADER_SIZE>::new(TestStep, SHARED_SIZE).unwrap();
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

        let adapter =
            Adapter::<Pasta, TestStep, TestR, HEADER_SIZE>::new(TestStep, SHARED_SIZE).unwrap();
        let witness = Always::maybe_just(|| (Fp::from(10u64), Fp::from(20u64), ()));

        let aux = adapter
            .witness(dr, witness)
            .expect("witness should succeed")
            .into_aux();

        let ((left_header, right_header), output_data, _step_aux, shared) = aux.take();
        assert!(shared.is_empty());

        // Left header should start with 10
        assert_eq!(left_header[0], Fp::from(10u64));
        // Right header should start with 20
        assert_eq!(right_header[0], Fp::from(20u64));
        // Step aux should be 10 + 20 = 30
        assert_eq!(output_data, Fp::from(30u64));
    }

    /// The step returns its actual shared wires; the adapter exports their
    /// values and binds those wires to the stage's reserved wires.
    #[test]
    fn step_exports_its_shared_gadget() {
        let adapter =
            Adapter::<Pasta, SharedSum, TestR, HEADER_SIZE>::new(SharedSum, SHARED_SIZE).unwrap();
        let values = [Fp::from(3u64), Fp::from(4u64)];
        let (_, aux) = adapter
            .trace((Fp::from(10u64), Fp::from(20u64), values))
            .expect("trace")
            .into_parts();
        let (_, output_data, (), shared) = aux;
        assert_eq!(shared, values);
        assert_eq!(output_data, Fp::from(7u64));

        // A stage smaller than the step's gadget is refused.
        assert!(
            Adapter::<Pasta, SharedSum, TestR, HEADER_SIZE>::new(SharedSum, SHARED_SIZE - 1)
                .is_err()
        );
    }

    // Deliberately broken implementations exercise checks independently of
    // the derive macro: the actual gadget always contains two wires.
    #[derive(Gadget)]
    struct Malformed<'dr, D: Driver<'dr>, const SIZE: usize, const EXPORTS: usize> {
        a: Element<'dr, D>,
        b: Element<'dr, D>,
    }

    impl<F: udon::field::Field, const SIZE: usize, const EXPORTS: usize> Shared<F>
        for Malformed<'static, PhantomData<F>, SIZE, EXPORTS>
    {
        fn num_values() -> Result<usize> {
            Ok(SIZE)
        }
        fn write_shared<'dr, D: Driver<'dr, F = F>>(
            this: &Malformed<'dr, D, SIZE, EXPORTS>,
            values: &mut Vec<Element<'dr, D>>,
        ) -> Result<()> {
            values.extend([this.a.clone(), this.b.clone()].into_iter().take(EXPORTS));
            Ok(())
        }
    }

    struct MalformedStep<const SIZE: usize, const EXPORTS: usize>;

    impl<const SIZE: usize, const EXPORTS: usize> Step<Pasta> for MalformedStep<SIZE, EXPORTS> {
        const INDEX: Index = Index::new(1);
        type Shared = Kind![Fp; Malformed<'_, _, SIZE, EXPORTS>];
        type Witness<'source> = [Fp; 2];
        type Aux<'source> = ();
        type Left = TestHeader;
        type Right = TestHeader;
        type Output = TestHeader;

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, Self::Witness<'source>>,
            left: DriverValue<D, Fp>,
            right: DriverValue<D, Fp>,
        ) -> Result<(
            (
                Encoded<'dr, D, TestHeader, HS>,
                Encoded<'dr, D, TestHeader, HS>,
                Encoded<'dr, D, TestHeader, HS>,
            ),
            Bound<'dr, D, Self::Shared>,
            DriverValue<D, Fp>,
            DriverValue<D, ()>,
        )> {
            let (headers, shared, output, aux) =
                SharedSum.witness::<_, HS>(dr, witness, left, right)?;
            Ok((
                headers,
                Malformed {
                    a: shared.a,
                    b: shared.b,
                },
                output,
                aux,
            ))
        }
    }

    #[test]
    fn malformed_shared_schemas_cannot_omit_wire_bindings() {
        fn trace<const SIZE: usize, const EXPORTS: usize>() -> Result<()> {
            Adapter::<Pasta, MalformedStep<SIZE, EXPORTS>, TestR, HEADER_SIZE>::new(
                MalformedStep,
                3,
            )?
            .trace((Fp::from(10), Fp::from(20), [Fp::from(3), Fp::from(4)]))?;
            Ok(())
        }
        assert!(
            trace::<1, 1>().is_err(),
            "actual wire count exceeds declaration"
        );
        assert!(
            trace::<3, 2>().is_err(),
            "actual wire count is below declaration"
        );
        assert!(trace::<2, 1>().is_err(), "witness collection omits a wire");
        assert!(trace::<2, 2>().is_ok(), "honest control uses both wires");
    }

    /// Every step reserves the stage's gates, two values per gate, before
    /// its own; an empty stage reserves none.
    #[test]
    fn steps_reserve_the_stage_gates() {
        let counts = |size| {
            ragu_circuits::testing::synthesis_counts(
                &Adapter::<Pasta, TestStep, TestR, HEADER_SIZE>::new(TestStep, size).unwrap(),
            )
            .unwrap()
        };
        let unstaged = counts(0);
        for size in [1, 2, 3, 64, 257] {
            assert_eq!(
                counts(size).num_gates - unstaged.num_gates,
                size.div_ceil(2),
                "stage of {size} elements"
            );
        }
    }
}

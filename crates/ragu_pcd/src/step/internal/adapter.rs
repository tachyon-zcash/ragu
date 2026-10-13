use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_circuits::{Circuit, WithAux, polynomials::Rank, registry::CircuitIndex, staging};
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
use crate::{APPLICATION_SLOTS, Header};

/// The fixed bundle IDs followed by three padded headers.
pub struct InstanceLen<const N: usize>;

impl<const N: usize> Len for InstanceLen<N> {
    fn len() -> usize {
        APPLICATION_SLOTS + N * 3
    }
}

/// The circuit of an application [`Step`]: the fragment's constraints
/// over the proof's shared stage, with the registered bundle's IDs and the
/// three headers as its public inputs.
///
/// The shared stage occupies the first gates of a split bundle's circuits,
/// reserved by [`reserve_shared_stage`]: a fragment's own trace is zero there
/// and the stage polynomial supplies those wires, as for a staged circuit.
/// Its size is derived from every registered fragment before constructing
/// the circuits, so the block is reserved here rather than through a
/// type-level stage.
pub(crate) struct Adapter<C, S, R, const HEADER_SIZE: usize> {
    step: S,
    bundle: [CircuitIndex; APPLICATION_SLOTS],
    /// The bundle's shared stage size, zero for a standalone step.
    shared_size: usize,
    _marker: PhantomData<(C, R)>,
}

/// The witness of an [`Adapter`]: child data and the fragment's own witness.
pub(crate) type AdapterWitness<'source, C, S> = (
    <<S as Step<C>>::Left as Header<<C as Cycle>::CircuitField>>::Data,
    <<S as Step<C>>::Right as Header<<C as Cycle>::CircuitField>>::Data,
    <S as Step<C>>::Witness<'source>,
);

impl<C: Cycle, S: Step<C>, R: Rank, const HEADER_SIZE: usize> Adapter<C, S, R, HEADER_SIZE> {
    /// The circuit of `step` within `bundle`, over a shared stage of
    /// `shared_size` elements.
    ///
    /// # Errors
    ///
    /// Returns an initialization error if the fragment reads more shared
    /// elements than the stage holds; registration refuses such a bundle,
    /// so this guards the prover's own calls.
    pub fn new(
        step: S,
        bundle: [CircuitIndex; APPLICATION_SLOTS],
        shared_size: usize,
    ) -> Result<Self> {
        let shared_size = if crate::internal::native::is_split_bundle(bundle) {
            shared_size
        } else {
            0
        };
        if S::Shared::num_values()? > shared_size {
            return Err(Error::Initialization(
                "the fragment reads more shared elements than the shared stage holds".into(),
            ));
        }
        Ok(Adapter {
            step,
            bundle,
            shared_size,
            _marker: PhantomData,
        })
    }
}

/// Reserves the shared stage's gates at the start of the circuit, as a stage
/// builder would, and returns its reserved wires.
///
/// The reserved wires are zero in the circuit's own trace; the committed
/// stage polynomial supplies their values, and the application final mask
/// holds the own trace to zero there. Only split bundles reserve the block;
/// the mask is switched off for a standalone step using its registered IDs.
/// See the cost note on
/// [`ApplicationBuilder::register_bundle`](crate::ApplicationBuilder::register_bundle)
/// for the gates this takes in each bundle fragment.
///
/// Invariant: the adapter only binds the returned gadget to the block's `a`
/// and `d` wires. The final mask holds all four wire slots of
/// each reserved gate to zero in the fragment's own trace. The stage mask
/// does not force the block's `b` and `c` wires or an odd-sized stage's
/// padding wire to zero in the shared polynomial, so those wires must
/// remain unexposed. The SYSTEM gate is not part of the shared inputs.
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
    type Witness<'source> = AdapterWitness<'source, C, S>;
    type Output = Kind![C::CircuitField; FixedVec<Element<'_, _>, InstanceLen<HEADER_SIZE>>];
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

        // These are circuit constants, fixed at registration. Every fragment
        // attests the entire ordered bundle, so selecting or repeating just
        // one fragment cannot prove the registered step. The verifier derives
        // these public inputs from the proof's actual circuit selectors.
        let instance = self
            .bundle
            .map(|id| Element::constant(dr, id.omega_j()))
            .into_iter()
            .chain(elements)
            .collect_fixed()?;
        Ok(WithAux::new(instance, adapter_aux))
    }
}

#[cfg(test)]
mod tests {
    use ragu_circuits::polynomials::TestRank;
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
        type Witness<'source> = ();
        type Aux<'source> = ();
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
            DriverValue<D, ()>,
        )> {
            let allocator = &mut Standard::new();
            // Allocate elements for left and right
            let left_elem = Element::alloc(dr, allocator, left)?;
            let right_elem = Element::alloc(dr, allocator, right)?;

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

        let adapter = Adapter::<Pasta, TestStep, TestR, HEADER_SIZE>::new(TestStep);
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

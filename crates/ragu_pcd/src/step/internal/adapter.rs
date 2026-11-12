use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_circuits::{Circuit, WithAux, polynomials::Rank, staging};
use ragu_core::{
    Coeff, Cycle, Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element, GadgetExt,
    allocator::{Allocator, Standard},
    vec::{CollectFixed, ConstLen, FixedVec, Len},
};

use super::super::{
    Prepared, Step,
    oracles::{self, OnlineWitness, Oracles},
};
use crate::{Header, internal::online};

/// The length of an application circuit's instance: $\zeta$, the online
/// openings, the bridge hash's two coordinates and the three padded headers.
pub struct InstanceLen<const HEADER_SIZE: usize>;

impl<const HEADER_SIZE: usize> Len for InstanceLen<HEADER_SIZE> {
    fn len() -> usize {
        1 + 2 * online::NUM_ONLINE_QUERIES + 2 + 3 * HEADER_SIZE
    }
}

/// Adapts a [`Step`] to a [`Circuit`] whose instance is
/// `[zeta, x_0, y_0, ..., x_5, y_5, h_O1, left, right, output]`: the step's
/// challenge, its online openings in slot order, the bridge hash of its own
/// last online commitment and its three padded headers (see [`online`]).
/// After the step's circuit, every output slot the step left unopened is
/// opened at $\zeta$ and held to one, and every input slot it left
/// unopened is opened at $\zeta$ (see [`Oracles::finish`]).
///
/// The application stage occupies the first gates after the SYSTEM gate of
/// every step circuit, reserved by [`reserve_stage`]: the step's own trace is
/// zero there and the committed stage polynomial supplies those wires, as
/// for a staged circuit. Its size is the largest
/// [`NUM_STAGED`](Step::NUM_STAGED) registered in the application, known
/// once every step is, so the block is reserved here rather than through a
/// type-level stage.
pub(crate) struct Adapter<C, S, R, const HEADER_SIZE: usize> {
    step: S,
    /// The application stage's size, in values.
    stage_size: usize,
    _marker: PhantomData<(C, R)>,
}

impl<C: Cycle, S: Step<C>, R: Rank, const HEADER_SIZE: usize> Adapter<C, S, R, HEADER_SIZE> {
    /// The circuit of `step` over a stage of exactly its own
    /// [`NUM_STAGED`](Step::NUM_STAGED) values.
    #[cfg(test)]
    pub fn new(step: S) -> Self {
        Adapter {
            step,
            stage_size: S::NUM_STAGED,
            _marker: PhantomData,
        }
    }

    /// The circuit of `step` over an application stage of `stage_size`
    /// values.
    ///
    /// # Errors
    ///
    /// Returns an initialization error if the step stages more values than
    /// the stage holds; registration sizes the stage from every step, so
    /// this guards the prover's own calls.
    pub fn with_stage(step: S, stage_size: usize) -> Result<Self> {
        if S::NUM_STAGED > stage_size {
            return Err(Error::Initialization(
                "the step stages more values than the application stage holds".into(),
            ));
        }
        Ok(Adapter {
            step,
            stage_size,
            _marker: PhantomData,
        })
    }
}

/// Reserves the application stage's gates at the start of the circuit, as a
/// stage builder would, and returns its first `size` wires.
///
/// The reserved wires are zero in the circuit's own trace; the committed
/// stage polynomial supplies their values, and the application final mask
/// holds the own trace to zero there. Every step circuit reserves the block,
/// including the internal steps, so one pair of masks covers every proof.
///
/// Invariant: the adapter binds only the returned wires, the block's `a` and
/// `d` wires. The final mask holds all four wire slots of each reserved gate
/// to zero in the step's own trace. The stage mask does not force the block's
/// `b` and `c` wires or an odd-sized stage's padding wire to zero in the
/// stage polynomial, so those wires must remain unexposed.
fn reserve_stage<'dr, D: Driver<'dr>>(dr: &mut D, size: usize) -> Result<Vec<D::Wire>> {
    // Allocate whole gates, two wires each, so the step's own gates start
    // after the block; the padding wire of an odd-sized stage is unused.
    let allocator = &mut Standard::new();
    let mut wires = Vec::with_capacity(size);
    for i in 0..2 * staging::stage_gates(size) {
        let wire = allocator.alloc(dr, || Ok(Coeff::Zero))?;
        if i < size {
            wires.push(wire);
        }
    }
    Ok(wires)
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
        Prepared<C::CircuitField, S::Output>,
        OnlineWitness<C::CircuitField, R>,
    );
    type Output = Kind![C::CircuitField; FixedVec<Element<'_, _>, InstanceLen<HEADER_SIZE>>];
    type Aux<'source> = (
        (
            FixedVec<C::CircuitField, ConstLen<HEADER_SIZE>>,
            FixedVec<C::CircuitField, ConstLen<HEADER_SIZE>>,
        ),
        <S::Output as Header<C::CircuitField>>::Data,
        S::Aux<'source>,
        online::Queries<C::CircuitField>,
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
        let stage_wires = reserve_stage(dr, self.stage_size)?;
        let (left, right, witness, prepared, online) = witness.cast();

        // The step's staged values, each bound to its stage wire by one
        // equality: the committed stage supplies the stage wires, so a value
        // the circuit allocates here can only be the committed one. The
        // adapter owns this flat binding; no gadget traversal decides which
        // wires are bound.
        let mut staged = Vec::with_capacity(S::NUM_STAGED);
        for (i, stage_wire) in stage_wires.iter().take(S::NUM_STAGED).enumerate() {
            let value = Element::alloc(
                dr,
                &mut (),
                prepared.as_ref().map(|p| {
                    p.staged()
                        .get(i)
                        .copied()
                        .expect("the fuse checks the staged values' count")
                }),
            )?;
            dr.enforce_equal(value.wire(), stage_wire)?;
            staged.push(value);
        }

        let mut oracles = Oracles::alloc(dr, online.as_ref(), staged)?;
        let ((left, right, output), output_data, step_aux) =
            self.step
                .witness::<_, HEADER_SIZE>(dr, &mut oracles, witness, left, right)?;
        let (zeta, queries, bridge_hash) = oracles.finish(dr)?;
        let query_values = oracles::values(&queries);

        let mut elements = Vec::with_capacity(InstanceLen::<HEADER_SIZE>::len());
        elements.push(zeta);
        queries.write(dr, &mut elements)?;
        elements.extend(bridge_hash);
        let headers = elements.len();
        left.write(dr, &mut elements)?;
        right.write(dr, &mut elements)?;
        output.write(dr, &mut elements)?;

        let adapter_aux = D::try_just(|| {
            let left_header = elements[headers..headers + HEADER_SIZE]
                .iter()
                .map(|e| *e.value().take())
                .collect_fixed()?;

            let right_header = elements[headers + HEADER_SIZE..headers + 2 * HEADER_SIZE]
                .iter()
                .map(|e| *e.value().take())
                .collect_fixed()?;

            Ok((
                (left_header, right_header),
                output_data.take(),
                step_aux.take(),
                query_values.take(),
            ))
        })?;

        Ok(WithAux::new(FixedVec::try_from(elements)?, adapter_aux))
    }
}

#[cfg(test)]
mod tests {
    use ragu_circuits::polynomials::{TestRank, sparse};
    use ragu_core::{
        drivers::emulator::Emulator,
        gadgets::{Bound, Kind},
        maybe::{Always, Maybe, MaybeKind},
        pasta::{Fp, Pasta},
    };
    use ragu_primitives::allocator::{Allocator, Standard};
    use udon::field::Field;

    use super::*;
    use crate::{
        header::{Header, OnlinePoly, Padding, Suffix},
        step::{Encoded, Index, Oracles, Step},
    };

    type TestR = TestRank;
    const HEADER_SIZE: usize = 4;

    struct TestHeader;

    /// The polynomial a [`TestHeader`] keeps in its first slot.
    #[derive(Clone, Copy, Debug)]
    struct TestPoly;

    impl OnlinePoly for TestPoly {}

    impl Header<Fp> for TestHeader {
        const SUFFIX: Suffix = Suffix::new(50);
        type OnlinePolyCommit = (TestPoly, Padding);
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
            oracles: &mut Oracles<'_, 'dr, D, Pasta, Self>,
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

            // Open the first left slot at the left header's value, leaving
            // the other slots to be opened at zeta.
            oracles.left(TestPoly).open(dr, &left_elem)?;

            let left_enc = Encoded::from_gadget(left_elem);
            let right_enc = Encoded::from_gadget(right_elem);
            let output_enc = Encoded::from_gadget(output_elem);

            Ok(((left_enc, right_enc, output_enc), output_val, D::unit()))
        }
    }

    /// [`TestStep`] pinning its output slots by hand, after its own work.
    struct PinningTwin;

    impl Step<Pasta> for PinningTwin {
        const INDEX: Index = Index::new(0);
        type Witness<'source> = ();
        type Aux<'source> = ();
        type Left = TestHeader;
        type Right = TestHeader;
        type Output = TestHeader;

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
            &self,
            dr: &mut D,
            oracles: &mut Oracles<'_, 'dr, D, Pasta, Self>,
            witness: DriverValue<D, ()>,
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
            let _ = witness;
            let allocator = &mut Standard::new();
            let left_elem = Element::alloc(dr, allocator, left)?;
            let right_elem = Element::alloc(dr, allocator, right)?;
            let output_elem = left_elem.add(dr, &right_elem);
            let output_val = output_elem.value().map(|v| *v);
            oracles.left(TestPoly).open(dr, &left_elem)?;
            // What `TestStep` leaves to the adapter, done by hand.
            let zeta = oracles.zeta().clone();
            for i in 0..online::NUM_ONLINE_POLYNOMIALS {
                let value = oracles.output_at(i).open(dr, &zeta)?;
                value.enforce_equal(dr, &Element::one())?;
            }
            Ok((
                (
                    Encoded::from_gadget(left_elem),
                    Encoded::from_gadget(right_elem),
                    Encoded::from_gadget(output_elem),
                ),
                output_val,
                D::unit(),
            ))
        }
    }

    /// An online witness over distinct small polynomials, so that a slot's
    /// value tells which polynomial it was opened on.
    fn online(zeta: u64) -> OnlineWitness<Fp, TestR> {
        OnlineWitness {
            zeta: Fp::from(zeta),
            polys: core::array::from_fn(|slot| {
                // Slot i holds X + i.
                sparse::Polynomial::from_coeffs(alloc::vec![Fp::from(slot as u64), Fp::ONE])
            }),
            bridge_hash: [Fp::ZERO; 2],
        }
    }

    /// The adapter holds every output slot a step leaves unopened to one,
    /// exactly as the step pinning them by hand after its own checks would:
    /// the two circuits are wiring-identical.
    #[test]
    fn unopened_output_slots_are_pinned() {
        use ragu_testing::registry::TestRegistryBuilder;

        let mut builder: TestRegistryBuilder<'_, _, TestR> = TestRegistryBuilder::new();
        let plain = builder
            .register_circuit(Adapter::<Pasta, TestStep, TestR, HEADER_SIZE>::new(
                TestStep,
            ))
            .unwrap();
        let pinned = builder
            .register_circuit(Adapter::<Pasta, PinningTwin, TestR, HEADER_SIZE>::new(
                PinningTwin,
            ))
            .unwrap();
        let registry = builder.finalize().unwrap();
        let (x, y) = (Fp::from(5u64), Fp::from(17u64));
        assert_eq!(registry.xy(plain, x, y), registry.xy(pinned, x, y));
    }

    #[test]
    fn instance_len_counts_zeta_openings_and_headers() {
        assert_eq!(
            InstanceLen::<1>::len(),
            1 + 2 * online::NUM_ONLINE_QUERIES + 2 + 3
        );
        assert_eq!(
            InstanceLen::<4>::len(),
            1 + 2 * online::NUM_ONLINE_QUERIES + 2 + 12
        );
    }

    #[test]
    fn adapter_witness_produces_correct_output_size() {
        let mut dr = Emulator::execute();
        let dr = &mut dr;

        let adapter = Adapter::<Pasta, TestStep, TestR, HEADER_SIZE>::new(TestStep);
        let witness = Always::maybe_just(|| {
            (
                Fp::from(10u64),
                Fp::from(20u64),
                (),
                Prepared::<Fp, TestHeader>::new(),
                online(7),
            )
        });

        let output = adapter
            .witness(dr, witness)
            .expect("witness should succeed")
            .into_output();

        // zeta, the openings, the bridge hash, then the three padded headers
        assert_eq!(output.len(), InstanceLen::<HEADER_SIZE>::len());
        let values: alloc::vec::Vec<Fp> = output.iter().map(|e| *e.value().take()).collect();
        assert_eq!(values[0], Fp::from(7u64));
        let headers = 1 + 2 * online::NUM_ONLINE_QUERIES + 2;
        assert_eq!(values[headers], Fp::from(10u64));
        assert_eq!(values[headers + HEADER_SIZE], Fp::from(20u64));
        assert_eq!(values[headers + 2 * HEADER_SIZE], Fp::from(30u64));
    }

    #[test]
    fn adapter_witness_extracts_aux_correctly() {
        let mut dr = Emulator::execute();
        let dr = &mut dr;

        let adapter = Adapter::<Pasta, TestStep, TestR, HEADER_SIZE>::new(TestStep);
        let witness = Always::maybe_just(|| {
            (
                Fp::from(10u64),
                Fp::from(20u64),
                (),
                Prepared::<Fp, TestHeader>::new(),
                online(7),
            )
        });

        let aux = adapter
            .witness(dr, witness)
            .expect("witness should succeed")
            .into_aux();

        let ((left_header, right_header), output_data, _step_aux, queries) = aux.take();

        // Left header should start with 10
        assert_eq!(left_header[0], Fp::from(10u64));
        // Right header should start with 20
        assert_eq!(right_header[0], Fp::from(20u64));
        // Step aux should be 10 + 20 = 30
        assert_eq!(output_data, Fp::from(30u64));

        // The step opened slot 0 at the left value, 10, where X + 0 is 10;
        // every other slot was opened at zeta = 7, where X + i is 7 + i
        // (the output slots are held to one, which the emulator does not
        // check; `unopened_output_slots_are_pinned` pins the wiring).
        assert_eq!(queries[0].x, Fp::from(10u64));
        assert_eq!(queries[0].y, Fp::from(10u64));
        for (i, query) in queries.iter().enumerate().skip(1) {
            assert_eq!(query.x, Fp::from(7u64));
            assert_eq!(query.y, Fp::from(7 + i as u64));
        }
    }

    #[test]
    fn a_slot_is_queried_at_most_once() {
        let mut dr = Emulator::execute();
        let dr = &mut dr;
        let witness = online(3);
        let mut oracles =
            Oracles::<_, Pasta, TestStep>::alloc(dr, Always::maybe_just(|| &witness), Vec::new())
                .unwrap();
        let x = Element::alloc(dr, &mut (), Always::maybe_just(|| Fp::from(5u64))).unwrap();
        // The named polynomial through its oracle, once; the unnamed slot
        // through the crate's untyped query, as Ragu's own steps do.
        assert_eq!(
            *oracles
                .output(TestPoly)
                .open(dr, &x)
                .unwrap()
                .value()
                .take(),
            Fp::from(5 + 4u64)
        );
        assert!(oracles.output(TestPoly).open(dr, &x).is_err());
        let zeta = oracles.zeta().clone();
        assert!(oracles.output_at(1).open(dr, &zeta).is_ok());
        let (zeta, queries, _) = oracles.finish(dr).unwrap();
        assert_eq!(*zeta.value().take(), Fp::from(3u64));
        assert_eq!(*queries[0].x.value().take(), Fp::from(3u64));
        assert_eq!(*queries[4].x.value().take(), Fp::from(5u64));
        assert_eq!(*queries[5].x.value().take(), Fp::from(3u64));
    }
}

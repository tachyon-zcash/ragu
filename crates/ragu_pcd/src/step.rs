use arithmetic::Cycle;
use ff::PrimeField;
use ragu_circuits::{Circuit, polynomials::Rank};
use ragu_core::{
    Result,
    drivers::{
        Driver, DriverValue,
        emulator::{Emulator, Wireless},
    },
    gadgets::{GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element, GadgetExt,
    io::Buffer,
    vec::{FixedVec, Len},
};

use alloc::vec::Vec;
use core::marker::PhantomData;

use super::header::Header;

mod padded;
pub mod rerandomize;

/// The number of internal steps used by Ragu.
///
/// * `0` is used for the rerandomization step (see [`rerandomize`]).
const INTERNAL_STEPS: u8 = 1;

enum StepIndex {
    Internal(usize),
    Application(usize),
}

pub struct Index {
    index: StepIndex,
}

impl Index {
    /// Creates a new application-defined step index.
    pub const fn new(value: usize) -> Self {
        Index {
            index: StepIndex::Application(value),
        }
    }

    /// Creates a new internal step index, used by Ragu itself for plumbing like
    /// proof decompression or rerandomization.
    pub(crate) const fn internal(value: usize) -> Self {
        if value >= INTERNAL_STEPS as usize {
            panic!("invalid internal step index");
        }

        Index {
            index: StepIndex::Internal(value),
        }
    }

    /// Maps this index to the "actual" index used internally by Ragu to
    /// identify its order of insertion in the mesh.
    #[allow(dead_code)]
    pub(crate) fn map(&self) -> usize {
        match self.index {
            StepIndex::Internal(i) => i,
            StepIndex::Application(i) => i + INTERNAL_STEPS as usize,
        }
    }
}

#[test]
fn test_index_map() {
    assert_eq!(Index::internal(0).map(), 0);
    assert_eq!(Index::new(0).map(), 1);
    assert_eq!(Index::new(1).map(), 2);
}

/// Represents a node in the computational graph (or the proof-carrying data
/// tree) that represents the merging of two pieces of proof-carrying data.
pub trait Step<C: Cycle>: Sized + Send + Sync {
    /// Each unique [`Step`] implementation within a provided context must have
    /// a unique index.
    const INDEX: Index;

    /// The witness data needed to construct a proof for this step.
    type Witness<'source>: Send;

    /// Auxillary information produced during circuit synthesis. This may be
    /// necessary to construct the [`Header::Data`] for the resulting proof.
    type Aux<'source>: Send;

    /// The "left" header expected during this step.
    type Left: Header<C::CircuitField>;

    /// The "right" header expected during this step.
    type Right: Header<C::CircuitField>;

    /// The header produced during this step.
    type Output: Header<C::CircuitField>;

    /// The main synthesis method that checks the validity of this merging step.
    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: Encoder<'dr, 'source, D, Self::Left, HEADER_SIZE>,
        right: Encoder<'dr, 'source, D, Self::Right, HEADER_SIZE>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, Self::Aux<'source>>,
    )>;
}

/// Represents triple a length determined at compile time.
pub struct TripleConstLen<const N: usize>;

impl<const N: usize> Len for TripleConstLen<N> {
    fn len() -> usize {
        N * 3
    }
}

/// Represents one larger than a length determined at compile time.
pub struct OneLargerConstLen<const N: usize>;

impl<const N: usize> Len for OneLargerConstLen<N> {
    fn len() -> usize {
        N + 1
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
    type Aux<'source> = S::Aux<'source>;

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<<Self::Output as GadgetKind<C::CircuitField>>::Rebind<'dr, D>> {
        todo!()
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

        let left = Encoder { witness: left };
        let right = Encoder { witness: right };

        let ((left, right, output), aux) = self
            .step
            .witness::<_, HEADER_SIZE>(dr, witness, left, right)?;

        let mut elements = Vec::with_capacity(HEADER_SIZE * 3);
        output.write(dr, &mut elements)?;
        left.write(dr, &mut elements)?;
        right.write(dr, &mut elements)?;

        Ok((FixedVec::try_from(elements).expect("correct length"), aux))
    }
}
pub struct Encoder<'dr, 'source: 'dr, D: Driver<'dr>, H: Header<D::F>, const HEADER_SIZE: usize> {
    witness: DriverValue<D, H::Data<'source>>,
}

/// The result of running [`Header::encode`].
pub enum Encoded<'dr, D: Driver<'dr>, H: Header<D::F>, const HEADER_SIZE: usize> {
    Gadget(<H::Output as GadgetKind<D::F>>::Rebind<'dr, D>),
    Raw(FixedVec<Element<'dr, D>, OneLargerConstLen<HEADER_SIZE>>),
}

impl<'dr, D: Driver<'dr>, H: Header<D::F>, const HEADER_SIZE: usize> Clone
    for Encoded<'dr, D, H, HEADER_SIZE>
{
    fn clone(&self) -> Self {
        match self {
            Encoded::Gadget(gadget) => Encoded::Gadget(gadget.clone()),
            Encoded::Raw(raw) => Encoded::Raw(raw.clone()),
        }
    }
}

impl<'dr, D: Driver<'dr, F: PrimeField>, H: Header<D::F>, const HEADER_SIZE: usize>
    Encoded<'dr, D, H, HEADER_SIZE>
{
    pub fn from(gadget: <H::Output as GadgetKind<D::F>>::Rebind<'dr, D>) -> Self {
        Encoded::Gadget(gadget)
    }

    fn write(self, dr: &mut D, buf: &mut Vec<Element<'dr, D>>) -> Result<()> {
        match self {
            Encoded::Gadget(gadget) => {
                padded::from_header::<H, HEADER_SIZE, _>(dr, gadget)?.write(dr, buf)?
            }
            Encoded::Raw(raw) => {
                assert_eq!(raw.len(), HEADER_SIZE);
                for element in raw.into_inner() {
                    buf.push(element);
                }
            }
        }
        Ok(())
    }
}

impl<'dr, 'source: 'dr, D: Driver<'dr, F: PrimeField>, H: Header<D::F>, const HEADER_SIZE: usize>
    Encoder<'dr, 'source, D, H, HEADER_SIZE>
{
    pub fn encode(self, dr: &mut D) -> Result<Encoded<'dr, D, H, HEADER_SIZE>> {
        Ok(Encoded::from(H::encode(dr, self.witness)?))
    }

    /// This witnesses the Header's gadget as its serialized encoding (via
    /// [`Write`](ragu_primitives::io::Write)) directly, rather than witnessing
    /// the gadget and then performing serialization. This step (if successful)
    /// will always synthesize the same circuit regardless of the concrete
    /// header.
    pub(crate) fn raw_encode(self, dr: &mut D) -> Result<Encoded<'dr, D, H, HEADER_SIZE>> {
        let mut emulator: Emulator<Wireless<D::MaybeKind, _>> = Emulator::wireless();
        let gadget = H::encode(&mut emulator, self.witness)?;
        let gadget = padded::from_header::<H, HEADER_SIZE, _>(&mut emulator, gadget)?;

        /// A buffer that pipes into another driver by allocating elements.
        struct Pipe<'a, 'dr, D: Driver<'dr>> {
            dr: &'a mut D,
            buf: &'a mut Vec<Element<'dr, D>>,
            _marker: PhantomData<&'dr ()>,
        }

        impl<'dr, D: Driver<'dr>> Buffer<'_, Emulator<Wireless<D::MaybeKind, D::F>>> for Pipe<'_, 'dr, D> {
            fn write(
                &mut self,
                _: &mut Emulator<Wireless<D::MaybeKind, D::F>>,
                value: &Element<'_, Emulator<Wireless<D::MaybeKind, D::F>>>,
            ) -> Result<()> {
                self.buf
                    .push(Element::alloc(self.dr, value.value().map(|v| *v))?);
                Ok(())
            }
        }

        let mut raw = Vec::with_capacity(HEADER_SIZE);
        {
            let mut buffer = Pipe {
                dr,
                buf: &mut raw,
                _marker: PhantomData,
            };
            gadget.write(&mut emulator, &mut buffer)?;
        }
        assert_eq!(raw.len(), HEADER_SIZE);

        Ok(Encoded::Raw(
            FixedVec::try_from(raw).expect("correct length"),
        ))
    }
}

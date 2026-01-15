use ff::PrimeField;
use ragu_core::{
    Result,
    drivers::{
        Driver, DriverValue,
        emulator::{Emulator, Wireless},
    },
    gadgets::GadgetKind,
};
use ragu_primitives::{
    Element, GadgetExt,
    io::Pipe,
    vec::{ConstLen, FixedVec},
};

use alloc::vec::Vec;

use super::{Header, internal::padded};

enum EncodedInner<'dr, D: Driver<'dr>, H: Header<D::F>, const HEADER_SIZE: usize> {
    Gadget(<H::Output as GadgetKind<D::F>>::Rebind<'dr, D>),
    Raw(FixedVec<Element<'dr, D>, ConstLen<HEADER_SIZE>>),
}

/// The result of encoding a header within a step.
pub struct Encoded<'dr, D: Driver<'dr>, H: Header<D::F>, const HEADER_SIZE: usize>(
    EncodedInner<'dr, D, H, HEADER_SIZE>,
);

impl<'dr, D: Driver<'dr>, H: Header<D::F>, const HEADER_SIZE: usize> Clone
    for EncodedInner<'dr, D, H, HEADER_SIZE>
{
    fn clone(&self) -> Self {
        match self {
            EncodedInner::Gadget(gadget) => EncodedInner::Gadget(gadget.clone()),
            EncodedInner::Raw(raw) => EncodedInner::Raw(raw.clone()),
        }
    }
}

impl<'dr, D: Driver<'dr>, H: Header<D::F>, const HEADER_SIZE: usize> Clone
    for Encoded<'dr, D, H, HEADER_SIZE>
{
    fn clone(&self) -> Self {
        Encoded(self.0.clone())
    }
}

impl<'dr, D: Driver<'dr, F: PrimeField>, H: Header<D::F>, const HEADER_SIZE: usize>
    Encoded<'dr, D, H, HEADER_SIZE>
{
    /// Create an encoded header from a gadget value.
    pub fn from_gadget(gadget: <H::Output as GadgetKind<D::F>>::Rebind<'dr, D>) -> Self {
        Encoded(EncodedInner::Gadget(gadget))
    }

    /// Returns a reference to the underlying gadget.
    pub fn as_gadget(&self) -> &<H::Output as GadgetKind<D::F>>::Rebind<'dr, D> {
        match &self.0 {
            EncodedInner::Gadget(g) => g,
            EncodedInner::Raw(_) => unreachable!(),
        }
    }

    pub(crate) fn write(self, dr: &mut D, buf: &mut Vec<Element<'dr, D>>) -> Result<()> {
        match self.0 {
            EncodedInner::Gadget(gadget) => {
                padded::for_header::<H, HEADER_SIZE, _>(dr, gadget)?.write(dr, buf)?
            }
            EncodedInner::Raw(raw) => {
                buf.extend(raw.into_inner());
            }
        }
        Ok(())
    }

    /// Creates a new encoded header by converting the header data into its gadget form.
    ///
    /// This is the standard encoding method used by most Steps. The gadget structure
    /// is preserved and will be serialized with padding during the write phase.
    pub fn new<'source: 'dr>(
        dr: &mut D,
        witness: DriverValue<D, H::Data<'source>>,
    ) -> Result<Self> {
        Ok(Encoded::from_gadget(H::encode(dr, witness)?))
    }

    /// Creates a uniform encoded header for circuit-independent encoding.
    ///
    /// This encoding method pre-serializes the header into field elements using an
    /// emulator, ensuring that different header types produce identical circuit
    /// structures. This is used internally for rerandomization to guarantee that
    /// `Rerandomize<HeaderA>` and `Rerandomize<HeaderB>` synthesize the same circuit.
    ///
    /// The tradeoff: less efficient (requires emulation + serialization) but achieves
    /// circuit uniformity across different header types.
    pub(crate) fn new_uniform<'source: 'dr>(
        dr: &mut D,
        witness: DriverValue<D, H::Data<'source>>,
    ) -> Result<Self> {
        let mut emulator: Emulator<Wireless<D::MaybeKind, _>> = Emulator::wireless();
        let gadget = H::encode(&mut emulator, witness)?;
        let gadget = padded::for_header::<H, HEADER_SIZE, _>(&mut emulator, gadget)?;

        let mut raw = Vec::with_capacity(HEADER_SIZE);
        gadget.write(&mut emulator, &mut Pipe::new(dr, &mut raw))?;

        Ok(Encoded(EncodedInner::Raw(FixedVec::try_from(raw)?)))
    }
}

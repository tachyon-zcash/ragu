use ff::PrimeField;
use ragu_core::{
    Result,
    drivers::{
        Driver, DriverValue,
        emulator::{Emulator, Wireless},
    },
    gadgets::GadgetKind,
    maybe::Maybe,
};
use ragu_primitives::{
    Element, GadgetExt,
    io::Buffer,
    vec::{ConstLen, FixedVec},
};

use alloc::vec::Vec;
use core::marker::PhantomData;

use super::{Header, padded};

/// A helper passed to step synthesis that provides access to the header data
/// for an input, along with methods to encode it into either a header gadget
/// or a raw serialized header of fixed length `HEADER_SIZE`.
pub struct Encoder<'dr, 'source: 'dr, D: Driver<'dr>, H: Header<D::F>, const HEADER_SIZE: usize> {
    witness: DriverValue<D, H::Data<'source>>,
}

impl<'dr, 'source: 'dr, D: Driver<'dr>, H: Header<D::F>, const HEADER_SIZE: usize>
    Encoder<'dr, 'source, D, H, HEADER_SIZE>
{
    /// Creates a new encoder for some header data.
    pub(crate) fn new(witness: DriverValue<D, H::Data<'source>>) -> Self {
        Encoder { witness }
    }
}

/// The result of encoding a header within a step.
///
/// This can either be a concrete gadget encoding (`Gadget`) or a raw
/// fixed-length serialized form (`Raw`) padded to `HEADER_SIZE`.
pub enum Encoded<'dr, D: Driver<'dr>, H: Header<D::F>, const HEADER_SIZE: usize> {
    /// A gadget form of the header produced by `Header::encode`.
    Gadget(<H::Output as GadgetKind<D::F>>::Rebind<'dr, D>),
    /// A fixed-length serialized header (including prefix), padded to `HEADER_SIZE`.
    Raw(FixedVec<Element<'dr, D>, ConstLen<HEADER_SIZE>>),
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
    /// Create an `Encoded::Gadget` from a header gadget value.
    pub fn from_gadget(gadget: <H::Output as GadgetKind<D::F>>::Rebind<'dr, D>) -> Self {
        Encoded::Gadget(gadget)
    }

    /// Returns a reference to the gadget if this is a `Gadget` encoding.
    /// Returns `None` if this is a `Raw` encoding.
    pub fn as_gadget(&self) -> Option<&<H::Output as GadgetKind<D::F>>::Rebind<'dr, D>> {
        match self {
            Encoded::Gadget(g) => Some(g),
            Encoded::Raw(_) => None,
        }
    }

    pub(crate) fn write(self, dr: &mut D, buf: &mut Vec<Element<'dr, D>>) -> Result<()> {
        match self {
            Encoded::Gadget(gadget) => {
                padded::for_header::<H, HEADER_SIZE, _>(dr, gadget)?.write(dr, buf)?
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
    /// Proxy for [`Header::encode`] applied to the [`Header::Data`] held by
    /// this encoder.
    pub fn encode(self, dr: &mut D) -> Result<Encoded<'dr, D, H, HEADER_SIZE>> {
        Ok(Encoded::from_gadget(H::encode(dr, self.witness)?))
    }

    /// This witnesses the Header's gadget as its serialized encoding (via
    /// [`Write`](ragu_primitives::io::Write)) directly, rather than witnessing
    /// the gadget and then performing serialization. This step (if successful)
    /// will always synthesize the same circuit regardless of the concrete
    /// header.
    pub(crate) fn raw_encode(self, dr: &mut D) -> Result<Encoded<'dr, D, H, HEADER_SIZE>> {
        let mut emulator: Emulator<Wireless<D::MaybeKind, _>> = Emulator::wireless();
        let gadget = H::encode(&mut emulator, self.witness)?;
        let gadget = padded::for_header::<H, HEADER_SIZE, _>(&mut emulator, gadget)?;

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

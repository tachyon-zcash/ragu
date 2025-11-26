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
                buf.extend(raw.into_inner());
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

        let mut raw = Vec::with_capacity(HEADER_SIZE);
        gadget.write(&mut emulator, &mut Pipe::new(dr, &mut raw))?;

        Ok(Encoded::Raw(
            FixedVec::try_from(raw).expect("correct length"),
        ))
    }
}

/// Test that encoding the same header data twice produces identical field elements.
/// If H::encode() is non-deterministic, verification would fail.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{Header, Prefix};
    use ragu_core::{
        drivers::{Driver, DriverValue},
        gadgets::{GadgetKind, Kind},
        maybe::{Always, Maybe, MaybeKind},
    };
    use ragu_pasta::Fp;
    use ragu_primitives::Element;

    const HEADER_SIZE: usize = 4;

    struct TestHeader;
    impl Header<Fp> for TestHeader {
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

    #[test]
    fn test_encode_determinism() -> Result<()> {
        let data = Fp::from(42u64);

        // Encode with first emulator
        let mut dr1: Emulator<Wireless<Always<()>, Fp>> = Emulator::wireless();
        let encoder1: Encoder<'_, '_, _, TestHeader, HEADER_SIZE> =
            Encoder::new(Always::maybe_just(|| data));
        let encoded1 = encoder1.encode(&mut dr1)?;
        let mut buf1 = Vec::new();
        encoded1.write(&mut dr1, &mut buf1)?;
        let values1: Vec<Fp> = buf1.iter().map(|e| *e.value().take()).collect();

        // Encode with second emulator
        let mut dr2: Emulator<Wireless<Always<()>, Fp>> = Emulator::wireless();
        let encoder2: Encoder<'_, '_, _, TestHeader, HEADER_SIZE> =
            Encoder::new(Always::maybe_just(|| data));
        let encoded2 = encoder2.encode(&mut dr2)?;
        let mut buf2 = Vec::new();
        encoded2.write(&mut dr2, &mut buf2)?;
        let values2: Vec<Fp> = buf2.iter().map(|e| *e.value().take()).collect();

        // Verify identical field elements
        assert_eq!(values1, values2);

        Ok(())
    }

    #[test]
    fn test_raw_encode_determinism() -> Result<()> {
        let data = Fp::from(42u64);

        // Raw encode with first emulator
        let mut dr1: Emulator<Wireless<Always<()>, Fp>> = Emulator::wireless();
        let encoder1: Encoder<'_, '_, _, TestHeader, HEADER_SIZE> =
            Encoder::new(Always::maybe_just(|| data));
        let encoded1 = encoder1.raw_encode(&mut dr1)?;
        let mut buf1 = Vec::new();
        encoded1.write(&mut dr1, &mut buf1)?;
        let values1: Vec<Fp> = buf1.iter().map(|e| *e.value().take()).collect();

        // Raw encode with second emulator
        let mut dr2: Emulator<Wireless<Always<()>, Fp>> = Emulator::wireless();
        let encoder2: Encoder<'_, '_, _, TestHeader, HEADER_SIZE> =
            Encoder::new(Always::maybe_just(|| data));
        let encoded2 = encoder2.raw_encode(&mut dr2)?;
        let mut buf2 = Vec::new();
        encoded2.write(&mut dr2, &mut buf2)?;
        let values2: Vec<Fp> = buf2.iter().map(|e| *e.value().take()).collect();

        // Verify identical field elements
        assert_eq!(values1, values2);

        Ok(())
    }

    #[test]
    fn test_encode_and_raw_encode_produce_same_values() -> Result<()> {
        let data = Fp::from(42u64);

        // Regular encode
        let mut dr1: Emulator<Wireless<Always<()>, Fp>> = Emulator::wireless();
        let encoder1: Encoder<'_, '_, _, TestHeader, HEADER_SIZE> =
            Encoder::new(Always::maybe_just(|| data));
        let encoded1 = encoder1.encode(&mut dr1)?;
        let mut buf1 = Vec::new();
        encoded1.write(&mut dr1, &mut buf1)?;
        let values1: Vec<Fp> = buf1.iter().map(|e| *e.value().take()).collect();

        // Raw encode
        let mut dr2: Emulator<Wireless<Always<()>, Fp>> = Emulator::wireless();
        let encoder2: Encoder<'_, '_, _, TestHeader, HEADER_SIZE> =
            Encoder::new(Always::maybe_just(|| data));
        let encoded2 = encoder2.raw_encode(&mut dr2)?;
        let mut buf2 = Vec::new();
        encoded2.write(&mut dr2, &mut buf2)?;
        let values2: Vec<Fp> = buf2.iter().map(|e| *e.value().take()).collect();

        // Both should produce same field element values
        assert_eq!(values1, values2);

        Ok(())
    }
}

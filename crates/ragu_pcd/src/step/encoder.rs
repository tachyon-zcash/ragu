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

/// Headers can be encoded in two ways depending on the circuit requirements:
///
/// # Variants
///
/// ## `Gadget` - Standard Encoding
/// Preserves the header's gadget structure. The gadget will be serialized with
/// padding during the write phase. This is the efficient default used by most Steps.
///
/// Different header types produce different circuit structures (e.g., a single-element
/// header vs a tuple header will have different constraint systems).
///
/// ## `Uniform` - Circuit-Uniform Encoding
/// Pre-serializes the header into a fixed-size array of field elements using an
/// emulator. This ensures identical circuit structure regardless of the underlying
/// header type.
///
/// Used internally for rerandomization where `Rerandomize<H>` must produce the same
/// circuit for any header type `H`. The tradeoff is reduced efficiency (emulation
/// overhead) in exchange for circuit uniformity.
///
/// # Why Two Variants?
///
/// Most Steps benefit from structural encoding (`Gadget`) - it's efficient and the
/// circuit structure matches the computation. However, rerandomization requires that
/// the same circuit handles any header type, necessitating the uniform encoding
/// (`Uniform`) that erases type-level differences through serialization.
enum EncodedInner<'dr, D: Driver<'dr>, H: Header<D::F>, const HEADER_SIZE: usize> {
    /// Standard gadget encoding preserving structure (efficient, type-dependent circuit)
    Gadget(<H::Output as GadgetKind<D::F>>::Rebind<'dr, D>),
    /// Uniform encoding as field elements (less efficient, type-independent circuit)
    Uniform(FixedVec<Element<'dr, D>, ConstLen<HEADER_SIZE>>),
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
            EncodedInner::Uniform(uniform) => EncodedInner::Uniform(uniform.clone()),
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
            EncodedInner::Uniform(_) => {
                unreachable!("as_gadget should not be called on Uniform encoded headers")
            }
        }
    }

    pub(crate) fn write(self, dr: &mut D, buf: &mut Vec<Element<'dr, D>>) -> Result<()> {
        match self.0 {
            EncodedInner::Gadget(gadget) => {
                padded::for_header::<H, HEADER_SIZE, _>(dr, gadget)?.write(dr, buf)?
            }
            EncodedInner::Uniform(elements) => {
                buf.extend(elements.into_inner());
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

        Ok(Encoded(EncodedInner::Uniform(FixedVec::try_from(raw)?)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{Header, Suffix};
    use ragu_core::{
        drivers::emulator::Emulator,
        gadgets::Kind,
        maybe::{Always, Maybe, MaybeKind},
    };
    use ragu_pasta::Fp;

    const HEADER_SIZE: usize = 4;

    struct SingleHeader;

    impl Header<Fp> for SingleHeader {
        const SUFFIX: Suffix = Suffix::new(100);
        type Data<'source> = Fp;
        type Output = Kind![Fp; Element<'_, _>];

        fn encode<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            dr: &mut D,
            witness: DriverValue<D, Self::Data<'source>>,
        ) -> Result<<Self::Output as GadgetKind<Fp>>::Rebind<'dr, D>> {
            Element::alloc(dr, witness)
        }
    }

    struct PairHeader;

    impl Header<Fp> for PairHeader {
        const SUFFIX: Suffix = Suffix::new(101);
        type Data<'source> = (Fp, Fp);
        type Output = Kind![Fp; (Element<'_, _>, Element<'_, _>)];

        fn encode<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            dr: &mut D,
            witness: DriverValue<D, Self::Data<'source>>,
        ) -> Result<<Self::Output as GadgetKind<Fp>>::Rebind<'dr, D>> {
            let (a, b) = witness.cast();
            Ok((Element::alloc(dr, a)?, Element::alloc(dr, b)?))
        }
    }

    #[test]
    fn encoded_new_produces_header_size_output() {
        let mut dr = Emulator::execute();
        let dr = &mut dr;

        let witness = Always::maybe_just(|| Fp::from(42u64));
        let encoded = Encoded::<_, SingleHeader, HEADER_SIZE>::new(dr, witness)
            .expect("encoding should succeed");

        let mut buf = vec![];
        encoded.write(dr, &mut buf).expect("write should succeed");

        assert_eq!(buf.len(), HEADER_SIZE);
    }

    #[test]
    fn encoded_new_uniform_produces_header_size_output() {
        let mut dr = Emulator::execute();
        let dr = &mut dr;

        let witness = Always::maybe_just(|| Fp::from(42u64));
        let encoded = Encoded::<_, SingleHeader, HEADER_SIZE>::new_uniform(dr, witness)
            .expect("encoding should succeed");

        let mut buf = vec![];
        encoded.write(dr, &mut buf).expect("write should succeed");

        assert_eq!(buf.len(), HEADER_SIZE);
    }

    #[test]
    fn encoded_as_gadget_returns_inner_value() {
        let mut dr = Emulator::execute();
        let dr = &mut dr;

        let witness = Always::maybe_just(|| Fp::from(99u64));
        let encoded = Encoded::<_, SingleHeader, HEADER_SIZE>::new(dr, witness)
            .expect("encoding should succeed");

        let gadget = encoded.as_gadget();
        assert_eq!(*gadget.value().take(), Fp::from(99u64));
    }

    #[test]
    fn encoded_write_includes_suffix() {
        let mut dr = Emulator::execute();
        let dr = &mut dr;

        let witness = Always::maybe_just(|| Fp::from(1u64));
        let encoded = Encoded::<_, SingleHeader, HEADER_SIZE>::new(dr, witness)
            .expect("encoding should succeed");

        let mut buf = vec![];
        encoded.write(dr, &mut buf).expect("write should succeed");

        // Suffix is at the last position: 100 (app suffix) + 2 (internal offset) = 102
        assert_eq!(*buf[HEADER_SIZE - 1].value().take(), Fp::from(102u64));
    }

    #[test]
    fn encoded_uniform_different_headers_same_size() {
        let mut dr = Emulator::execute();
        let dr = &mut dr;

        let single = Encoded::<_, SingleHeader, HEADER_SIZE>::new_uniform(
            dr,
            Always::maybe_just(|| Fp::from(1u64)),
        )
        .expect("single encoding should succeed");

        let pair = Encoded::<_, PairHeader, HEADER_SIZE>::new_uniform(
            dr,
            Always::maybe_just(|| (Fp::from(2u64), Fp::from(3u64))),
        )
        .expect("pair encoding should succeed");

        let trivial = Encoded::<_, (), HEADER_SIZE>::new_uniform(dr, Always::maybe_just(|| ()))
            .expect("trivial encoding should succeed");

        let mut buf_single = vec![];
        let mut buf_pair = vec![];
        let mut buf_trivial = vec![];

        single.write(dr, &mut buf_single).unwrap();
        pair.write(dr, &mut buf_pair).unwrap();
        trivial.write(dr, &mut buf_trivial).unwrap();

        // All produce same size regardless of header type
        assert_eq!(buf_single.len(), HEADER_SIZE);
        assert_eq!(buf_pair.len(), HEADER_SIZE);
        assert_eq!(buf_trivial.len(), HEADER_SIZE);
    }

    #[test]
    fn encoded_clone_preserves_values() {
        let mut dr = Emulator::execute();
        let dr = &mut dr;

        let witness = Always::maybe_just(|| Fp::from(77u64));
        let original = Encoded::<_, SingleHeader, HEADER_SIZE>::new(dr, witness)
            .expect("encoding should succeed");
        let cloned = original.clone();

        let mut buf_orig = vec![];
        let mut buf_clone = vec![];
        original.write(dr, &mut buf_orig).unwrap();
        cloned.write(dr, &mut buf_clone).unwrap();

        for (a, b) in buf_orig.iter().zip(buf_clone.iter()) {
            assert_eq!(*a.value().take(), *b.value().take());
        }
    }
}

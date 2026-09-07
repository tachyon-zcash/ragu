use alloc::vec::Vec;

use ragu_arithmetic::ff::PrimeField;
use ragu_core::{
    Result,
    drivers::{
        Driver, DriverValue,
        emulator::{Emulator, Wireless},
    },
    gadgets::Bound,
};
use ragu_primitives::{
    Element, GadgetExt,
    allocator::Allocator,
    io::Pipe,
    vec::{ConstLen, FixedVec},
};

use super::{Header, internal::padded};
use crate::header::Suffix;

/// Headers can be encoded in two ways depending on the circuit requirements:
///
/// # Variants
///
/// ## `Gadget` - Standard Encoding
/// Preserves the header's gadget structure. The gadget will be serialized with
/// padding during the write phase. This is the efficient default used by most Steps.
///
/// Different header types may emit different constraints, e.g. a single-element
/// header and a tuple header allocate and serialize different gadgets.
///
/// ## `Uniform` - Circuit-Uniform Encoding
/// Pre-serializes the header into a fixed-size array of field elements using an
/// emulator. This ensures identical emitted constraints regardless of the
/// underlying header type.
///
/// Used internally for rerandomization where `Rerandomize<H>` must produce the same
/// circuit for any header type `H`. The tradeoff is reduced efficiency (emulation
/// overhead) in exchange for circuit uniformity.
///
/// # Why Two Variants?
///
/// Most Steps benefit from structural encoding (`Gadget`) - it's efficient and the
/// emitted constraints match the header gadget. However, rerandomization requires
/// that the same circuit handles any header type, necessitating the uniform
/// encoding (`Uniform`) that erases type-level differences through serialization.
enum EncodedInner<'dr, D: Driver<'dr>, H: Header<D::F>, const HEADER_SIZE: usize> {
    /// Standard gadget encoding preserving structure (efficient, type-dependent constraints).
    Gadget(Bound<'dr, D, H::Output>),
    /// Uniform encoding as field elements (less efficient, type-independent constraints).
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
    pub fn from_gadget(gadget: Bound<'dr, D, H::Output>) -> Self {
        Encoded(EncodedInner::Gadget(gadget))
    }

    /// Returns a reference to the underlying gadget.
    pub fn as_gadget(&self) -> &Bound<'dr, D, H::Output> {
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

    /// Creates a new encoded header by converting the header data into its
    /// gadget form.
    ///
    /// This is the standard encoding method used by most Steps. The header
    /// gadget structure is preserved and will be serialized with padding during
    /// the write phase.
    ///
    /// # Constraints
    ///
    /// `H::encode`, `H::Output` serialization, `HEADER_SIZE`, and the allocator's
    /// behavior and state determine the constraints emitted while constructing
    /// and writing the header.
    pub fn new<A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, H::Data>,
    ) -> Result<Self> {
        Ok(Encoded::from_gadget(H::encode(dr, allocator, witness)?))
    }

    /// Creates a uniform encoded header for type-independent encoding.
    ///
    /// This encoding method pre-serializes the header into field elements using an
    /// emulator, ensuring that different header types produce identical emitted
    /// constraints. This is used internally for rerandomization to guarantee
    /// that `Rerandomize<HeaderA>` and `Rerandomize<HeaderB>` emit the same
    /// constraints.
    ///
    /// Because every slot — including the suffix — is a witness wire rather than
    /// a constant, this encoding also **constrains the suffix wire to differ
    /// from the [`Dummy`](crate::header::Dummy) suffix**, so that no
    /// step consuming a uniform-encoded header can present the suffix that
    /// triggers the base case. See
    /// [`is_dummy_input`](crate::internal::native::stages::preamble::ProofInputs::is_dummy_input).
    ///
    /// The tradeoff: less efficient (requires emulation + serialization, plus
    /// one gate for the suffix check) but achieves constraint uniformity across
    /// different header types.
    ///
    /// # Constraints
    ///
    /// `HEADER_SIZE` and the destination allocator's behavior and state determine
    /// the emitted constraints, plus one multiplication gate and two constraints
    /// for the suffix check. `H::encode` and `H::Output` serialization affect
    /// only the wireless pre-serialization step.
    ///
    /// # Errors
    ///
    /// Returns an encoding error if the serialized header exceeds
    /// `HEADER_SIZE - 1` field elements. Header-specific errors from `H::encode`
    /// are also propagated during wireless pre-serialization.
    pub(crate) fn new_uniform<A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, H::Data>,
    ) -> Result<Self> {
        let mut emulator: Emulator<Wireless<D::MaybeKind, _>> = Emulator::wireless();
        let gadget = H::encode(&mut emulator, &mut (), witness)?;
        let gadget = padded::for_header::<H, HEADER_SIZE, _>(&mut emulator, gadget)?;

        let mut raw = Vec::with_capacity(HEADER_SIZE);
        gadget.write(&mut emulator, &mut Pipe::new(dr, allocator, &mut raw))?;
        let raw: FixedVec<Element<'dr, D>, ConstLen<HEADER_SIZE>> = FixedVec::try_from(raw)?;

        // Unlike a standard encoding, the suffix here is a witness wire rather
        // than a constant, so pin it away from `Dummy`: no circuit consuming
        // a uniform-encoded header may present the suffix that triggers the
        // base case.
        let trivial = Element::constant(dr, D::F::from(Suffix::internal(2).get()));
        raw[HEADER_SIZE - 1].sub(dr, &trivial).enforce_nonzero(dr)?;

        Ok(Encoded(EncodedInner::Uniform(raw)))
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use ragu_core::{
        drivers::emulator::Emulator,
        gadgets::{Bound, Kind},
        maybe::{Always, Maybe, MaybeKind},
    };
    use ragu_pasta::Fp;

    use super::*;
    use crate::header::{Header, Suffix};

    const HEADER_SIZE: usize = 4;

    struct SingleHeader;

    impl Header<Fp> for SingleHeader {
        const SUFFIX: Suffix = Suffix::new(100);
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

    struct PairHeader;

    impl Header<Fp> for PairHeader {
        const SUFFIX: Suffix = Suffix::new(101);
        type Data = (Fp, Fp);
        type Output = Kind![Fp; (Element<'_, _>, Element<'_, _>)];

        fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
            dr: &mut D,
            allocator: &mut A,
            witness: DriverValue<D, Self::Data>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            let (a, b) = witness.cast();
            Ok((
                Element::alloc(dr, allocator, a)?,
                Element::alloc(dr, allocator, b)?,
            ))
        }
    }

    /// A header squatting the reserved `Dummy` suffix, which is what a prover
    /// would need in order to make a uniform-encoded header present the suffix
    /// that triggers the base case.
    struct TrivialSuffixHeader;

    impl Header<Fp> for TrivialSuffixHeader {
        const SUFFIX: Suffix = Suffix::internal(2);
        type Data = ();
        type Output = ();

        fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
            _: &mut D,
            _: &mut A,
            _: DriverValue<D, Self::Data>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            Ok(())
        }
    }

    #[test]
    fn uniform_encoding_cannot_carry_the_dummy_suffix() {
        // Uniform encoding witnesses every header slot, including the suffix,
        // so it is the one encoding whose suffix is not a circuit constant.
        // `new_uniform` therefore constrains that wire away from the `Dummy`
        // suffix, which is what stops the step using it — rerandomization —
        // from ever taking the base case. A prover that tries anyway cannot
        // satisfy the constraint: witness generation fails here, and no
        // assignment satisfies it in a real circuit either, since the wire is
        // forced nonzero.
        let mut dr = Emulator::execute();
        let dr = &mut dr;

        let honest = Encoded::<_, SingleHeader, HEADER_SIZE>::new_uniform(
            dr,
            &mut (),
            Always::maybe_just(|| Fp::from(7u64)),
        );
        assert!(
            honest.is_ok(),
            "an ordinary header must encode uniformly without tripping the suffix check"
        );

        let forged = Encoded::<_, TrivialSuffixHeader, HEADER_SIZE>::new_uniform(
            dr,
            &mut (),
            Always::maybe_just(|| ()),
        );
        assert!(
            forged.is_err(),
            "a uniform-encoded header must not be able to carry the Dummy suffix"
        );
    }

    #[test]
    fn encoded_new_produces_header_size_output() {
        let mut dr = Emulator::execute();
        let dr = &mut dr;

        let witness = Always::maybe_just(|| Fp::from(42u64));
        let encoded = Encoded::<_, SingleHeader, HEADER_SIZE>::new(dr, &mut (), witness)
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
        let encoded = Encoded::<_, SingleHeader, HEADER_SIZE>::new_uniform(dr, &mut (), witness)
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
        let encoded = Encoded::<_, SingleHeader, HEADER_SIZE>::new(dr, &mut (), witness)
            .expect("encoding should succeed");

        let gadget = encoded.as_gadget();
        assert_eq!(*gadget.value().take(), Fp::from(99u64));
    }

    #[test]
    fn encoded_write_includes_suffix() {
        let mut dr = Emulator::execute();
        let dr = &mut dr;

        let witness = Always::maybe_just(|| Fp::from(1u64));
        let encoded = Encoded::<_, SingleHeader, HEADER_SIZE>::new(dr, &mut (), witness)
            .expect("encoding should succeed");

        let mut buf = vec![];
        encoded.write(dr, &mut buf).expect("write should succeed");

        // Suffix is at the last position: 100 (app suffix) + 3 (internal offset) = 103
        assert_eq!(*buf[HEADER_SIZE - 1].value().take(), Fp::from(103u64));
    }

    #[test]
    fn encoded_uniform_different_headers_same_size() {
        let mut dr = Emulator::execute();
        let dr = &mut dr;
        let allocator = &mut ();

        let single = Encoded::<_, SingleHeader, HEADER_SIZE>::new_uniform(
            dr,
            allocator,
            Always::maybe_just(|| Fp::from(1u64)),
        )
        .expect("single encoding should succeed");

        let pair = Encoded::<_, PairHeader, HEADER_SIZE>::new_uniform(
            dr,
            allocator,
            Always::maybe_just(|| (Fp::from(2u64), Fp::from(3u64))),
        )
        .expect("pair encoding should succeed");

        let trivial =
            Encoded::<_, (), HEADER_SIZE>::new_uniform(dr, allocator, Always::maybe_just(|| ()))
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
        let original = Encoded::<_, SingleHeader, HEADER_SIZE>::new(dr, &mut (), witness)
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

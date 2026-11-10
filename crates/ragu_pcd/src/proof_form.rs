//! Operations shared by the two built-in proof representations.

use alloc::vec::Vec;

use ragu_circuits::polynomials::Rank;
use ragu_core::Result;
use rand::CryptoRng;

use crate::{
    Application, CompressedPcd, CompressedProof, Pcd, Proof, SelectableBackend,
    header::{Header, NUM_ONLINE_POLYNOMIALS},
    ipa::IpaCycle,
    profile::ProfiledCycle,
    wire,
};

mod sealed {
    use ragu_circuits::polynomials::Rank;
    use ragu_core::Cycle;

    use crate::{CompressedProof, Proof};

    pub trait Sealed {}

    impl<C: Cycle, R: Rank> Sealed for Proof<C, R> {}
    impl<C: Cycle> Sealed for CompressedProof<C> {}
}

/// Common operations on [`Proof`] and [`CompressedProof`].
///
/// `R` specifies the expected rank for encoded length and verification.
/// Verification checks the receiving application's full proof shape.
/// This trait is sealed to the two built-in forms.
pub trait ProofForm<C: ProfiledCycle, R: Rank>: sealed::Sealed + Sized {
    /// This proof form with data described by `H` attached.
    ///
    /// This is [`Pcd<C, R, H>`] for [`Proof`] and [`CompressedPcd<C, H>`]
    /// for [`CompressedProof`].
    type Carried<H: Header<C::CircuitField>>;

    /// The step's own online polynomial commitments, in slot order.
    ///
    /// These are unverified claims until verification succeeds. Applications
    /// must compare them with their expected commitments as well as verify
    /// the carried data: attaching a header does not perform that comparison.
    fn online_commitments(&self) -> [C::HostCurve; NUM_ONLINE_POLYNOMIALS];

    /// Attaches data without checking that the proof attests it.
    fn carry<H: Header<C::CircuitField>>(self, data: H::Data) -> Self::Carried<H>;

    /// The exact encoded length for the expected rank and header size,
    /// including the envelope. Bound input before buffering it.
    ///
    /// This bound alone does not validate the encoded dimensions. In
    /// particular, compressed proofs of different dimensions can have the
    /// same length; verification must still check the application's shape.
    fn encoded_len<const HEADER_SIZE: usize>() -> usize;

    /// Encodes the proof with its version envelope, without verifying it.
    ///
    /// # Errors
    ///
    /// Returns [`wire::Error::Unencodable`] for an unrepresentable proof.
    fn to_bytes(&self) -> core::result::Result<Vec<u8>, wire::Error<'static>>;

    /// Decodes the proof's envelope and payload, without verifying it.
    ///
    /// # Errors
    ///
    /// Returns a wire error for invalid bytes. The uncompressed form also
    /// requires the declared rank to match `R`; the compressed form admits
    /// any bounded rank and leaves the application-shape check to verification.
    fn from_bytes(bytes: &[u8]) -> core::result::Result<Self, wire::Error<'_>>;

    /// Verifies carried data using the application's production verifier.
    ///
    /// After `proof.carry::<H>`, call as
    /// `P::verify::<H, _, _, HEADER_SIZE>(application, &carried, rng)`.
    /// [`Proof`] passes through [`Application::compress`] followed by
    /// [`Application::verify_compressed`]. Compression requires `rng` to be
    /// unpredictable to the proof's producer to validate its stored online
    /// polynomials for reuse as a child. [`CompressedProof`] passes directly
    /// to [`Application::verify_compressed`] and does not use `rng`.
    ///
    /// Verification uses the application's fixed setup and sealed verifier
    /// backend. It does not compare online slots against application-specific
    /// expected commitments; the caller must do that separately.
    ///
    /// # Cost
    ///
    /// Verification of [`Proof`] allocates a compressed proof and performs
    /// the compression's prover work before checking the result.
    ///
    /// # Errors
    ///
    /// Preserves errors from compression, header encoding and verification.
    /// In particular, malformed uncompressed proofs may return
    /// [`ragu_core::Error::InvalidWitness`] rather than `Ok(false)`. Accept
    /// only `Ok(true)`; both `Ok(false)` and `Err` are rejections.
    fn verify<
        H: Header<C::CircuitField>,
        B: SelectableBackend,
        RNG: CryptoRng,
        const HEADER_SIZE: usize,
    >(
        application: &Application<'_, C, R, HEADER_SIZE, B>,
        pcd: &Self::Carried<H>,
        rng: &mut RNG,
    ) -> Result<bool>
    where
        C: IpaCycle;
}

impl<C: ProfiledCycle, R: Rank> ProofForm<C, R> for Proof<C, R> {
    type Carried<H: Header<C::CircuitField>> = Pcd<C, R, H>;

    fn online_commitments(&self) -> [C::HostCurve; NUM_ONLINE_POLYNOMIALS] {
        self.online_commitments()
    }

    fn carry<H: Header<C::CircuitField>>(self, data: H::Data) -> Self::Carried<H> {
        self.carry::<H>(data)
    }

    fn encoded_len<const HEADER_SIZE: usize>() -> usize {
        Self::encoded_len::<HEADER_SIZE>()
    }

    fn to_bytes(&self) -> core::result::Result<Vec<u8>, wire::Error<'static>> {
        self.to_bytes()
    }

    fn from_bytes(bytes: &[u8]) -> core::result::Result<Self, wire::Error<'_>> {
        Self::from_bytes(bytes)
    }

    fn verify<
        H: Header<C::CircuitField>,
        B: SelectableBackend,
        RNG: CryptoRng,
        const HEADER_SIZE: usize,
    >(
        application: &Application<'_, C, R, HEADER_SIZE, B>,
        pcd: &Self::Carried<H>,
        rng: &mut RNG,
    ) -> Result<bool>
    where
        C: IpaCycle,
    {
        let compressed = application.compress(pcd, rng)?;
        application.verify_compressed(&compressed)
    }
}

impl<C: ProfiledCycle, R: Rank> ProofForm<C, R> for CompressedProof<C> {
    type Carried<H: Header<C::CircuitField>> = CompressedPcd<C, H>;

    fn online_commitments(&self) -> [C::HostCurve; NUM_ONLINE_POLYNOMIALS] {
        self.online_commitments()
    }

    fn carry<H: Header<C::CircuitField>>(self, data: H::Data) -> Self::Carried<H> {
        self.carry::<H>(data)
    }

    fn encoded_len<const HEADER_SIZE: usize>() -> usize {
        Self::encoded_len::<R, HEADER_SIZE>()
    }

    fn to_bytes(&self) -> core::result::Result<Vec<u8>, wire::Error<'static>> {
        self.to_bytes()
    }

    fn from_bytes(bytes: &[u8]) -> core::result::Result<Self, wire::Error<'_>> {
        Self::from_bytes(bytes)
    }

    fn verify<
        H: Header<C::CircuitField>,
        B: SelectableBackend,
        RNG: CryptoRng,
        const HEADER_SIZE: usize,
    >(
        application: &Application<'_, C, R, HEADER_SIZE, B>,
        pcd: &Self::Carried<H>,
        _rng: &mut RNG,
    ) -> Result<bool>
    where
        C: IpaCycle,
    {
        application.verify_compressed(pcd)
    }
}

//! The sealed choice of proof representation.

use core::marker::PhantomData;

use ragu_circuits::polynomials::Rank;

/// A proof retaining its rank-indexed polynomials for recursive proving.
#[derive(Clone, Copy, Debug)]
pub struct Uncompressed<R: Rank>(PhantomData<R>);

/// A terminal proof containing commitments and opening messages.
///
/// Its rank is carried by the wire encoding and checked against the receiving
/// application during verification, rather than fixed by this marker.
#[derive(Clone, Copy, Debug)]
pub struct Compressed;

/// A Ragu-owned proof representation.
///
/// This trait is sealed. Select [`Uncompressed<R>`] to retain polynomials of
/// rank `R`, or [`Compressed`] for a terminal proof. Generic code can carry,
/// clone and encode either representation without an associated carried type.
pub trait Form: sealed::Sealed {}

impl<R: Rank> Form for Uncompressed<R> {}
impl Form for Compressed {}

pub(super) mod sealed {
    use alloc::vec::Vec;

    use ragu_core::Cycle;

    use super::{Compressed, Rank, Uncompressed};
    use crate::{
        Proof, compress::CompressedData, header::NUM_ONLINE_POLYNOMIALS, profile::ProfiledCycle,
        proof::UncompressedData, wire::Error,
    };

    pub trait Sealed: Sized {
        type Payload<C: Cycle>: Clone;

        #[cfg(feature = "serde")]
        const EXPECTING: &'static str;

        fn online_commitments<C: Cycle>(
            proof: &Proof<C, Self>,
        ) -> [C::HostCurve; NUM_ONLINE_POLYNOMIALS]
        where
            Self: super::Form;

        fn to_bytes<C: ProfiledCycle>(proof: &Proof<C, Self>) -> Result<Vec<u8>, Error<'static>>
        where
            Self: super::Form;

        fn from_bytes<C: ProfiledCycle>(bytes: &[u8]) -> Result<Proof<C, Self>, Error<'_>>
        where
            Self: super::Form;

        #[cfg(feature = "serde")]
        fn framed_len<C: ProfiledCycle>(bytes: &[u8]) -> Result<usize, Error<'_>>;
    }

    impl<R: Rank> Sealed for Uncompressed<R> {
        type Payload<C: Cycle> = UncompressedData<C, R>;

        #[cfg(feature = "serde")]
        const EXPECTING: &'static str = "a proof in its wire format";

        fn online_commitments<C: Cycle>(
            proof: &Proof<C, Self>,
        ) -> [C::HostCurve; NUM_ONLINE_POLYNOMIALS] {
            proof
                .payload
                .online_commitments
                .clone()
                .map(|point| point.0)
        }

        fn to_bytes<C: ProfiledCycle>(proof: &Proof<C, Self>) -> Result<Vec<u8>, Error<'static>> {
            proof.encode_wire()
        }

        fn from_bytes<C: ProfiledCycle>(bytes: &[u8]) -> Result<Proof<C, Self>, Error<'_>> {
            Proof::<C, Self>::decode_wire(bytes)
        }

        #[cfg(feature = "serde")]
        fn framed_len<C: ProfiledCycle>(bytes: &[u8]) -> Result<usize, Error<'_>> {
            Proof::<C, Self>::framed_len(bytes)
        }
    }

    impl Sealed for Compressed {
        type Payload<C: Cycle> = CompressedData<C>;

        #[cfg(feature = "serde")]
        const EXPECTING: &'static str = "a compressed proof in its wire format";

        fn online_commitments<C: Cycle>(
            proof: &Proof<C, Self>,
        ) -> [C::HostCurve; NUM_ONLINE_POLYNOMIALS] {
            proof.payload.instance.online_commitments
        }

        fn to_bytes<C: ProfiledCycle>(proof: &Proof<C, Self>) -> Result<Vec<u8>, Error<'static>> {
            proof.encode_wire()
        }

        fn from_bytes<C: ProfiledCycle>(bytes: &[u8]) -> Result<Proof<C, Self>, Error<'_>> {
            Proof::<C, Self>::decode_wire(bytes)
        }

        #[cfg(feature = "serde")]
        fn framed_len<C: ProfiledCycle>(bytes: &[u8]) -> Result<usize, Error<'_>> {
            Proof::<C, Self>::framed_len(bytes)
        }
    }
}

//! Fixed-length encoding of compressed proofs.
//!
//! Fields are encoded in declaration order. Vector lengths come from the
//! receiving profile and from the payload's dimensions, its rank and header size;
//! no counts are read from the payload.

use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_primitives::vec::{ConstLen, Len};
use udon::{curve::Affine, field::Field};

use crate::{
    compress::{
        CompressedProof, Messages,
        batch::Batch,
        instance::{Child, Instance, NestedChild, OPENED},
        revdot::{
            Reduction,
            fold::{Derived, Fold},
            native_components, nested_components,
        },
    },
    ipa::IpaProof,
    profile::{Profile, ProfiledCycle},
    wire::{
        Decode, DefaultEncoding, Dimensions, Encode, Error, FixedSequence, HeaderSize, Point,
        Reader, Rounds, Scalar, SizedSequence, field_len,
    },
};

struct Native<P>(PhantomData<P>);
struct Nested<P>(PhantomData<P>);
impl<P: Profile> Len for Native<P> {
    fn len() -> usize {
        native_components::<P>().count()
    }
}
impl<P: Profile> Len for Nested<P> {
    fn len() -> usize {
        nested_components::<P>().count()
    }
}

// Keep encoding, decoding and size calculation in one field list so that
// they cannot disagree about the compressed layout. The field types are
// inferred from the struct; `encoded_len` alone has no value to infer them
// from and takes them from a projection.
macro_rules! codec {
    ([$($generics:tt)*] $ty:ty { $($field:ident => $enc:ty),* $(,)? }) => {
        impl<$($generics)*> Encode for $ty {
            fn encode(&self, output: &mut Vec<u8>, dims: Dimensions) -> Result<(), Error<'static>> {
                $( <_ as Encode<$enc>>::encode(&self.$field, output, dims)?; )*
                Ok(())
            }
        }
        impl<$($generics)*> Decode for $ty {
            fn encoded_len(dims: Dimensions) -> usize {
                0 $(+ field_len::<Self, _, $enc>(|value| &value.$field, dims))*
            }
            fn decode<'a>(reader: &mut Reader<'a>, dims: Dimensions) -> Result<Self, Error<'a>> {
                Ok(Self {
                    $( $field: <_ as Decode<$enc>>::decode(reader, dims)?, )*
                })
            }
        }
    }
}
codec!([F: Field] Child<F> {
    x => Scalar,
    y => Scalar,
    id => Scalar,
});
codec!([F: Field] NestedChild<F> {
    x => Scalar,
    y => Scalar,
});
codec!([P: Affine] Fold<P> {
    inner => Point,
    outer => Point,
    inner_epsilon => Scalar,
    outer_epsilon => Scalar,
});
codec!([P: Affine] Reduction<P> {
    fold => DefaultEncoding,
    p => Point,
    q => Point,
    openings => FixedSequence<Scalar, ConstLen<{Derived::ALL.len()}>>,
    p_at_inverse_r => Scalar,
    q_at_r => Scalar,
});
codec!([P: Affine] Batch<P> {
    f => Point,
    evaluations => FixedSequence<Scalar, ConstLen<{Derived::ALL.len() + 2 + OPENED}>>,
});
struct RoundPair;
impl<P: Affine> Encode<RoundPair> for (P, P) {
    fn encode(&self, out: &mut Vec<u8>, dims: Dimensions) -> Result<(), Error<'static>> {
        <P as Encode<Point>>::encode(&self.0, out, dims)?;
        <P as Encode<Point>>::encode(&self.1, out, dims)
    }
}
impl<P: Affine> Decode<RoundPair> for (P, P) {
    fn encoded_len(dims: Dimensions) -> usize {
        2 * <P as Decode<Point>>::encoded_len(dims)
    }
    fn decode<'a>(reader: &mut Reader<'a>, dims: Dimensions) -> Result<Self, Error<'a>> {
        Ok((
            <P as Decode<Point>>::decode(reader, dims)?,
            <P as Decode<Point>>::decode(reader, dims)?,
        ))
    }
}
codec!([P: Affine] IpaProof<P> {
    s_commitment => Point,
    rounds => SizedSequence<RoundPair, Rounds>,
    c => Scalar,
});
codec!([P: Affine] Messages<P> {
    reduction => DefaultEncoding,
    batch => DefaultEncoding,
    opening => DefaultEncoding,
});
codec!([C: ProfiledCycle] Instance<C> {
    circuit_id => DefaultEncoding,
    left_header => SizedSequence<Scalar, HeaderSize>,
    right_header => SizedSequence<Scalar, HeaderSize>,
    native => FixedSequence<Point, Native<C::Profile>>,
    native_registry_xy => Point,
    native_p => Point,
    nested => FixedSequence<Point, Nested<C::Profile>>,
    nested_registry_xy => Point,
    nested_p => Point,
    nested_challenges_partial => Point,
    bridge_alpha => Scalar,
    c => Scalar,
    v => Scalar,
    nested_c => Scalar,
    nested_v => Scalar,
    left => DefaultEncoding,
    right => DefaultEncoding,
    a_at_u => Scalar,
    b_at_u => Scalar,
    nested_left => DefaultEncoding,
    nested_right => DefaultEncoding,
    nested_a_at_u => Scalar,
    nested_b_at_u => Scalar,
});
codec!([C: ProfiledCycle] CompressedProof<C> {
    instance => DefaultEncoding,
    native => DefaultEncoding,
    nested => DefaultEncoding,
});

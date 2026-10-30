//! Fixed-length encoding of compressed proofs.
//!
//! Fields are encoded in declaration order. Vector lengths come from the
//! receiving profile and from the payload's dimensions, its rank and header size;
//! no counts are read from the payload.

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
        Reader, Rounds, Scalar, SizedSequence, Validate,
    },
};
use alloc::vec::Vec;
use core::marker::PhantomData;
use ragu_circuits::registry::CircuitIndex;
use ragu_primitives::vec::{ConstLen, Len};
use udon::{curve::Affine, field::Field};

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

// Keep encoding, decoding, size calculation and structural checks in one field
// declaration so that they cannot disagree about the compressed layout.
macro_rules! codec {
    ([$($generics:tt)*] $ty:ty, $ctor:ident { $($field:ident: $ft:ty => $enc:ty),* $(,)? }) => {
        impl<$($generics)*> Validate for $ty {
            fn valid(&self, dims: Dimensions) -> bool {
                true $( && <$ft as Validate<$enc>>::valid(&self.$field, dims) )*
            }
        }
        impl<$($generics)*> Encode for $ty {
            fn encode(&self, output: &mut Vec<u8>) {
                $( <$ft as Encode<$enc>>::encode(&self.$field, output); )*
            }
        }
        impl<$($generics)*> Decode for $ty {
            fn encoded_len(dims: Dimensions) -> usize {
                0 $(+ <$ft as Decode<$enc>>::encoded_len(dims))*
            }
            fn decode<'a>(reader: &mut Reader<'a>, dims: Dimensions) -> Result<Self, Error<'a>> {
                Ok($ctor {
                    $( $field: <$ft as Decode<$enc>>::decode(reader, dims)?, )*
                })
            }
        }
    }
}
codec!([F: Field] Child<F>, Child {
    x: F => Scalar,
    y: F => Scalar,
    id: F => Scalar,
});
codec!([F: Field] NestedChild<F>, NestedChild {
    x: F => Scalar,
    y: F => Scalar,
});
codec!([P: Affine] Fold<P>, Fold {
    inner: P => Point,
    outer: P => Point,
    inner_epsilon: P::Scalar => Scalar,
    outer_epsilon: P::Scalar => Scalar,
});
codec!([P: Affine] Reduction<P>, Reduction {
    fold: Fold<P> => DefaultEncoding,
    p: P => Point,
    q: P => Point,
    openings: Vec<P::Scalar> => FixedSequence<Scalar, ConstLen<{Derived::ALL.len()}>>,
    p_at_inverse_r: P::Scalar => Scalar,
    q_at_r: P::Scalar => Scalar,
});
codec!([P: Affine] Batch<P>, Batch {
    f: P => Point,
    evaluations: Vec<P::Scalar> => FixedSequence<Scalar, ConstLen<{Derived::ALL.len() + 2 + OPENED}>>,
});
struct RoundPair;
impl<P: Affine> Validate<RoundPair> for (P, P) {
    fn valid(&self, dims: Dimensions) -> bool {
        <P as Validate<Point>>::valid(&self.0, dims) && <P as Validate<Point>>::valid(&self.1, dims)
    }
}
impl<P: Affine> Encode<RoundPair> for (P, P) {
    fn encode(&self, out: &mut Vec<u8>) {
        <P as Encode<Point>>::encode(&self.0, out);
        <P as Encode<Point>>::encode(&self.1, out);
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
codec!([P: Affine] IpaProof<P>, IpaProof {
    s_commitment: P => Point,
    rounds: Vec<(P, P)> => SizedSequence<RoundPair, Rounds>,
    c: P::Scalar => Scalar,
});
codec!([P: Affine] Messages<P>, Messages {
    reduction: Reduction<P> => DefaultEncoding,
    batch: Batch<P> => DefaultEncoding,
    opening: IpaProof<P> => DefaultEncoding,
});
codec!([C: ProfiledCycle] Instance<C>, Instance {
    circuit_id: CircuitIndex => DefaultEncoding,
    left_header: Vec<C::CircuitField> => SizedSequence<Scalar, HeaderSize>,
    right_header: Vec<C::CircuitField> => SizedSequence<Scalar, HeaderSize>,
    native: Vec<C::HostCurve> => FixedSequence<Point, Native<C::Profile>>,
    native_registry_xy: C::HostCurve => Point,
    native_p: C::HostCurve => Point,
    nested: Vec<C::NestedCurve> => FixedSequence<Point, Nested<C::Profile>>,
    nested_registry_xy: C::NestedCurve => Point,
    nested_p: C::NestedCurve => Point,
    nested_challenges_partial: C::NestedCurve => Point,
    bridge_alpha: C::ScalarField => Scalar,
    c: C::CircuitField => Scalar,
    v: C::CircuitField => Scalar,
    nested_c: C::ScalarField => Scalar,
    nested_v: C::ScalarField => Scalar,
    left: Child<C::CircuitField> => DefaultEncoding,
    right: Child<C::CircuitField> => DefaultEncoding,
    a_at_u: C::CircuitField => Scalar,
    b_at_u: C::CircuitField => Scalar,
    nested_left: NestedChild<C::ScalarField> => DefaultEncoding,
    nested_right: NestedChild<C::ScalarField> => DefaultEncoding,
    nested_a_at_u: C::ScalarField => Scalar,
    nested_b_at_u: C::ScalarField => Scalar,
});
codec!([C: ProfiledCycle] CompressedProof<C>, CompressedProof {
    instance: Instance<C> => DefaultEncoding,
    native: Messages<C::HostCurve> => DefaultEncoding,
    nested: Messages<C::NestedCurve> => DefaultEncoding,
});

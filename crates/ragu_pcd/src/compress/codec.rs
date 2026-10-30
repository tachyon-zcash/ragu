//! Count-free compressed payload. All counts come from the receiving type.
use super::{
    CompressedProof, Messages,
    batch::Batch,
    instance::{Child, Instance, NestedChild, OPENED},
    revdot::{
        Reduction,
        fold::{Derived, Fold},
        native_components, nested_components,
    },
};
use crate::ipa::IpaProof;
use crate::{
    profile::{Profile, ProfiledCycle},
    wire::{
        Decode, DefaultEncoding, Encode, Error, FixedSequence, Point, Reader, Scalar, Validate,
    },
};
use alloc::vec::Vec;
use core::marker::PhantomData;
use ragu_circuits::{polynomials::Rank, registry::CircuitIndex};
use ragu_primitives::vec::{ConstLen, Len};
use udon::{curve::Affine, field::Field};

pub(crate) struct Compressed<R, const H: usize>(PhantomData<R>);
struct Native<P>(PhantomData<P>);
struct Nested<P>(PhantomData<P>);
struct Rounds<R>(PhantomData<R>);
struct Headers<const H: usize>;
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
impl<R: Rank> Len for Rounds<R> {
    fn len() -> usize {
        R::RANK as usize
    }
}
impl<const H: usize> Len for Headers<H> {
    fn len() -> usize {
        H
    }
}

macro_rules! codec {
    ([$($generics:tt)*] $ty:ty, $codec:ty, $ctor:ident { $($field:ident: $ft:ty => $enc:ty),* $(,)? }) => {
        impl<$($generics)*> Validate<$codec> for $ty {
            fn valid(&self) -> bool { true $( && <$ft as Validate<$enc>>::valid(&self.$field) )* }
        }
        impl<$($generics)*> Encode<$codec> for $ty {
            fn encode(&self, out: &mut Vec<u8>) { $( <$ft as Encode<$enc>>::encode(&self.$field, out); )* }
        }
        impl<$($generics)*> Decode<$codec> for $ty {
            fn encoded_len() -> usize { 0 $(+ <$ft as Decode<$enc>>::encoded_len())* }
            fn decode<'a>(reader: &mut Reader<'a>) -> Result<Self, Error<'a>> {
                Ok($ctor { $( $field: <$ft as Decode<$enc>>::decode(reader)?, )* })
            }
        }
    }
}
codec!([F: Field] Child<F>, DefaultEncoding, Child { x: F => Scalar, y: F => Scalar, id: F => Scalar });
codec!([F: Field] NestedChild<F>, DefaultEncoding, NestedChild { x: F => Scalar, y: F => Scalar });
codec!([P: Affine] Fold<P>, DefaultEncoding, Fold { inner: P => Point, outer: P => Point, inner_epsilon: P::Scalar => Scalar, outer_epsilon: P::Scalar => Scalar });
codec!([P: Affine] Reduction<P>, DefaultEncoding, Reduction {
    fold: Fold<P> => DefaultEncoding, p: P => Point, q: P => Point,
    openings: Vec<P::Scalar> => FixedSequence<Scalar, ConstLen<{Derived::ALL.len()}>>,
    p_at_inverse_r: P::Scalar => Scalar, q_at_r: P::Scalar => Scalar,
});
codec!([P: Affine] Batch<P>, DefaultEncoding, Batch {
    f: P => Point,
    evaluations: Vec<P::Scalar> => FixedSequence<Scalar, ConstLen<{Derived::ALL.len() + 2 + OPENED}>>,
});
struct RoundPair;
impl<P: Affine> Validate<RoundPair> for (P, P) {
    fn valid(&self) -> bool {
        <P as Validate<Point>>::valid(&self.0) && <P as Validate<Point>>::valid(&self.1)
    }
}
impl<P: Affine> Encode<RoundPair> for (P, P) {
    fn encode(&self, out: &mut Vec<u8>) {
        <P as Encode<Point>>::encode(&self.0, out);
        <P as Encode<Point>>::encode(&self.1, out);
    }
}
impl<P: Affine> Decode<RoundPair> for (P, P) {
    fn encoded_len() -> usize {
        2 * <P as Decode<Point>>::encoded_len()
    }
    fn decode<'a>(reader: &mut Reader<'a>) -> Result<Self, Error<'a>> {
        Ok((
            <P as Decode<Point>>::decode(reader)?,
            <P as Decode<Point>>::decode(reader)?,
        ))
    }
}
codec!([P: Affine, R: Rank, const H: usize] IpaProof<P>, Compressed<R,H>, IpaProof {
    s_commitment: P => Point, rounds: Vec<(P,P)> => FixedSequence<RoundPair, Rounds<R>>, c: P::Scalar => Scalar,
});
codec!([P: Affine, R: Rank, const H: usize] Messages<P>, Compressed<R,H>, Messages {
    reduction: Reduction<P> => DefaultEncoding, batch: Batch<P> => DefaultEncoding, opening: IpaProof<P> => Compressed<R,H>,
});
codec!([C: ProfiledCycle, R: Rank, const H: usize] Instance<C>, Compressed<R,H>, Instance {
    circuit_id: CircuitIndex => DefaultEncoding,
    left_header: Vec<C::CircuitField> => FixedSequence<Scalar, Headers<H>>,
    right_header: Vec<C::CircuitField> => FixedSequence<Scalar, Headers<H>>,
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
codec!([C: ProfiledCycle, R: Rank, const H: usize] CompressedProof<C>, Compressed<R,H>, CompressedProof {
    instance: Instance<C> => Compressed<R,H>, native: Messages<C::HostCurve> => Compressed<R,H>, nested: Messages<C::NestedCurve> => Compressed<R,H>,
});

//! Identity policy for a private batch's commitment walk.

use core::marker::PhantomData;

use ragu_primitives::{ConditionalPoint, PointEncoding};

use crate::profile::{Profile, online::stages::Side};

#[derive(Clone, Copy)]
pub(crate) struct Encoding<P: Profile, S: Side>(PhantomData<(P, S)>);
impl<P: Profile, S: Side> PointEncoding for Encoding<P, S> {
    const ALLOW_IDENTITY: bool = if S::NATIVE {
        !P::NATIVE_ONLINE.is_empty()
    } else {
        !P::NESTED_ONLINE.is_empty()
    };
}

/// The private batch's encoding, finite for an empty declaration.
pub(crate) type BatchPoint<'dr, D, C, P, S> = ConditionalPoint<'dr, D, C, Encoding<P, S>>;

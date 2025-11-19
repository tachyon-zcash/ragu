use arithmetic::Cycle;

use core::marker::PhantomData;

use super::header::Header;

/// Represents a recursive proof for the correctness of some computation.
pub struct Proof<C: Cycle> {
    pub(crate) _marker: PhantomData<C>,
}

impl<C: Cycle> Proof<C> {
    /// Augment a recursive proof with some data, described by a [`Header`].
    pub fn carry<H: Header<C::CircuitField>>(self, data: H::Data<'_>) -> Pcd<'_, C, H> {
        Pcd { proof: self, data }
    }
}

/// Represents proof-carrying data, a recursive proof for the correctness of
/// some accompanying data.
pub struct Pcd<'source, C: Cycle, H: Header<C::CircuitField>> {
    /// The recursive proof for the accompanying data.
    pub proof: Proof<C>,

    /// Arbitrary data encoded into a [`Header`].
    pub data: H::Data<'source>,
}

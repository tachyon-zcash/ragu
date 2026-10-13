//! Circuit indices encoded through the existing public conversion API.
use alloc::vec::Vec;

use ragu_circuits::registry::CircuitIndex;

use super::{Decode, Encode, Error, Reader};
impl Encode for CircuitIndex {
    fn encode(&self, output: &mut Vec<u8>) {
        (usize::from(*self) as u32).encode(output);
    }
}
impl Decode for CircuitIndex {
    fn min_encoded_len() -> usize {
        4
    }
    fn decode<'a>(reader: &mut Reader<'a>) -> Result<Self, Error<'a>> {
        u32::decode(reader).map(CircuitIndex::from_u32)
    }
}

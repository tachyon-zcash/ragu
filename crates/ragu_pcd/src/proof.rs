use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::{
    CircuitExt,
    mesh::Mesh,
    polynomials::{Rank, structured},
};

use alloc::{vec, vec::Vec};
use core::marker::PhantomData;

use super::{
    header::Header,
    internal_circuits::{self, dummy},
};

/// Represents a recursive proof for the correctness of some computation.
pub struct Proof<C: Cycle, R: Rank> {
    pub(crate) application_circuit_id: usize,
    pub(crate) left_header: Vec<C::CircuitField>,
    pub(crate) right_header: Vec<C::CircuitField>,
    pub(crate) application_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) _marker: PhantomData<(C, R)>,
}

impl<C: Cycle, R: Rank> Clone for Proof<C, R> {
    fn clone(&self) -> Self {
        Proof {
            application_circuit_id: self.application_circuit_id,
            left_header: self.left_header.clone(),
            right_header: self.right_header.clone(),
            application_rx: self.application_rx.clone(),
            _marker: PhantomData,
        }
    }
}

impl<C: Cycle, R: Rank> Proof<C, R> {
    /// Augment a recursive proof with some data, described by a [`Header`].
    pub fn carry<H: Header<C::CircuitField>>(self, data: H::Data<'_>) -> Pcd<'_, C, R, H> {
        Pcd { proof: self, data }
    }
}

/// Represents proof-carrying data, a recursive proof for the correctness of
/// some accompanying data.
pub struct Pcd<'source, C: Cycle, R: Rank, H: Header<C::CircuitField>> {
    /// The recursive proof for the accompanying data.
    pub proof: Proof<C, R>,

    /// Arbitrary data encoded into a [`Header`].
    pub data: H::Data<'source>,
}

impl<C: Cycle, R: Rank, H: Header<C::CircuitField>> Clone for Pcd<'_, C, R, H> {
    fn clone(&self) -> Self {
        Pcd {
            proof: self.proof.clone(),
            data: self.data.clone(),
        }
    }
}

pub fn trivial<C: Cycle, R: Rank, const HEADER_SIZE: usize>(
    num_application_steps: usize,
    mesh: &Mesh<'_, C::CircuitField, R>,
) -> Proof<C, R> {
    let application_rx = dummy::Circuit
        .rx((), mesh.get_key())
        .expect("should not fail")
        .0;

    Proof {
        application_rx,
        application_circuit_id: internal_circuits::index(num_application_steps, dummy::CIRCUIT_ID),
        left_header: vec![C::CircuitField::ZERO; HEADER_SIZE],
        right_header: vec![C::CircuitField::ZERO; HEADER_SIZE],
        _marker: PhantomData,
    }
}

//! Proof and proof-carrying data structures.
//!
//! Defines the [`Proof`] structure containing trace polynomials, commitments,
//! and accumulated claims, along with [`Pcd`] which bundles a [`Proof`] with the
//! data that a [`Header`] succinctly encodes.

#![allow(dead_code)]

pub(crate) mod components;
pub(crate) use components::*;

use ff::Field;
use ragu_arithmetic::Cycle;
use ragu_circuits::{
    polynomials::{Rank, structured, unstructured},
    registry::CircuitIndex,
};
use ragu_primitives::vec::Len;

use alloc::vec;

use crate::circuits::nested::NUM_ENDOSCALING_POINTS;
use crate::components::claims::native::RxComponent;
use crate::components::endoscalar::NumStepsLen;
use crate::header::Header;

/// Represents proof-carrying data, a recursive proof for the correctness of
/// some accompanying data.
pub struct Pcd<'source, C: Cycle, R: Rank, H: Header<C::CircuitField>> {
    /// The recursive proof for the accompanying data.
    pub proof: Proof<C, R>,

    /// Data needed to witness a [`Header`] within a [`Step`](super::Step).
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

/// Represents a recursive proof for the correctness of some computation.
#[derive(Clone)]
pub struct Proof<C: Cycle, R: Rank> {
    pub(crate) application: Application<C, R>,
    pub(crate) preamble: Preamble<C, R>,
    pub(crate) s_prime: SPrime<C, R>,
    pub(crate) error_n: ErrorN<C, R>,
    pub(crate) error_m: ErrorM<C, R>,
    pub(crate) ab: AB<C, R>,
    pub(crate) query: Query<C, R>,
    pub(crate) f: F<C, R>,
    pub(crate) eval: Eval<C, R>,
    pub(crate) p: P<C, R>,
    pub(crate) challenges: Challenges<C>,
    pub(crate) circuits: InternalCircuits<C, R>,
}

impl<C: Cycle, R: Rank> Proof<C, R> {
    /// Augment a recursive proof with some data, described by a [`Header`].
    pub fn carry<H: Header<C::CircuitField>>(self, data: H::Data<'_>) -> Pcd<'_, C, R, H> {
        Pcd { proof: self, data }
    }

    /// Returns the native-field rx polynomial for the given [`RxComponent`].
    pub(crate) fn native_rx(
        &self,
        component: RxComponent,
    ) -> &structured::Polynomial<C::CircuitField, R> {
        use RxComponent::*;
        match component {
            AbA => self.ab.a.poly(),
            AbB => self.ab.b.poly(),
            Application => self.application.rx.poly(),
            Hashes1 => self.circuits.hashes_1.poly(),
            Hashes2 => self.circuits.hashes_2.poly(),
            PartialCollapse => self.circuits.partial_collapse.poly(),
            FullCollapse => self.circuits.full_collapse.poly(),
            ComputeV => self.circuits.compute_v.poly(),
            Preamble => self.preamble.native_rx.poly(),
            ErrorM => self.error_m.native_rx.poly(),
            ErrorN => self.error_n.native_rx.poly(),
            Query => self.query.native_rx.poly(),
            Eval => self.eval.native_rx.poly(),
        }
    }
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> crate::Application<'_, C, R, HEADER_SIZE> {
    pub(crate) fn trivial_pcd<'source>(&self) -> Pcd<'source, C, R, ()> {
        self.trivial_proof().carry(())
    }

    pub(crate) fn trivial_proof(&self) -> Proof<C, R> {
        let host_blind = C::CircuitField::ONE;
        let nested_blind = C::ScalarField::ONE;

        let zero_structured_host = structured::Polynomial::<C::CircuitField, R>::new();
        let zero_structured_nested = structured::Polynomial::<C::ScalarField, R>::new();
        let zero_unstructured = unstructured::Polynomial::<C::CircuitField, R>::new();

        let host_gen = C::host_generators(self.params);
        let nested_gen = C::nested_generators(self.params);

        let [cp_host] =
            structured::batch_commit_with_blinds(host_gen, [zero_structured_host], [host_blind]);
        let [cp_nested] = structured::batch_commit_with_blinds(
            nested_gen,
            [zero_structured_nested.clone()],
            [nested_blind],
        );
        let [cp_unstructured] =
            unstructured::batch_commit_with_blinds(host_gen, [zero_unstructured], [host_blind]);

        Proof {
            application: Application {
                circuit_id: CircuitIndex::new(0),
                left_header: vec![C::CircuitField::ZERO; HEADER_SIZE],
                right_header: vec![C::CircuitField::ZERO; HEADER_SIZE],
                rx: cp_host.clone(),
            },
            preamble: Preamble {
                native_rx: cp_host.clone(),
                nested_rx: cp_nested.clone(),
            },
            s_prime: SPrime {
                registry_wx0: cp_unstructured.clone(),
                registry_wx1: cp_unstructured.clone(),
                nested_s_prime_rx: cp_nested.clone(),
            },
            error_n: ErrorN {
                native_rx: cp_host.clone(),
                nested_rx: cp_nested.clone(),
            },
            error_m: ErrorM {
                registry_wy: cp_host.clone(),
                native_rx: cp_host.clone(),
                nested_rx: cp_nested.clone(),
            },
            ab: AB {
                a: cp_host.clone(),
                b: cp_host.clone(),
                c: C::CircuitField::ZERO,
                nested_rx: cp_nested.clone(),
            },
            query: Query {
                registry_xy: cp_unstructured.clone(),
                native_rx: cp_host.clone(),
                nested_rx: cp_nested.clone(),
            },
            f: F {
                aggregated: cp_unstructured.clone(),
                nested_rx: cp_nested.clone(),
            },
            eval: Eval {
                native_rx: cp_host.clone(),
                nested_rx: cp_nested.clone(),
            },
            p: P {
                agg_qx: cp_unstructured,
                v: C::CircuitField::ZERO,
                endoscalar_rx: zero_structured_nested.clone(),
                points_rx: zero_structured_nested.clone(),
                step_rxs: vec![
                    zero_structured_nested.clone();
                    NumStepsLen::<NUM_ENDOSCALING_POINTS>::len()
                ],
            },
            challenges: Challenges::trivial(),
            circuits: InternalCircuits {
                hashes_1: cp_host.clone(),
                hashes_2: cp_host.clone(),
                partial_collapse: cp_host.clone(),
                full_collapse: cp_host.clone(),
                compute_v: cp_host,
            },
        }
    }
}

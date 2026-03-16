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

use crate::header::Header;
use crate::internal::endoscalar::NumStepsLen;
use crate::internal::native::{CircuitProofIndex, RxComponent, RxIndex};
use crate::internal::nested::NUM_ENDOSCALING_POINTS;

/// Represents proof-carrying data, a recursive proof for the correctness of
/// some accompanying data.
pub struct Pcd<'source, C: Cycle, R: Rank, H: Header<C::CircuitField>> {
    proof: Proof<C, R>,
    data: H::Data<'source>,
}

impl<'source, C: Cycle, R: Rank, H: Header<C::CircuitField>> Pcd<'source, C, R, H> {
    /// Returns a reference to the data that the proof accompanies.
    pub fn data(&self) -> &H::Data<'source> {
        &self.data
    }

    /// Returns a reference to the recursive proof.
    pub(crate) fn proof(&self) -> &Proof<C, R> {
        &self.proof
    }

    /// Consumes the proof-carrying data and returns the proof and data
    /// separately.
    pub(crate) fn into_parts(self) -> (Proof<C, R>, H::Data<'source>) {
        (self.proof, self.data)
    }
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
    pub(crate) error_m: ErrorM<C, R>,
    pub(crate) error_n: ErrorN<C, R>,
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

    /// Returns the committed rx polynomial triple for the given [`RxIndex`].
    pub(crate) fn committed_rx(
        &self,
        idx: RxIndex,
    ) -> (
        &structured::Polynomial<C::CircuitField, R>,
        C::CircuitField,
        C::HostCurve,
    ) {
        use RxIndex::*;
        match idx {
            Preamble => (
                &self.preamble.native.rx,
                self.preamble.native.blind,
                self.preamble.native.commitment,
            ),
            ErrorM => (
                &self.error_m.native.rx,
                self.error_m.native.blind,
                self.error_m.native.commitment,
            ),
            ErrorN => (
                &self.error_n.native.rx,
                self.error_n.native.blind,
                self.error_n.native.commitment,
            ),
            Query => (
                &self.query.native.rx,
                self.query.native.blind,
                self.query.native.commitment,
            ),
            Eval => (
                &self.eval.native.rx,
                self.eval.native.blind,
                self.eval.native.commitment,
            ),
            Application => (
                &self.application.rx,
                self.application.blind,
                self.application.commitment,
            ),
            Hashes1 | Hashes2 | PartialCollapse | FullCollapse | ComputeV => {
                let p = self.circuits.get(
                    CircuitProofIndex::from_rx_index(idx)
                        .expect("circuit variant maps to CircuitProofIndex"),
                );
                (&p.rx, p.blind, p.commitment)
            }
        }
    }

    /// Returns the rx polynomial for the given [`RxIndex`].
    pub(crate) fn rx_poly(&self, idx: RxIndex) -> &structured::Polynomial<C::CircuitField, R> {
        self.committed_rx(idx).0
    }

    /// Returns the native-field rx polynomial for the given [`RxComponent`].
    pub(crate) fn native_rx(
        &self,
        component: RxComponent,
    ) -> &structured::Polynomial<C::CircuitField, R> {
        match component {
            RxComponent::AbA => &self.ab.native.a_poly,
            RxComponent::AbB => &self.ab.native.b_poly,
            RxComponent::Rx(idx) => self.rx_poly(idx),
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

        let host_commitment =
            zero_structured_host.commit_to_affine(C::host_generators(self.params), host_blind);
        let nested_commitment = zero_structured_nested
            .commit_to_affine(C::nested_generators(self.params), nested_blind);

        let trivial_bridge = Bridge {
            rx: zero_structured_nested.clone(),
            blind: nested_blind,
            commitment: nested_commitment,
        };

        Proof {
            application: Application {
                circuit_id: CircuitIndex::new(0),
                left_header: vec![C::CircuitField::ZERO; HEADER_SIZE],
                right_header: vec![C::CircuitField::ZERO; HEADER_SIZE],
                rx: zero_structured_host.clone(),
                blind: host_blind,
                commitment: host_commitment,
            },
            preamble: Preamble {
                native: NativePreamble {
                    rx: zero_structured_host.clone(),
                    blind: host_blind,
                    commitment: host_commitment,
                },
                bridge: trivial_bridge.clone(),
            },
            s_prime: SPrime {
                native: NativeSPrime {
                    registry_wx0_poly: zero_unstructured.clone(),
                    registry_wx0_blind: host_blind,
                    registry_wx0_commitment: host_commitment,
                    registry_wx1_poly: zero_unstructured.clone(),
                    registry_wx1_blind: host_blind,
                    registry_wx1_commitment: host_commitment,
                },
                bridge: trivial_bridge.clone(),
            },
            error_m: ErrorM {
                native: NativeErrorM {
                    registry_wy_poly: zero_structured_host.clone(),
                    registry_wy_blind: host_blind,
                    registry_wy_commitment: host_commitment,
                    rx: zero_structured_host.clone(),
                    blind: host_blind,
                    commitment: host_commitment,
                },
                bridge: trivial_bridge.clone(),
            },
            error_n: ErrorN {
                native: NativeErrorN {
                    rx: zero_structured_host.clone(),
                    blind: host_blind,
                    commitment: host_commitment,
                },
                bridge: trivial_bridge.clone(),
            },
            ab: AB {
                native: NativeAB {
                    a_poly: zero_structured_host.clone(),
                    a_blind: host_blind,
                    a_commitment: host_commitment,
                    b_poly: zero_structured_host.clone(),
                    b_blind: host_blind,
                    b_commitment: host_commitment,
                    c: C::CircuitField::ZERO,
                },
                bridge: trivial_bridge.clone(),
            },
            query: Query {
                native: NativeQuery {
                    registry_xy_poly: zero_unstructured.clone(),
                    registry_xy_blind: host_blind,
                    registry_xy_commitment: host_commitment,
                    rx: zero_structured_host.clone(),
                    blind: host_blind,
                    commitment: host_commitment,
                },
                bridge: trivial_bridge.clone(),
            },
            f: F {
                native: NativeF {
                    poly: zero_unstructured.clone(),
                    blind: host_blind,
                    commitment: host_commitment,
                },
                bridge: trivial_bridge.clone(),
            },
            eval: Eval {
                native: NativeEval {
                    rx: zero_structured_host.clone(),
                    blind: host_blind,
                    commitment: host_commitment,
                },
                bridge: trivial_bridge,
            },
            p: P {
                native: NativeP {
                    poly: zero_unstructured.clone(),
                    blind: host_blind,
                    commitment: host_commitment,
                    v: C::CircuitField::ZERO,
                },
                nested: NestedP {
                    endoscalar_rx: zero_structured_nested.clone(),
                    points_rx: zero_structured_nested.clone(),
                    step_rxs: vec![
                        zero_structured_nested.clone();
                        NumStepsLen::<NUM_ENDOSCALING_POINTS>::len()
                    ],
                },
            },
            challenges: Challenges::trivial(),
            circuits: crate::internal::native::CircuitProofValues::from_fn(|_| CircuitProof {
                rx: zero_structured_host.clone(),
                blind: host_blind,
                commitment: host_commitment,
            }),
        }
    }
}

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
    polynomials::{Rank, sparse},
    registry::CircuitIndex,
};
use ragu_primitives::vec::Len;

use alloc::vec;

use crate::header::Header;
use crate::internal::endoscalar::NumStepsLen;
use crate::internal::native::{RxComponent, RxIndex};
use crate::internal::nested;
use crate::internal::nested::NUM_ENDOSCALING_POINTS;

/// Represents proof-carrying data, a recursive proof for the correctness of
/// some accompanying data.
pub struct Pcd<C: Cycle, R: Rank, H: Header<C::CircuitField>> {
    proof: Proof<C, R>,
    data: H::Data,
}

impl<C: Cycle, R: Rank, H: Header<C::CircuitField>> Pcd<C, R, H> {
    /// Returns a reference to the data that the proof accompanies.
    pub fn data(&self) -> &H::Data {
        &self.data
    }

    /// Returns a reference to the recursive proof.
    pub(crate) fn proof(&self) -> &Proof<C, R> {
        &self.proof
    }

    /// Consumes the proof-carrying data and returns the proof and data
    /// separately.
    pub(crate) fn into_parts(self) -> (Proof<C, R>, H::Data) {
        (self.proof, self.data)
    }
}

impl<C: Cycle, R: Rank, H: Header<C::CircuitField>> Clone for Pcd<C, R, H> {
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
    pub(crate) inner_error: InnerError<C, R>,
    pub(crate) outer_error: OuterError<C, R>,
    pub(crate) ab: AB<C, R>,
    pub(crate) query: Query<C, R>,
    pub(crate) f: F<C, R>,
    pub(crate) eval: Eval<C, R>,
    pub(crate) p: P<C, R>,
    pub(crate) challenges: Challenges<C>,
    pub(crate) circuits: InternalCircuits<C, R>,
}

impl<C: Cycle, R: Rank> core::ops::Index<RxIndex> for Proof<C, R> {
    type Output = RxTriple<C, R>;
    fn index(&self, idx: RxIndex) -> &RxTriple<C, R> {
        use RxIndex::*;
        match idx {
            Preamble => &self.preamble.native,
            InnerError => &self.inner_error.native.rx_triple,
            OuterError => &self.outer_error.native,
            Query => &self.query.native.rx_triple,
            Eval => &self.eval.native,
            Application => &self.application.rx_triple,
            Hashes1 => &self.circuits.hashes_1,
            Hashes2 => &self.circuits.hashes_2,
            InnerCollapse => &self.circuits.inner_collapse,
            OuterCollapse => &self.circuits.outer_collapse,
            ComputeV => &self.circuits.compute_v,
        }
    }
}

impl<C: Cycle, R: Rank> core::ops::Index<nested::RxIndex> for Proof<C, R> {
    type Output = sparse::Polynomial<C::ScalarField, R>;
    fn index(&self, idx: nested::RxIndex) -> &sparse::Polynomial<C::ScalarField, R> {
        use nested::RxIndex::*;
        match idx {
            EndoscalingStep(step) => &self.p.nested.step_rxs[step as usize],
            EndoscalarStage => &self.p.nested.endoscalar_rx,
            PointsStage => &self.p.nested.points_rx,
            BridgePreamble => &self.preamble.bridge.rx,
            BridgeSPrime => &self.s_prime.bridge.rx,
            BridgeInnerError => &self.inner_error.bridge.rx,
            BridgeOuterError => &self.outer_error.bridge.rx,
            BridgeAB => &self.ab.bridge.rx,
            BridgeQuery => &self.query.bridge.rx,
            BridgeF => &self.f.bridge.rx,
            BridgeEval => &self.eval.bridge.rx,
        }
    }
}

impl<C: Cycle, R: Rank> Proof<C, R> {
    /// Augment a recursive proof with some data, described by a [`Header`].
    pub fn carry<H: Header<C::CircuitField>>(self, data: H::Data) -> Pcd<C, R, H> {
        Pcd { proof: self, data }
    }

    /// Returns the native-field rx polynomial for the given [`RxIndex`].
    pub(crate) fn native_rx_poly(&self, idx: RxIndex) -> &sparse::Polynomial<C::CircuitField, R> {
        &self[idx].rx
    }

    /// Returns the nested-field rx polynomial for the given [`nested::RxIndex`].
    pub(crate) fn nested_rx_poly(
        &self,
        idx: nested::RxIndex,
    ) -> &sparse::Polynomial<C::ScalarField, R> {
        &self[idx]
    }

    /// Returns the native-field rx polynomial for the given [`RxComponent`].
    pub(crate) fn native_rx(
        &self,
        component: RxComponent,
    ) -> &sparse::Polynomial<C::CircuitField, R> {
        match component {
            RxComponent::AbA => &self.ab.native.a_poly,
            RxComponent::AbB => &self.ab.native.b_poly,
            RxComponent::Rx(idx) => &self[idx].rx,
        }
    }
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> crate::Application<'_, C, R, HEADER_SIZE> {
    pub(crate) fn trivial_pcd(&self) -> Pcd<C, R, ()> {
        self.trivial_proof().carry(())
    }

    pub(crate) fn trivial_proof(&self) -> Proof<C, R> {
        // a[0] = b[0] = c[0] = d[0] = 1, all others zero.
        let ones_host = {
            let mut view = sparse::View::<_, R, _>::trace();
            view.a.push(C::CircuitField::ONE);
            view.b.push(C::CircuitField::ONE);
            view.c.push(C::CircuitField::ONE);
            view.d.push(C::CircuitField::ONE);
            view.build()
        };
        let ones_nested = {
            let mut view = sparse::View::<_, R, _>::trace();
            view.a.push(C::ScalarField::ONE);
            view.b.push(C::ScalarField::ONE);
            view.c.push(C::ScalarField::ONE);
            view.d.push(C::ScalarField::ONE);
            view.build()
        };

        let host_commitment = ones_host.commit_to_affine(C::host_generators(self.params));
        let bridge_commitment = ones_nested.commit_to_affine(C::nested_generators(self.params));

        let challenges = Challenges::trivial();

        // registry_xy must be the actual registry evaluation (fuse cross-checks it).
        let registry_xy_poly = self.native_registry.xy(challenges.x, challenges.y);
        let registry_xy_commitment =
            registry_xy_poly.commit_to_affine(C::host_generators(self.params));

        // Derived values must be consistent with the polynomials.
        let c = ones_host.revdot(&ones_host);
        let v = ones_host.eval(challenges.u);

        let trivial_bridge = Bridge {
            rx: ones_nested.clone(),
            commitment: bridge_commitment,
        };

        let trivial_rx_triple = || RxTriple {
            rx: ones_host.clone(),
            commitment: host_commitment,
        };

        Proof {
            application: Application {
                circuit_id: CircuitIndex::new(0),
                left_header: vec![C::CircuitField::ZERO; HEADER_SIZE],
                right_header: vec![C::CircuitField::ZERO; HEADER_SIZE],
                rx_triple: trivial_rx_triple(),
            },
            preamble: Preamble {
                native: trivial_rx_triple(),
                bridge: trivial_bridge.clone(),
            },
            s_prime: SPrime {
                native: NativeSPrime {
                    // registry_wx0/wx1 are not cross-checked by the verifier,
                    // so placeholder ones polys suffice for the trivial proof.
                    registry_wx0_poly: ones_host.clone(),
                    registry_wx0_commitment: host_commitment,
                    registry_wx1_poly: ones_host.clone(),
                    registry_wx1_commitment: host_commitment,
                },
                bridge: trivial_bridge.clone(),
            },
            inner_error: InnerError {
                native: NativeInnerError {
                    registry_wy_poly: ones_host.clone(),
                    registry_wy_commitment: host_commitment,
                    rx_triple: trivial_rx_triple(),
                },
                bridge: trivial_bridge.clone(),
            },
            outer_error: OuterError {
                native: trivial_rx_triple(),
                bridge: trivial_bridge.clone(),
            },
            ab: AB {
                native: NativeAB {
                    a_poly: ones_host.clone(),
                    a_commitment: host_commitment,
                    b_poly: ones_host.clone(),
                    b_commitment: host_commitment,
                    c,
                },
                bridge: trivial_bridge.clone(),
            },
            query: Query {
                native: NativeQuery {
                    registry_xy_poly,
                    registry_xy_commitment,
                    rx_triple: trivial_rx_triple(),
                },
                bridge: trivial_bridge.clone(),
            },
            f: F {
                native: NativeF {
                    poly: ones_host.clone(),
                    commitment: host_commitment,
                },
                bridge: trivial_bridge.clone(),
            },
            eval: Eval {
                native: trivial_rx_triple(),
                bridge: trivial_bridge,
            },
            p: P {
                native: NativeP {
                    poly: ones_host.clone(),
                    commitment: host_commitment,
                    v,
                },
                nested: NestedP {
                    step_rxs: vec![
                        ones_nested.clone();
                        NumStepsLen::<NUM_ENDOSCALING_POINTS>::len()
                    ],
                    endoscalar_rx: ones_nested.clone(),
                    points_rx: ones_nested,
                },
            },
            challenges,
            circuits: InternalCircuits {
                hashes_1: trivial_rx_triple(),
                hashes_2: trivial_rx_triple(),
                inner_collapse: trivial_rx_triple(),
                outer_collapse: trivial_rx_triple(),
                compute_v: trivial_rx_triple(),
            },
        }
    }
}

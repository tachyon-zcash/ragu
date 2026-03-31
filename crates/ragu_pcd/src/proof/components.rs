//! Proof component structs. Each component pairs a `Native*` struct
//! (host-curve data) with a shared [`Bridge`] struct (cross-curve data
//! that bridges to the inner verifier).

use ff::Field;
use ragu_arithmetic::Cycle;
use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::CircuitIndex,
};
use ragu_core::{
    drivers::Driver,
    maybe::{Always, Maybe},
};
use ragu_primitives::Element;

use alloc::vec::Vec;

/// A grouped `(rx, commitment)` triple for a native-field rx polynomial.
#[derive(Clone)]
pub struct RxTriple<C: Cycle, R: Rank> {
    /// The rx polynomial.
    pub(crate) rx: sparse::Polynomial<C::CircuitField, R>,

    /// The commitment to `rx`.
    pub(crate) commitment: C::HostCurve,
}

#[derive(Clone)]
pub(crate) struct Application<C: Cycle, R: Rank> {
    pub(crate) circuit_id: CircuitIndex,
    pub(crate) left_header: Vec<C::CircuitField>,
    pub(crate) right_header: Vec<C::CircuitField>,
    pub(crate) rx_triple: RxTriple<C, R>,
}

#[derive(Clone)]
pub(crate) struct Bridge<C: Cycle, R: Rank> {
    pub(crate) rx: sparse::Polynomial<C::ScalarField, R>,
    pub(crate) commitment: C::NestedCurve,
}

impl<C: Cycle, R: Rank> Bridge<C, R> {
    pub(crate) fn commit(params: &C::Params, rx: sparse::Polynomial<C::ScalarField, R>) -> Self {
        let commitment = rx.commit_to_affine(C::nested_generators(params));
        Bridge { rx, commitment }
    }
}

#[derive(Clone)]
pub(crate) struct Preamble<C: Cycle, R: Rank> {
    pub(crate) native: RxTriple<C, R>,
    pub(crate) bridge: Bridge<C, R>,
    pub(crate) left_child_bridges: ChildBridges<C, R>,
    pub(crate) right_child_bridges: ChildBridges<C, R>,
}

#[derive(Clone)]
pub(crate) struct NativeSPrime<C: Cycle, R: Rank> {
    pub(crate) registry_wx0_poly: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) registry_wx0_commitment: C::HostCurve,
    pub(crate) registry_wx1_poly: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) registry_wx1_commitment: C::HostCurve,
}

#[derive(Clone)]
pub(crate) struct SPrime<C: Cycle, R: Rank> {
    pub(crate) native: NativeSPrime<C, R>,
    pub(crate) bridge: Bridge<C, R>,
}

#[derive(Clone)]
pub(crate) struct NativeInnerError<C: Cycle, R: Rank> {
    pub(crate) registry_wy_poly: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) registry_wy_commitment: C::HostCurve,
    pub(crate) rx_triple: RxTriple<C, R>,
}

#[derive(Clone)]
pub(crate) struct InnerError<C: Cycle, R: Rank> {
    pub(crate) native: NativeInnerError<C, R>,
    pub(crate) bridge: Bridge<C, R>,
}

#[derive(Clone)]
pub(crate) struct OuterError<C: Cycle, R: Rank> {
    pub(crate) native: RxTriple<C, R>,
    pub(crate) bridge: Bridge<C, R>,
}

#[derive(Clone)]
pub(crate) struct NativeAB<C: Cycle, R: Rank> {
    pub(crate) a_poly: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) a_commitment: C::HostCurve,
    pub(crate) b_poly: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) b_commitment: C::HostCurve,
    pub(crate) c: C::CircuitField,
}

#[derive(Clone)]
pub(crate) struct AB<C: Cycle, R: Rank> {
    pub(crate) native: NativeAB<C, R>,
    pub(crate) bridge: Bridge<C, R>,
}

#[derive(Clone)]
pub(crate) struct NativeQuery<C: Cycle, R: Rank> {
    pub(crate) registry_xy_poly: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) registry_xy_commitment: C::HostCurve,
    pub(crate) rx_triple: RxTriple<C, R>,
}

#[derive(Clone)]
pub(crate) struct Query<C: Cycle, R: Rank> {
    pub(crate) native: NativeQuery<C, R>,
    pub(crate) bridge: Bridge<C, R>,
}

#[derive(Clone)]
pub(crate) struct NativeF<C: Cycle, R: Rank> {
    pub(crate) poly: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) commitment: C::HostCurve,
}

#[derive(Clone)]
pub(crate) struct F<C: Cycle, R: Rank> {
    pub(crate) native: NativeF<C, R>,
    pub(crate) bridge: Bridge<C, R>,
}

#[derive(Clone)]
pub(crate) struct Eval<C: Cycle, R: Rank> {
    pub(crate) native: RxTriple<C, R>,
    pub(crate) bridge: Bridge<C, R>,
}

#[derive(Clone)]
pub(crate) struct NativeP<C: Cycle, R: Rank> {
    pub(crate) poly: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) commitment: C::HostCurve,
    pub(crate) v: C::CircuitField,
}

#[derive(Clone)]
pub(crate) struct P<C: Cycle, R: Rank> {
    pub(crate) native: NativeP<C, R>,
}

#[derive(Clone)]
pub(crate) struct Challenges<C: Cycle> {
    pub(crate) w: C::CircuitField,
    pub(crate) y: C::CircuitField,
    pub(crate) z: C::CircuitField,
    pub(crate) mu: C::CircuitField,
    pub(crate) nu: C::CircuitField,
    pub(crate) mu_prime: C::CircuitField,
    pub(crate) nu_prime: C::CircuitField,
    pub(crate) x: C::CircuitField,
    pub(crate) alpha: C::CircuitField,
    pub(crate) u: C::CircuitField,
    /// Pre-endoscalar beta challenge. Effective beta is derived via endoscalar extraction.
    pub(crate) pre_beta: C::CircuitField,
}

impl<C: Cycle> Challenges<C> {
    pub(crate) fn new<'dr, D>(
        w: &Element<'dr, D>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        mu: &Element<'dr, D>,
        nu: &Element<'dr, D>,
        mu_prime: &Element<'dr, D>,
        nu_prime: &Element<'dr, D>,
        x: &Element<'dr, D>,
        alpha: &Element<'dr, D>,
        u: &Element<'dr, D>,
        pre_beta: &Element<'dr, D>,
    ) -> Self
    where
        D: Driver<'dr, F = C::CircuitField, MaybeKind = Always<()>>,
    {
        Self {
            w: *w.value().take(),
            y: *y.value().take(),
            z: *z.value().take(),
            mu: *mu.value().take(),
            nu: *nu.value().take(),
            mu_prime: *mu_prime.value().take(),
            nu_prime: *nu_prime.value().take(),
            x: *x.value().take(),
            alpha: *alpha.value().take(),
            u: *u.value().take(),
            pre_beta: *pre_beta.value().take(),
        }
    }

    pub(crate) fn trivial() -> Self {
        Self {
            w: C::CircuitField::ONE,
            y: C::CircuitField::ONE,
            z: C::CircuitField::ONE,
            mu: C::CircuitField::ONE,
            nu: C::CircuitField::ONE,
            mu_prime: C::CircuitField::ONE,
            nu_prime: C::CircuitField::ONE,
            x: C::CircuitField::ONE,
            alpha: C::CircuitField::ONE,
            u: C::CircuitField::ONE,
            pre_beta: C::CircuitField::ONE,
        }
    }
}

/// Bridge rx polynomials preserved from a child proof for the copying circuit.
///
/// Each field is a scalar-field rx polynomial from the corresponding bridge
/// stage of the child proof. Only the rx polynomial is stored; the nested-curve
/// commitment is derivable from it and never needed after construction.
#[derive(Clone)]
pub(crate) struct ChildBridges<C: Cycle, R: Rank> {
    pub(crate) inner_error: Bridge<C, R>,
    pub(crate) outer_error: Bridge<C, R>,
    pub(crate) ab: Bridge<C, R>,
    pub(crate) query: Bridge<C, R>,
    pub(crate) eval: Bridge<C, R>,
    pub(crate) points: Bridge<C, R>,
}

impl<C: Cycle, R: Rank> ChildBridges<C, R> {
    /// Returns the rx polynomial for the given child bridge [`RxIndex`](crate::internal::nested::RxIndex) variant.
    pub(crate) fn rx(
        &self,
        idx: crate::internal::nested::RxIndex,
    ) -> &sparse::Polynomial<C::ScalarField, R> {
        use crate::internal::nested::RxIndex::*;
        match idx {
            ChildBridgeInnerError(_) => &self.inner_error.rx,
            ChildBridgeOuterError(_) => &self.outer_error.rx,
            ChildBridgeAB(_) => &self.ab.rx,
            ChildBridgeQuery(_) => &self.query.rx,
            ChildBridgeEval(_) => &self.eval.rx,
            ChildPointsStage(_) => &self.points.rx,
            _ => unreachable!(),
        }
    }
}

/// Rx polynomials for all internal circuits in a single proof step.
///
/// The first five fields are native-field circuits: each is an [`RxTriple`]
/// pairing the rx polynomial (over `C::CircuitField`) with its host-curve
/// commitment.
///
/// The remaining fields are nested-field circuits: bare rx polynomials over
/// `C::ScalarField` for the endoscaling commitment computation (no host-curve
/// commitment; verified via the nested registry).
#[derive(Clone)]
pub(crate) struct InternalCircuits<C: Cycle, R: Rank> {
    pub(crate) hashes_1: RxTriple<C, R>,
    pub(crate) hashes_2: RxTriple<C, R>,
    pub(crate) inner_collapse: RxTriple<C, R>,
    pub(crate) outer_collapse: RxTriple<C, R>,
    pub(crate) compute_v: RxTriple<C, R>,
    pub(crate) step_rxs: Vec<sparse::Polynomial<C::ScalarField, R>>,
    pub(crate) endoscalar_rx: sparse::Polynomial<C::ScalarField, R>,
    pub(crate) points_rx: sparse::Polynomial<C::ScalarField, R>,
}

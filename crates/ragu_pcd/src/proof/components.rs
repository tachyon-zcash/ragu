#![allow(dead_code)]

use ff::Field;
use ragu_arithmetic::Cycle;
use ragu_circuits::{
    polynomials::{CommittedPolynomial, Rank, structured, unstructured},
    registry::CircuitIndex,
};
use ragu_core::{
    drivers::Driver,
    maybe::{Always, Maybe},
};
use ragu_primitives::Element;

use alloc::vec::Vec;

#[derive(Clone)]
pub(crate) struct Application<C: Cycle, R: Rank> {
    pub(crate) circuit_id: CircuitIndex,
    pub(crate) left_header: Vec<C::CircuitField>,
    pub(crate) right_header: Vec<C::CircuitField>,
    pub(crate) rx: CommittedPolynomial<structured::Polynomial<C::CircuitField, R>, C::HostCurve>,
}

#[derive(Clone)]
pub(crate) struct Preamble<C: Cycle, R: Rank> {
    pub(crate) native_rx:
        CommittedPolynomial<structured::Polynomial<C::CircuitField, R>, C::HostCurve>,
    pub(crate) nested_rx:
        CommittedPolynomial<structured::Polynomial<C::ScalarField, R>, C::NestedCurve>,
}

#[derive(Clone)]
pub(crate) struct SPrime<C: Cycle, R: Rank> {
    pub(crate) registry_wx0:
        CommittedPolynomial<unstructured::Polynomial<C::CircuitField, R>, C::HostCurve>,
    pub(crate) registry_wx1:
        CommittedPolynomial<unstructured::Polynomial<C::CircuitField, R>, C::HostCurve>,
    pub(crate) nested_s_prime_rx:
        CommittedPolynomial<structured::Polynomial<C::ScalarField, R>, C::NestedCurve>,
}

#[derive(Clone)]
pub(crate) struct ErrorM<C: Cycle, R: Rank> {
    pub(crate) registry_wy:
        CommittedPolynomial<structured::Polynomial<C::CircuitField, R>, C::HostCurve>,
    pub(crate) native_rx:
        CommittedPolynomial<structured::Polynomial<C::CircuitField, R>, C::HostCurve>,
    pub(crate) nested_rx:
        CommittedPolynomial<structured::Polynomial<C::ScalarField, R>, C::NestedCurve>,
}

#[derive(Clone)]
pub(crate) struct ErrorN<C: Cycle, R: Rank> {
    pub(crate) native_rx:
        CommittedPolynomial<structured::Polynomial<C::CircuitField, R>, C::HostCurve>,
    pub(crate) nested_rx:
        CommittedPolynomial<structured::Polynomial<C::ScalarField, R>, C::NestedCurve>,
}

#[derive(Clone)]
pub(crate) struct AB<C: Cycle, R: Rank> {
    pub(crate) a: CommittedPolynomial<structured::Polynomial<C::CircuitField, R>, C::HostCurve>,
    pub(crate) b: CommittedPolynomial<structured::Polynomial<C::CircuitField, R>, C::HostCurve>,
    pub(crate) c: C::CircuitField,
    pub(crate) nested_rx:
        CommittedPolynomial<structured::Polynomial<C::ScalarField, R>, C::NestedCurve>,
}

#[derive(Clone)]
pub(crate) struct Query<C: Cycle, R: Rank> {
    pub(crate) registry_xy:
        CommittedPolynomial<unstructured::Polynomial<C::CircuitField, R>, C::HostCurve>,
    pub(crate) native_rx:
        CommittedPolynomial<structured::Polynomial<C::CircuitField, R>, C::HostCurve>,
    pub(crate) nested_rx:
        CommittedPolynomial<structured::Polynomial<C::ScalarField, R>, C::NestedCurve>,
}

#[derive(Clone)]
pub(crate) struct F<C: Cycle, R: Rank> {
    pub(crate) poly:
        CommittedPolynomial<unstructured::Polynomial<C::CircuitField, R>, C::HostCurve>,
    pub(crate) nested_rx:
        CommittedPolynomial<structured::Polynomial<C::ScalarField, R>, C::NestedCurve>,
}

#[derive(Clone)]
pub(crate) struct Eval<C: Cycle, R: Rank> {
    pub(crate) native_rx:
        CommittedPolynomial<structured::Polynomial<C::CircuitField, R>, C::HostCurve>,
    pub(crate) nested_rx:
        CommittedPolynomial<structured::Polynomial<C::ScalarField, R>, C::NestedCurve>,
}

#[derive(Clone)]
pub(crate) struct P<C: Cycle, R: Rank> {
    pub(crate) poly:
        CommittedPolynomial<unstructured::Polynomial<C::CircuitField, R>, C::HostCurve>,
    pub(crate) v: C::CircuitField,
    pub(crate) endoscalar_rx: structured::Polynomial<C::ScalarField, R>,
    pub(crate) points_rx: structured::Polynomial<C::ScalarField, R>,
    pub(crate) step_rxs: Vec<structured::Polynomial<C::ScalarField, R>>,
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
            w: C::CircuitField::ZERO,
            y: C::CircuitField::ZERO,
            z: C::CircuitField::ZERO,
            mu: C::CircuitField::ZERO,
            nu: C::CircuitField::ZERO,
            mu_prime: C::CircuitField::ZERO,
            nu_prime: C::CircuitField::ZERO,
            x: C::CircuitField::ZERO,
            alpha: C::CircuitField::ZERO,
            u: C::CircuitField::ZERO,
            pre_beta: C::CircuitField::ZERO,
        }
    }
}

#[derive(Clone)]
pub(crate) struct InternalCircuits<C: Cycle, R: Rank> {
    pub(crate) hashes_1:
        CommittedPolynomial<structured::Polynomial<C::CircuitField, R>, C::HostCurve>,
    pub(crate) hashes_2:
        CommittedPolynomial<structured::Polynomial<C::CircuitField, R>, C::HostCurve>,
    pub(crate) partial_collapse:
        CommittedPolynomial<structured::Polynomial<C::CircuitField, R>, C::HostCurve>,
    pub(crate) full_collapse:
        CommittedPolynomial<structured::Polynomial<C::CircuitField, R>, C::HostCurve>,
    pub(crate) compute_v:
        CommittedPolynomial<structured::Polynomial<C::CircuitField, R>, C::HostCurve>,
}

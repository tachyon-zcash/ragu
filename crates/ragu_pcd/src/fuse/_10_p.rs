//! Accumulate $p(X)$.
//!
//! This creates the [`proof::P`] component of the proof, which contains the
//! accumulated polynomial $p(X)$ and its claimed evaluation $p(u) = v$.
//!
//! The commitment is derived as a linear combination of all constituent
//! polynomial commitments using additive homomorphism:
//! $\text{commit}(\sum\_j \beta^j \cdot p\_j) = \sum\_j \beta^j \cdot C\_j$.
//!
//! The commitment is computed via [`PointsWitness`] Horner evaluation.
//! The [`PointsWitness`] and [`Uendo`] endoscalar are returned alongside the proof
//! component so that [`super::_11_circuits`] can create the corresponding
//! nested circuit traces.

use alloc::vec::Vec;
use core::ops::AddAssign;
use ragu_arithmetic::{Cycle, Uendo};
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::{Element, extract_endoscalar, lift_endoscalar};

use crate::internal::endoscalar::PointsWitness;
use crate::internal::native::RxIndex;
use crate::internal::nested::NUM_ENDOSCALING_POINTS;
use crate::{Application, Proof, proof};

/// Accumulates polynomials with their commitments.
struct Accumulator<'a, C: Cycle, R: Rank> {
    poly: &'a mut sparse::Polynomial<C::CircuitField, R>,
    commitments: &'a mut Vec<C::HostCurve>,
    beta: C::CircuitField,
}

impl<C: Cycle, R: Rank> Accumulator<'_, C, R> {
    fn acc<P>(&mut self, poly: &P, commitment: C::HostCurve)
    where
        for<'p> sparse::Polynomial<C::CircuitField, R>: AddAssign<&'p P>,
    {
        self.poly.scale(self.beta);
        *self.poly += poly;
        self.commitments.push(commitment);
    }
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    pub(super) fn compute_p<'dr, D>(
        &self,
        pre_beta: &Element<'dr, D>,
        u: &Element<'dr, D>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        s_prime: &proof::SPrime<C, R>,
        inner_error: &proof::InnerError<C, R>,
        ab: &proof::AB<C, R>,
        query: &proof::Query<C, R>,
        f: &proof::F<C, R>,
    ) -> Result<(
        proof::P<C, R>,
        Uendo,
        PointsWitness<C::HostCurve, NUM_ENDOSCALING_POINTS>,
    )>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let mut poly = f.native.poly.clone();

        // Collect commitments for PointsWitness construction.
        let mut commitments: Vec<C::HostCurve> = Vec::new();

        // The orderings in this code must match the `Write` serialization
        // order of `native::stages::eval::Output`.
        //
        // We accumulate polynomials while collecting MSM terms for the
        // commitment computation.

        // Extract endoscalar from pre_beta and compute effective beta
        let pre_beta_value = *pre_beta.value().take();
        let beta_endo = extract_endoscalar(pre_beta_value);
        let effective_beta = lift_endoscalar(beta_endo);

        {
            let mut acc: Accumulator<'_, C, R> = Accumulator {
                poly: &mut poly,
                commitments: &mut commitments,
                beta: effective_beta,
            };

            // This accumulation order must match the loading circuit in
            // `nested::circuits::loading::Loading`.
            for proof in [left, right] {
                for &id in &RxIndex::ALL {
                    let t = &proof[id];
                    acc.acc(&t.rx, t.commitment);
                }
                acc.acc(&proof.ab.native.a_poly, proof.ab.native.a_commitment);
                acc.acc(&proof.ab.native.b_poly, proof.ab.native.b_commitment);
                acc.acc(
                    &proof.query.native.registry_xy_poly,
                    proof.query.native.registry_xy_commitment,
                );
                acc.acc(&proof.p.native.poly, proof.p.native.commitment);
            }

            acc.acc(
                &s_prime.native.registry_wx0_poly,
                s_prime.native.registry_wx0_commitment,
            );
            acc.acc(
                &s_prime.native.registry_wx1_poly,
                s_prime.native.registry_wx1_commitment,
            );
            acc.acc(
                &inner_error.native.registry_wy_poly,
                inner_error.native.registry_wy_commitment,
            );
            acc.acc(&ab.native.a_poly, ab.native.a_commitment);
            acc.acc(&ab.native.b_poly, ab.native.b_commitment);
            acc.acc(
                &query.native.registry_xy_poly,
                query.native.registry_xy_commitment,
            );
        }

        // Construct commitment via PointsWitness Horner evaluation.
        // Points order: [f.commitment, commitments...] computes β^n·f + β^{n-1}·C₀ + ...
        let witness = {
            let mut points = Vec::with_capacity(NUM_ENDOSCALING_POINTS);
            points.push(f.native.commitment);
            points.extend_from_slice(&commitments);

            PointsWitness::<C::HostCurve, NUM_ENDOSCALING_POINTS>::new(beta_endo, &points)
        };

        let commitment = *witness
            .interstitials
            .last()
            .expect("NumStepsLen guarantees at least one interstitial");

        let v = poly.eval(*u.value().take());

        Ok((
            proof::P {
                native: proof::NativeP {
                    poly,
                    commitment,
                    v,
                },
            },
            beta_endo,
            witness,
        ))
    }
}

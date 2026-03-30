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

use alloc::vec::Vec;
use core::ops::AddAssign;
use ff::Field;
use ragu_arithmetic::Cycle;
use ragu_circuits::{
    CircuitExt,
    polynomials::{Rank, sparse},
    staging::{MultiStage, StageExt},
};
use ragu_core::{Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::{Element, extract_endoscalar, lift_endoscalar, vec::Len};

use crate::internal::endoscalar::{
    EndoscalarStage, EndoscalingStep, EndoscalingStepWitness, NumStepsLen, PointsStage,
    PointsWitness,
};
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
    pub(super) fn compute_p<'dr, D, RNG: rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        pre_beta: &Element<'dr, D>,
        u: &Element<'dr, D>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        s_prime: &proof::SPrime<C, R>,
        inner_error: &proof::InnerError<C, R>,
        ab: &proof::AB<C, R>,
        query: &proof::Query<C, R>,
        f: &proof::F<C, R>,
    ) -> Result<proof::P<C, R>>
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
        let (commitment, endoscalar_rx, points_rx, step_rxs) = {
            let mut points = Vec::with_capacity(NUM_ENDOSCALING_POINTS);
            points.push(f.native.commitment);
            points.extend_from_slice(&commitments);

            let witness =
                PointsWitness::<C::HostCurve, NUM_ENDOSCALING_POINTS>::new(beta_endo, &points);

            let endoscalar_rx = <EndoscalarStage as StageExt<C::ScalarField, R>>::rx(
                C::ScalarField::random(&mut *rng),
                beta_endo,
            )?;
            let points_rx = <PointsStage<C::HostCurve, NUM_ENDOSCALING_POINTS> as StageExt<
                C::ScalarField,
                R,
            >>::rx(C::ScalarField::random(&mut *rng), &witness)?;

            // Create rx polynomials for each endoscaling step circuit
            let num_steps = NumStepsLen::<NUM_ENDOSCALING_POINTS>::len();
            let mut step_rxs = Vec::with_capacity(num_steps);
            for step in 0..num_steps {
                let step_circuit =
                    EndoscalingStep::<C::HostCurve, R, NUM_ENDOSCALING_POINTS>::new(step);
                let staged = MultiStage::new(step_circuit);
                let step_trace = staged
                    .trace(EndoscalingStepWitness {
                        endoscalar: beta_endo,
                        points: &witness,
                    })?
                    .into_output();
                let step_rx = self.nested_registry.assemble(
                    &step_trace,
                    crate::internal::nested::InternalCircuitIndex::EndoscalingStep(step as u32)
                        .circuit_index(),
                    &mut *rng,
                )?;
                step_rxs.push(step_rx);
            }

            (
                *witness
                    .interstitials
                    .last()
                    .expect("NumStepsLen guarantees at least one interstitial"),
                endoscalar_rx,
                points_rx,
                step_rxs,
            )
        };

        let v = poly.eval(*u.value().take());

        Ok(proof::P {
            native: proof::NativeP {
                poly,
                commitment,
                v,
            },
            nested: proof::NestedP {
                step_rxs,
                endoscalar_rx,
                points_rx,
            },
        })
    }
}

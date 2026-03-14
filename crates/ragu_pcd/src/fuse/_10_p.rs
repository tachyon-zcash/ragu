//! Accumulate $p(X)$.
//!
//! This creates the [`proof::P`] component of the proof, which contains the
//! accumulated polynomial $p(X)$ and its claimed evaluation $p(u) = v$.
//!
//! The commitment and blinding factor are derived as linear combinations of
//! all constituent polynomial commitments/blinds using the additive
//! homomorphism of Pedersen commitments:
//! `commit(Σ β^j * p_j, Σ β^j * r_j) = Σ β^j * C_j`.
//!
//! The commitment is computed via [`PointsWitness`] Horner evaluation.

use alloc::vec::Vec;
use core::ops::AddAssign;
use ragu_arithmetic::Cycle;
use ragu_circuits::{
    CircuitExt,
    polynomials::{Rank, unstructured},
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
use crate::proof::{Challenge, ChallengePreBeta, ChallengeU};
use crate::{Application, Proof, proof};

/// Accumulates polynomials with their blinds and commitments.
struct Accumulator<'a, C: Cycle, R: Rank> {
    poly: &'a mut unstructured::Polynomial<C::CircuitField, R>,
    blind: &'a mut C::CircuitField,
    commitments: &'a mut Vec<C::HostCurve>,
    beta: C::CircuitField,
}

impl<C: Cycle, R: Rank> Accumulator<'_, C, R> {
    fn acc<P>(&mut self, poly: &P, blind: C::CircuitField, commitment: C::HostCurve)
    where
        for<'p> unstructured::Polynomial<C::CircuitField, R>: AddAssign<&'p P>,
    {
        self.poly.scale(self.beta);
        *self.poly += poly;
        *self.blind = self.beta * *self.blind + blind;
        self.commitments.push(commitment);
    }
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    pub(super) fn compute_p<'dr, D>(
        &self,
        pre_beta: &Challenge<Element<'dr, D>, ChallengePreBeta>,
        u: &Challenge<Element<'dr, D>, ChallengeU>,
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
        let mut blind = f.native.blind;

        // Collect commitments for PointsWitness construction.
        let mut commitments: Vec<C::HostCurve> = Vec::new();

        // The orderings in this code must match the `Write` serialization
        // order of `native::stages::eval::Output`.
        //
        // We accumulate polynomial and blind in lock-step, while collecting
        // MSM terms for the commitment computation.

        // Extract endoscalar from pre_beta and compute effective beta
        let pre_beta_value = *pre_beta.value().take();
        let beta_endo = extract_endoscalar(pre_beta_value);
        let effective_beta = lift_endoscalar(beta_endo);

        {
            let mut acc: Accumulator<'_, C, R> = Accumulator {
                poly: &mut poly,
                blind: &mut blind,
                commitments: &mut commitments,
                beta: effective_beta,
            };

            for proof in [left, right] {
                for &id in &RxIndex::ALL {
                    let t = &proof[id];
                    acc.acc(&t.rx, t.blind, t.commitment);
                }
                acc.acc(
                    &proof.ab.native.a_poly,
                    proof.ab.native.a_blind,
                    proof.ab.native.a_commitment,
                );
                acc.acc(
                    &proof.ab.native.b_poly,
                    proof.ab.native.b_blind,
                    proof.ab.native.b_commitment,
                );
                acc.acc(
                    &proof.query.native.registry_xy_poly,
                    proof.query.native.registry_xy_blind,
                    proof.query.native.registry_xy_commitment,
                );
                acc.acc(
                    &proof.p.native.poly,
                    proof.p.native.blind,
                    proof.p.native.commitment,
                );
            }

            acc.acc(
                &s_prime.native.registry_wx0_poly,
                s_prime.native.registry_wx0_blind,
                s_prime.native.registry_wx0_commitment,
            );
            acc.acc(
                &s_prime.native.registry_wx1_poly,
                s_prime.native.registry_wx1_blind,
                s_prime.native.registry_wx1_commitment,
            );
            acc.acc(
                &inner_error.native.registry_wy_poly,
                inner_error.native.registry_wy_blind,
                inner_error.native.registry_wy_commitment,
            );
            acc.acc(&ab.native.a_poly, ab.native.a_blind, ab.native.a_commitment);
            acc.acc(&ab.native.b_poly, ab.native.b_blind, ab.native.b_commitment);
            acc.acc(
                &query.native.registry_xy_poly,
                query.native.registry_xy_blind,
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

            let endoscalar_rx = <EndoscalarStage as StageExt<C::ScalarField, R>>::rx(beta_endo)?;
            let points_rx = <PointsStage<C::HostCurve, NUM_ENDOSCALING_POINTS> as StageExt<
                C::ScalarField,
                R,
            >>::rx(&witness)?;

            // Create rx polynomials for each endoscaling step circuit
            let num_steps = NumStepsLen::<NUM_ENDOSCALING_POINTS>::len();
            let mut step_rxs = Vec::with_capacity(num_steps);
            for step in 0..num_steps {
                let step_circuit =
                    EndoscalingStep::<C::HostCurve, R, NUM_ENDOSCALING_POINTS>::new(step);
                let staged = MultiStage::new(step_circuit);
                let (step_trace, _) = staged.rx(EndoscalingStepWitness {
                    endoscalar: beta_endo,
                    points: &witness,
                })?;
                let step_rx = self.nested_registry.assemble(
                    &step_trace,
                    crate::internal::nested::InternalCircuitIndex::EndoscalingStep(step as u32)
                        .circuit_index(),
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
                blind,
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

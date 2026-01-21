//! Evaluate $p(X)$.
//!
//! This creates the [`proof::P`] component of the proof, which contains the
//! accumulated polynomial $p(X)$ and its claimed evaluation $p(u) = v$.
//!
//! The commitment and blinding factor are derived as linear combinations of
//! the child proof commitments/blinds using the additive homomorphism of
//! Pedersen commitments: `commit(Σ β^j * p_j, Σ β^j * r_j) = Σ β^j * C_j`.
//!
//! The commitment is computed via [`PointsWitness`] Horner evaluation.

use alloc::vec::Vec;
use arithmetic::Cycle;
use core::ops::AddAssign;
use ragu_circuits::{
    CircuitExt,
    polynomials::{Rank, unstructured},
    staging::{StageExt, Staged},
};
use ragu_core::{
    Result,
    drivers::Driver,
    maybe::{Always, Maybe},
};
use ragu_primitives::{Element, compute_endoscalar, extract_endoscalar, vec::Len};

use crate::circuits::nested::NUM_ENDOSCALING_POINTS;
use crate::components::endoscalar::{
    EndoscalarStage, EndoscalingStep, EndoscalingStepWitness, NumStepsLen, PointsStage,
    PointsWitness,
};
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
        pre_beta: &Element<'dr, D>,
        u: &Element<'dr, D>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        s_prime: &proof::SPrime<C, R>,
        error_m: &proof::ErrorM<C, R>,
        ab: &proof::AB<C, R>,
        query: &proof::Query<C, R>,
        f: &proof::F<C, R>,
    ) -> Result<proof::P<C, R>>
    where
        D: Driver<'dr, F = C::CircuitField, MaybeKind = Always<()>>,
    {
        let mut poly = f.poly.clone();
        let mut blind = f.blind;

        // Collect commitments for PointsWitness construction.
        let mut commitments: Vec<C::HostCurve> = Vec::new();

        // The orderings in this code must match the corresponding struct
        // definition ordering of `native::stages::eval::Output`.
        //
        // We accumulate polynomial and blind in lock-step, while collecting
        // MSM terms for the commitment computation.

        // Extract endoscalar from pre_beta and compute effective beta
        let pre_beta_value = *pre_beta.value().take();
        let beta_endo = extract_endoscalar(pre_beta_value);
        let effective_beta = compute_endoscalar(beta_endo);

        {
            let mut acc: Accumulator<'_, C, R> = Accumulator {
                poly: &mut poly,
                blind: &mut blind,
                commitments: &mut commitments,
                beta: effective_beta,
            };

            for proof in [left, right] {
                acc.acc(
                    &proof.application.rx,
                    proof.application.blind,
                    proof.application.commitment,
                );
                acc.acc(
                    &proof.preamble.native_rx,
                    proof.preamble.native_blind,
                    proof.preamble.native_commitment,
                );
                acc.acc(
                    &proof.error_n.native_rx,
                    proof.error_n.native_blind,
                    proof.error_n.native_commitment,
                );
                acc.acc(
                    &proof.error_m.native_rx,
                    proof.error_m.native_blind,
                    proof.error_m.native_commitment,
                );
                acc.acc(&proof.ab.a_poly, proof.ab.a_blind, proof.ab.a_commitment);
                acc.acc(&proof.ab.b_poly, proof.ab.b_blind, proof.ab.b_commitment);
                acc.acc(
                    &proof.query.native_rx,
                    proof.query.native_blind,
                    proof.query.native_commitment,
                );
                acc.acc(
                    &proof.query.mesh_xy_poly,
                    proof.query.mesh_xy_blind,
                    proof.query.mesh_xy_commitment,
                );
                acc.acc(
                    &proof.eval.native_rx,
                    proof.eval.native_blind,
                    proof.eval.native_commitment,
                );
                acc.acc(&proof.p.poly, proof.p.blind, proof.p.commitment);
                acc.acc(
                    &proof.circuits.hashes_1_rx,
                    proof.circuits.hashes_1_blind,
                    proof.circuits.hashes_1_commitment,
                );
                acc.acc(
                    &proof.circuits.hashes_2_rx,
                    proof.circuits.hashes_2_blind,
                    proof.circuits.hashes_2_commitment,
                );
                acc.acc(
                    &proof.circuits.partial_collapse_rx,
                    proof.circuits.partial_collapse_blind,
                    proof.circuits.partial_collapse_commitment,
                );
                acc.acc(
                    &proof.circuits.full_collapse_rx,
                    proof.circuits.full_collapse_blind,
                    proof.circuits.full_collapse_commitment,
                );
                acc.acc(
                    &proof.circuits.compute_v_rx,
                    proof.circuits.compute_v_blind,
                    proof.circuits.compute_v_commitment,
                );
                acc.acc(
                    &proof.circuits.endoscale_challenges_rx,
                    proof.circuits.endoscale_challenges_blind,
                    proof.circuits.endoscale_challenges_commitment,
                );
            }

            acc.acc(
                &s_prime.mesh_wx0_poly,
                s_prime.mesh_wx0_blind,
                s_prime.mesh_wx0_commitment,
            );
            acc.acc(
                &s_prime.mesh_wx1_poly,
                s_prime.mesh_wx1_blind,
                s_prime.mesh_wx1_commitment,
            );
            acc.acc(
                &error_m.mesh_wy_poly,
                error_m.mesh_wy_blind,
                error_m.mesh_wy_commitment,
            );
            acc.acc(&ab.a_poly, ab.a_blind, ab.a_commitment);
            acc.acc(&ab.b_poly, ab.b_blind, ab.b_commitment);
            acc.acc(
                &query.mesh_xy_poly,
                query.mesh_xy_blind,
                query.mesh_xy_commitment,
            );
        }

        // Construct commitment via PointsWitness Horner evaluation.
        // Points order: [f.commitment, commitments...] computes β^n·f + β^{n-1}·C₀ + ...
        let (commitment, endoscalar_rx, points_rx, step_rxs) = {
            let mut points = Vec::with_capacity(NUM_ENDOSCALING_POINTS);
            points.push(f.commitment);
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
            let key = self.nested_mesh.get_key();
            let mut step_rxs = Vec::with_capacity(num_steps);
            for step in 0..num_steps {
                let step_circuit =
                    EndoscalingStep::<C::HostCurve, R, NUM_ENDOSCALING_POINTS>::new(step);
                let staged = Staged::new(step_circuit);
                let (step_rx, _) = staged.rx::<R>(
                    EndoscalingStepWitness {
                        endoscalar: beta_endo,
                        points: &witness,
                    },
                    key,
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
            poly,
            blind,
            commitment,
            v,
            endoscalar_rx,
            points_rx,
            step_rxs,
        })
    }
}

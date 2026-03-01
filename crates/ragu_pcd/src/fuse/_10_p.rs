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
use core::ops::AddAssign;
use ragu_arithmetic::Cycle;
use ragu_circuits::{
    CircuitExt,
    polynomials::{Committable, CommittedPolynomial, Rank, unstructured},
    staging::{MultiStage, StageExt},
};
use ragu_core::{
    Result,
    drivers::Driver,
    maybe::{Always, Maybe},
};
use ragu_primitives::{Element, extract_endoscalar, lift_endoscalar, vec::Len};

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
    fn acc<P>(&mut self, cp: &CommittedPolynomial<P, C::HostCurve>)
    where
        for<'p> unstructured::Polynomial<C::CircuitField, R>: AddAssign<&'p P>,
    {
        self.poly.scale(self.beta);
        *self.poly += cp.poly();
        *self.blind = self.beta * *self.blind + cp.blind();
        self.commitments.push(cp.commitment());
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
        let mut poly = f.poly.poly().clone();
        let mut blind = f.poly.blind();

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
        let effective_beta = lift_endoscalar(beta_endo);

        {
            let mut acc: Accumulator<'_, C, R> = Accumulator {
                poly: &mut poly,
                blind: &mut blind,
                commitments: &mut commitments,
                beta: effective_beta,
            };

            for proof in [left, right] {
                acc.acc(&proof.application.rx);
                acc.acc(&proof.preamble.native_rx);
                acc.acc(&proof.error_n.native_rx);
                acc.acc(&proof.error_m.native_rx);
                acc.acc(&proof.ab.a);
                acc.acc(&proof.ab.b);
                acc.acc(&proof.query.native_rx);
                acc.acc(&proof.query.registry_xy);
                acc.acc(&proof.eval.native_rx);
                acc.acc(&proof.p.poly);
                acc.acc(&proof.circuits.hashes_1);
                acc.acc(&proof.circuits.hashes_2);
                acc.acc(&proof.circuits.partial_collapse);
                acc.acc(&proof.circuits.full_collapse);
                acc.acc(&proof.circuits.compute_v);
            }

            acc.acc(&s_prime.registry_wx0);
            acc.acc(&s_prime.registry_wx1);
            acc.acc(&error_m.registry_wy);
            acc.acc(&ab.a);
            acc.acc(&ab.b);
            acc.acc(&query.registry_xy);
        }

        // Construct commitment via PointsWitness Horner evaluation.
        // Points order: [f.poly.commitment(), commitments...] computes β^n·f + β^{n-1}·C₀ + ...
        let (endoscalar_rx, points_rx, step_rxs) = {
            let mut points = Vec::with_capacity(NUM_ENDOSCALING_POINTS);
            points.push(f.poly.commitment());
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
                    crate::circuits::nested::InternalCircuitIndex::EndoscalingStep(step as u32)
                        .circuit_index(),
                )?;
                step_rxs.push(step_rx);
            }

            (endoscalar_rx, points_rx, step_rxs)
        };

        let v = poly.eval(*u.value().take());
        let poly = poly.commit_with_blind(C::host_generators(self.params), blind);

        Ok(proof::P {
            poly,
            v,
            endoscalar_rx,
            points_rx,
            step_rxs,
        })
    }
}

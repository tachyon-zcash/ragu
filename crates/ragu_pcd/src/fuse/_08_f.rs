//! Evaluates $f(X)$.
//!
//! This creates the [`proof::F`] component of the proof, which is a
//! multi-quotient polynomial that witnesses the correct evaluations of every
//! claimed query in the query stage for all of the committed polynomials so
//! far.
//!
//! Each `factor_iter` call below produces the coefficients of
//! $(p\_i(X) - v\_i) / (X - x\_i)$ for a single query. The total number of
//! terms must match `poly_queries` in the `compute_v` circuit exactly.

use ff::Field;
use ragu_arithmetic::Cycle;
use ragu_circuits::{
    polynomials::{Rank, unstructured},
    staging::StageExt,
};
use ragu_core::{
    Result,
    drivers::Driver,
    maybe::{Always, Maybe},
};
use ragu_primitives::Element;
use rand::CryptoRng;

use alloc::vec::Vec;

use crate::{
    Application, Proof, circuits::native::InternalCircuitIndex, circuits::nested::stages::f, proof,
};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    pub(super) fn compute_f<'dr, D, RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        w: &Element<'dr, D>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        x: &Element<'dr, D>,
        alpha: &Element<'dr, D>,
        s_prime: &proof::SPrime<C, R>,
        error_m: &proof::ErrorM<C, R>,
        ab: &proof::AB<C, R>,
        query: &proof::Query<C, R>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
    ) -> Result<proof::F<C, R>>
    where
        D: Driver<'dr, F = C::CircuitField, MaybeKind = Always<()>>,
    {
        use InternalCircuitIndex::*;
        use ragu_arithmetic::factor_iter;

        let w = *w.value().take();
        let y = *y.value().take();
        let z = *z.value().take();
        let x = *x.value().take();
        let xz = x * z;
        let alpha = *alpha.value().take();

        let omega_j =
            |idx: InternalCircuitIndex| -> C::CircuitField { idx.circuit_index().omega_j() };

        // This must exactly match the ordering of the `poly_queries` function
        // in the `compute_v` circuit.
        let mut iters = [
            factor_iter(left.p.poly.iter_coeffs(), left.challenges.u),
            factor_iter(right.p.poly.iter_coeffs(), right.challenges.u),
            factor_iter(left.query.registry_xy_poly.iter_coeffs(), w),
            factor_iter(right.query.registry_xy_poly.iter_coeffs(), w),
            factor_iter(s_prime.registry_wx0_poly.iter_coeffs(), left.challenges.y),
            factor_iter(s_prime.registry_wx1_poly.iter_coeffs(), right.challenges.y),
            factor_iter(s_prime.registry_wx0_poly.iter_coeffs(), y),
            factor_iter(s_prime.registry_wx1_poly.iter_coeffs(), y),
            factor_iter(error_m.registry_wy_poly.iter_coeffs(), left.challenges.x),
            factor_iter(error_m.registry_wy_poly.iter_coeffs(), right.challenges.x),
            factor_iter(error_m.registry_wy_poly.iter_coeffs(), x),
            factor_iter(query.registry_xy_poly.iter_coeffs(), w),
            factor_iter(query.registry_xy_poly.iter_coeffs(), omega_j(PreambleStage)),
            factor_iter(query.registry_xy_poly.iter_coeffs(), omega_j(ErrorNStage)),
            factor_iter(query.registry_xy_poly.iter_coeffs(), omega_j(ErrorMStage)),
            factor_iter(query.registry_xy_poly.iter_coeffs(), omega_j(QueryStage)),
            factor_iter(query.registry_xy_poly.iter_coeffs(), omega_j(EvalStage)),
            factor_iter(
                query.registry_xy_poly.iter_coeffs(),
                omega_j(ErrorMFinalStaged),
            ),
            factor_iter(
                query.registry_xy_poly.iter_coeffs(),
                omega_j(ErrorNFinalStaged),
            ),
            factor_iter(
                query.registry_xy_poly.iter_coeffs(),
                omega_j(EvalFinalStaged),
            ),
            factor_iter(
                query.registry_xy_poly.iter_coeffs(),
                omega_j(Hashes1Circuit),
            ),
            factor_iter(
                query.registry_xy_poly.iter_coeffs(),
                omega_j(Hashes2Circuit),
            ),
            factor_iter(
                query.registry_xy_poly.iter_coeffs(),
                omega_j(PartialCollapseCircuit),
            ),
            factor_iter(
                query.registry_xy_poly.iter_coeffs(),
                omega_j(FullCollapseCircuit),
            ),
            factor_iter(
                query.registry_xy_poly.iter_coeffs(),
                omega_j(ComputeVCircuit),
            ),
            factor_iter(
                query.registry_xy_poly.iter_coeffs(),
                omega_j(EndoscaleChallengesCircuit),
            ),
            factor_iter(
                query.registry_xy_poly.iter_coeffs(),
                left.application.circuit_id.omega_j(),
            ),
            factor_iter(
                query.registry_xy_poly.iter_coeffs(),
                right.application.circuit_id.omega_j(),
            ),
            // A/B polynomial queries:
            // a_poly at xz, b_poly at x for left child, right child, current
            factor_iter(left.ab.a_poly.iter_coeffs(), xz),
            factor_iter(left.ab.b_poly.iter_coeffs(), x),
            factor_iter(right.ab.a_poly.iter_coeffs(), xz),
            factor_iter(right.ab.b_poly.iter_coeffs(), x),
            factor_iter(ab.a_poly.iter_coeffs(), xz),
            factor_iter(ab.b_poly.iter_coeffs(), x),
            // Per-rx evaluations at xz only. The same r_i(xz) values feed
            // into both A(xz) (undilated) and B(x) (Z-dilated).
            factor_iter(left.preamble.native_rx.iter_coeffs(), xz),
            factor_iter(left.error_n.native_rx.iter_coeffs(), xz),
            factor_iter(left.error_m.native_rx.iter_coeffs(), xz),
            factor_iter(left.query.native_rx.iter_coeffs(), xz),
            factor_iter(left.eval.native_rx.iter_coeffs(), xz),
            factor_iter(left.application.rx.iter_coeffs(), xz),
            factor_iter(left.circuits.hashes_1_rx.iter_coeffs(), xz),
            factor_iter(left.circuits.hashes_2_rx.iter_coeffs(), xz),
            factor_iter(left.circuits.partial_collapse_rx.iter_coeffs(), xz),
            factor_iter(left.circuits.full_collapse_rx.iter_coeffs(), xz),
            factor_iter(left.circuits.compute_v_rx.iter_coeffs(), xz),
            factor_iter(left.circuits.endoscale_challenges_rx.iter_coeffs(), xz),
            factor_iter(right.preamble.native_rx.iter_coeffs(), xz),
            factor_iter(right.error_n.native_rx.iter_coeffs(), xz),
            factor_iter(right.error_m.native_rx.iter_coeffs(), xz),
            factor_iter(right.query.native_rx.iter_coeffs(), xz),
            factor_iter(right.eval.native_rx.iter_coeffs(), xz),
            factor_iter(right.application.rx.iter_coeffs(), xz),
            factor_iter(right.circuits.hashes_1_rx.iter_coeffs(), xz),
            factor_iter(right.circuits.hashes_2_rx.iter_coeffs(), xz),
            factor_iter(right.circuits.partial_collapse_rx.iter_coeffs(), xz),
            factor_iter(right.circuits.full_collapse_rx.iter_coeffs(), xz),
            factor_iter(right.circuits.compute_v_rx.iter_coeffs(), xz),
            factor_iter(right.circuits.endoscale_challenges_rx.iter_coeffs(), xz),
        ];

        let mut coeffs = Vec::new();
        while let Some(first) = iters[0].next() {
            let c = iters[1..]
                .iter_mut()
                .fold(first, |acc, iter| alpha * acc + iter.next().unwrap());
            coeffs.push(c);
        }
        coeffs.reverse();

        let poly = unstructured::Polynomial::from_coeffs(coeffs);
        let blind = C::CircuitField::random(&mut *rng);
        let commitment = poly.commit(C::host_generators(self.params), blind);

        let nested_f_witness = f::Witness {
            native_f: commitment,
        };
        let nested_rx = f::Stage::<C::HostCurve, R>::rx(&nested_f_witness)?;
        let nested_blind = C::ScalarField::random(&mut *rng);
        let nested_commitment = nested_rx.commit(C::nested_generators(self.params), nested_blind);

        Ok(proof::F {
            poly,
            blind,
            commitment,
            nested_rx,
            nested_blind,
            nested_commitment,
        })
    }
}

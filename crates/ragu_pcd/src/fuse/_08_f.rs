//! Evaluates $f(X)$.
//!
//! This creates the [`proof::F`] component of the proof, which is a
//! multi-quotient polynomial that witnesses the correct evaluations of every
//! claimed query in the query stage for all of the committed polynomials so
//! far.
//!
//! Each quotient $(p\_i(X) - v\_i) / (X - x\_i)$ is produced by either a
//! `factor_iter` call (single point) or a `factor_batch_for_each` call (multiple
//! points sharing the same polynomial). The total number of terms must
//! match `poly_queries` in the `compute_v` circuit exactly.

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

fn note_expected_len(expected_len: &mut Option<usize>, len: usize) {
    if let Some(expected) = *expected_len {
        assert_eq!(
            expected, len,
            "mismatched quotient lengths in compute_f: expected {}, got {}",
            expected, len
        );
    } else {
        *expected_len = Some(len);
    }
}

fn add_weighted_iter<F: Field>(
    coeffs_rev: &mut Vec<F>,
    expected_len: &mut Option<usize>,
    weight: F,
    iter: impl Iterator<Item = F>,
) {
    let mut len = 0usize;
    for (row, c) in iter.enumerate() {
        if row == coeffs_rev.len() {
            coeffs_rev.push(F::ZERO);
        }
        coeffs_rev[row] += weight * c;
        len = row + 1;
    }
    note_expected_len(expected_len, len);
}

fn add_weighted_batch<F: Field, I: IntoIterator<Item = F>>(
    coeffs_rev: &mut Vec<F>,
    expected_len: &mut Option<usize>,
    a: I,
    points: &[F],
    weights: &[F],
) where
    I::IntoIter: DoubleEndedIterator,
{
    assert_eq!(points.len(), weights.len());
    let mut len = 0usize;
    ragu_arithmetic::factor_batch_for_each(a, points, |row| {
        if len == coeffs_rev.len() {
            coeffs_rev.push(F::ZERO);
        }
        let mut acc = F::ZERO;
        for i in 0..row.len() {
            acc += weights[i] * row[i];
        }
        coeffs_rev[len] += acc;
        len += 1;
    });
    note_expected_len(expected_len, len);
}

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

        const TERM_COUNT: usize = 55;
        let mut weights = [C::CircuitField::ZERO; TERM_COUNT];
        let mut power = C::CircuitField::ONE;
        for i in (0..TERM_COUNT).rev() {
            weights[i] = power;
            power *= alpha;
        }

        let query_xy_points = [
            w,
            omega_j(PreambleStage),
            omega_j(ErrorNStage),
            omega_j(ErrorMStage),
            omega_j(QueryStage),
            omega_j(EvalStage),
            omega_j(ErrorMFinalStaged),
            omega_j(ErrorNFinalStaged),
            omega_j(EvalFinalStaged),
            omega_j(Hashes1Circuit),
            omega_j(Hashes2Circuit),
            omega_j(PartialCollapseCircuit),
            omega_j(FullCollapseCircuit),
            omega_j(ComputeVCircuit),
            left.application.circuit_id.omega_j(),
            right.application.circuit_id.omega_j(),
        ];
        let error_m_points = [left.challenges.x, right.challenges.x, x];
        let wx0_points = [left.challenges.y, y];
        let wx1_points = [right.challenges.y, y];

        let mut coeffs_rev = Vec::new();
        let mut expected_len = None;

        // This must exactly match the ordering of the `poly_queries` function
        // in the `compute_v` circuit.
        add_weighted_iter(
            &mut coeffs_rev,
            &mut expected_len,
            weights[0],
            factor_iter(left.p.poly.iter_coeffs(), left.challenges.u),
        );
        add_weighted_iter(
            &mut coeffs_rev,
            &mut expected_len,
            weights[1],
            factor_iter(right.p.poly.iter_coeffs(), right.challenges.u),
        );
        add_weighted_iter(
            &mut coeffs_rev,
            &mut expected_len,
            weights[2],
            factor_iter(left.query.registry_xy_poly.iter_coeffs(), w),
        );
        add_weighted_iter(
            &mut coeffs_rev,
            &mut expected_len,
            weights[3],
            factor_iter(right.query.registry_xy_poly.iter_coeffs(), w),
        );

        let wx0_weights = [weights[4], weights[6]];
        add_weighted_batch(
            &mut coeffs_rev,
            &mut expected_len,
            s_prime.registry_wx0_poly.iter_coeffs(),
            &wx0_points,
            &wx0_weights,
        );
        let wx1_weights = [weights[5], weights[7]];
        add_weighted_batch(
            &mut coeffs_rev,
            &mut expected_len,
            s_prime.registry_wx1_poly.iter_coeffs(),
            &wx1_points,
            &wx1_weights,
        );
        add_weighted_batch(
            &mut coeffs_rev,
            &mut expected_len,
            error_m.registry_wy_poly.iter_coeffs(),
            &error_m_points,
            &weights[8..11],
        );
        add_weighted_batch(
            &mut coeffs_rev,
            &mut expected_len,
            query.registry_xy_poly.iter_coeffs(),
            &query_xy_points,
            &weights[11..27],
        );

        // A/B polynomial queries:
        // a_poly at xz, b_poly at x for left child, right child, current
        add_weighted_iter(
            &mut coeffs_rev,
            &mut expected_len,
            weights[27],
            factor_iter(left.ab.a_poly.iter_coeffs(), xz),
        );
        add_weighted_iter(
            &mut coeffs_rev,
            &mut expected_len,
            weights[28],
            factor_iter(left.ab.b_poly.iter_coeffs(), x),
        );
        add_weighted_iter(
            &mut coeffs_rev,
            &mut expected_len,
            weights[29],
            factor_iter(right.ab.a_poly.iter_coeffs(), xz),
        );
        add_weighted_iter(
            &mut coeffs_rev,
            &mut expected_len,
            weights[30],
            factor_iter(right.ab.b_poly.iter_coeffs(), x),
        );
        add_weighted_iter(
            &mut coeffs_rev,
            &mut expected_len,
            weights[31],
            factor_iter(ab.a_poly.iter_coeffs(), xz),
        );
        add_weighted_iter(
            &mut coeffs_rev,
            &mut expected_len,
            weights[32],
            factor_iter(ab.b_poly.iter_coeffs(), x),
        );

        // Per-rx evaluations at xz only. The same r_i(xz) values feed
        // into both A(xz) (undilated) and B(x) (Z-dilated).
        add_weighted_iter(
            &mut coeffs_rev,
            &mut expected_len,
            weights[33],
            factor_iter(left.preamble.native_rx.iter_coeffs(), xz),
        );
        add_weighted_iter(
            &mut coeffs_rev,
            &mut expected_len,
            weights[34],
            factor_iter(left.error_n.native_rx.iter_coeffs(), xz),
        );
        add_weighted_iter(
            &mut coeffs_rev,
            &mut expected_len,
            weights[35],
            factor_iter(left.error_m.native_rx.iter_coeffs(), xz),
        );
        add_weighted_iter(
            &mut coeffs_rev,
            &mut expected_len,
            weights[36],
            factor_iter(left.query.native_rx.iter_coeffs(), xz),
        );
        add_weighted_iter(
            &mut coeffs_rev,
            &mut expected_len,
            weights[37],
            factor_iter(left.eval.native_rx.iter_coeffs(), xz),
        );
        add_weighted_iter(
            &mut coeffs_rev,
            &mut expected_len,
            weights[38],
            factor_iter(left.application.rx.iter_coeffs(), xz),
        );
        add_weighted_iter(
            &mut coeffs_rev,
            &mut expected_len,
            weights[39],
            factor_iter(left.circuits.hashes_1_rx.iter_coeffs(), xz),
        );
        add_weighted_iter(
            &mut coeffs_rev,
            &mut expected_len,
            weights[40],
            factor_iter(left.circuits.hashes_2_rx.iter_coeffs(), xz),
        );
        add_weighted_iter(
            &mut coeffs_rev,
            &mut expected_len,
            weights[41],
            factor_iter(left.circuits.partial_collapse_rx.iter_coeffs(), xz),
        );
        add_weighted_iter(
            &mut coeffs_rev,
            &mut expected_len,
            weights[42],
            factor_iter(left.circuits.full_collapse_rx.iter_coeffs(), xz),
        );
        add_weighted_iter(
            &mut coeffs_rev,
            &mut expected_len,
            weights[43],
            factor_iter(left.circuits.compute_v_rx.iter_coeffs(), xz),
        );
        add_weighted_iter(
            &mut coeffs_rev,
            &mut expected_len,
            weights[44],
            factor_iter(right.preamble.native_rx.iter_coeffs(), xz),
        );
        add_weighted_iter(
            &mut coeffs_rev,
            &mut expected_len,
            weights[45],
            factor_iter(right.error_n.native_rx.iter_coeffs(), xz),
        );
        add_weighted_iter(
            &mut coeffs_rev,
            &mut expected_len,
            weights[46],
            factor_iter(right.error_m.native_rx.iter_coeffs(), xz),
        );
        add_weighted_iter(
            &mut coeffs_rev,
            &mut expected_len,
            weights[47],
            factor_iter(right.query.native_rx.iter_coeffs(), xz),
        );
        add_weighted_iter(
            &mut coeffs_rev,
            &mut expected_len,
            weights[48],
            factor_iter(right.eval.native_rx.iter_coeffs(), xz),
        );
        add_weighted_iter(
            &mut coeffs_rev,
            &mut expected_len,
            weights[49],
            factor_iter(right.application.rx.iter_coeffs(), xz),
        );
        add_weighted_iter(
            &mut coeffs_rev,
            &mut expected_len,
            weights[50],
            factor_iter(right.circuits.hashes_1_rx.iter_coeffs(), xz),
        );
        add_weighted_iter(
            &mut coeffs_rev,
            &mut expected_len,
            weights[51],
            factor_iter(right.circuits.hashes_2_rx.iter_coeffs(), xz),
        );
        add_weighted_iter(
            &mut coeffs_rev,
            &mut expected_len,
            weights[52],
            factor_iter(right.circuits.partial_collapse_rx.iter_coeffs(), xz),
        );
        add_weighted_iter(
            &mut coeffs_rev,
            &mut expected_len,
            weights[53],
            factor_iter(right.circuits.full_collapse_rx.iter_coeffs(), xz),
        );
        add_weighted_iter(
            &mut coeffs_rev,
            &mut expected_len,
            weights[54],
            factor_iter(right.circuits.compute_v_rx.iter_coeffs(), xz),
        );

        let mut coeffs = coeffs_rev;
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

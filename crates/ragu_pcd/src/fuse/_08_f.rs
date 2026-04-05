//! Construct and commit to $f(X)$.
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
    polynomials::{Rank, sparse},
    staging::StageExt,
};
use ragu_core::{Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::Element;
use rand::CryptoRng;

use alloc::{vec, vec::Vec};

use crate::{
    Application, Proof,
    internal::{native, native::RxIndex, nested},
    proof,
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
        inner_error: &proof::InnerError<C, R>,
        ab: &proof::AB<C, R>,
        query: &proof::Query<C, R>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
    ) -> Result<proof::F<C, R>>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let native = self.compute_native_f(
            w,
            y,
            z,
            x,
            alpha,
            s_prime,
            inner_error,
            ab,
            query,
            left,
            right,
        )?;

        let bridge = proof::Bridge::commit(
            self.params,
            nested::stages::f::Stage::<C::HostCurve, R>::rx(
                C::ScalarField::random(&mut *rng),
                &nested::stages::f::Witness {
                    native_f: native.commitment,
                },
            )?,
        );

        Ok(proof::F { native, bridge })
    }

    fn compute_native_f<'dr, D>(
        &self,
        w: &Element<'dr, D>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        x: &Element<'dr, D>,
        alpha: &Element<'dr, D>,
        s_prime: &proof::SPrime<C, R>,
        inner_error: &proof::InnerError<C, R>,
        ab: &proof::AB<C, R>,
        query: &proof::Query<C, R>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
    ) -> Result<proof::NativeF<C, R>>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        use ragu_arithmetic::factor_iter;

        let w = *w.value().take();
        let y = *y.value().take();
        let z = *z.value().take();
        let x = *x.value().take();
        let xz = x * z;
        let alpha = *alpha.value().take();

        let omega_j = |idx: native::InternalCircuitIndex| -> C::CircuitField {
            idx.circuit_index().omega_j()
        };

        // This must exactly match the ordering of the `poly_queries` function
        // in the `compute_v` circuit.
        let mut iters: Vec<_> = vec![
            // Child proof p(u)=v checks
            factor_iter(left.p.native.poly.iter_coeffs(), left.challenges.u),
            factor_iter(right.p.native.poly.iter_coeffs(), right.challenges.u),
            // Registry transitions
            factor_iter(left.query.native.registry_xy_poly.iter_coeffs(), w),
            factor_iter(right.query.native.registry_xy_poly.iter_coeffs(), w),
            factor_iter(
                s_prime.native.registry_wx0_poly.iter_coeffs(),
                left.challenges.y,
            ),
            factor_iter(
                s_prime.native.registry_wx1_poly.iter_coeffs(),
                right.challenges.y,
            ),
            factor_iter(s_prime.native.registry_wx0_poly.iter_coeffs(), y),
            factor_iter(s_prime.native.registry_wx1_poly.iter_coeffs(), y),
            factor_iter(
                inner_error.native.registry_wy_poly.iter_coeffs(),
                left.challenges.x,
            ),
            factor_iter(
                inner_error.native.registry_wy_poly.iter_coeffs(),
                right.challenges.x,
            ),
            factor_iter(inner_error.native.registry_wy_poly.iter_coeffs(), x),
            factor_iter(query.native.registry_xy_poly.iter_coeffs(), w),
            // App circuit registry evals
            factor_iter(
                query.native.registry_xy_poly.iter_coeffs(),
                left.application.circuit_id.omega_j(),
            ),
            factor_iter(
                query.native.registry_xy_poly.iter_coeffs(),
                right.application.circuit_id.omega_j(),
            ),
            // A/B polynomial queries:
            // a_poly at xz, b_poly at x for left child, right child, current
            factor_iter(left.ab.native.a_poly.iter_coeffs(), xz),
            factor_iter(left.ab.native.b_poly.iter_coeffs(), x),
            factor_iter(right.ab.native.a_poly.iter_coeffs(), xz),
            factor_iter(right.ab.native.b_poly.iter_coeffs(), x),
            factor_iter(ab.native.a_poly.iter_coeffs(), xz),
            factor_iter(ab.native.b_poly.iter_coeffs(), x),
        ];
        // Per-rx evaluations at xz only. The same r_i(xz) values feed
        // into both A(xz) (undilated) and B(x) (Z-dilated).
        for proof in [left, right] {
            for &id in &RxIndex::ALL {
                iters.push(factor_iter(proof.native_rx_poly(id).iter_coeffs(), xz));
            }
        }

        // m(\omega^j, x, y) evaluations for each internal index j
        for &id in &native::InternalCircuitIndex::ALL {
            iters.push(factor_iter(
                query.native.registry_xy_poly.iter_coeffs(),
                omega_j(id),
            ));
        }

        let mut coeffs = Vec::with_capacity(R::num_coeffs());
        let (first, rest) = iters.split_first_mut().unwrap();
        for val in first.by_ref() {
            let c = rest
                .iter_mut()
                .fold(val, |acc, iter| alpha * acc + iter.next().unwrap());
            coeffs.push(c);
        }
        coeffs.reverse();

        let poly = sparse::Polynomial::from_coeffs(coeffs);
        let commitment = poly.commit_to_affine(C::host_generators(self.params));

        Ok(proof::NativeF { poly, commitment })
    }
}

//! Commit to the evaluations of every queried polynomial at $u$.
//!
//! This creates the [`proof::Eval`] component of the proof, which contains
//! evaluations of every committed or accumulated polynomial (thus far) at the
//! point $u$, except $f(u)$ which is _derived_ from said evaluations.

use ff::Field;
use ragu_arithmetic::Cycle;
use ragu_circuits::{polynomials::Rank, staging::StageExt};
use ragu_core::{Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::Element;
use rand::CryptoRng;

use crate::{
    Application, Proof,
    internal::{native, nested},
    proof,
};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    pub(super) fn compute_eval<'dr, D, RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        u: &Element<'dr, D>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        s_prime: &proof::SPrime<C, R>,
        inner_error: &proof::InnerError<C, R>,
        ab: &proof::AB<C, R>,
        query: &proof::Query<C, R>,
    ) -> Result<(
        proof::Eval<C, R>,
        native::stages::eval::Witness<C::CircuitField>,
    )>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let (native_eval, eval_witness) =
            self.compute_native_eval(rng, u, left, right, s_prime, inner_error, ab, query)?;

        let bridge = proof::Bridge::commit(
            self.params,
            nested::stages::eval::Stage::<C::HostCurve, R>::rx(
                C::ScalarField::random(&mut *rng),
                &nested::stages::eval::Witness {
                    native_eval: native_eval.commitment,
                },
            )?,
        );

        Ok((
            proof::Eval {
                native: native_eval,
                bridge,
            },
            eval_witness,
        ))
    }

    fn compute_native_eval<'dr, D, RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        u: &Element<'dr, D>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        s_prime: &proof::SPrime<C, R>,
        inner_error: &proof::InnerError<C, R>,
        ab: &proof::AB<C, R>,
        query: &proof::Query<C, R>,
    ) -> Result<(
        proof::RxTriple<C, R>,
        native::stages::eval::Witness<C::CircuitField>,
    )>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let u = *u.value().take();

        let eval_witness = native::stages::eval::Witness {
            left: native::stages::eval::ChildEvaluationsWitness::from_proof(left, u),
            right: native::stages::eval::ChildEvaluationsWitness::from_proof(right, u),
            current: native::stages::eval::CurrentStepWitness {
                // TODO: the registry evaluations here could _theoretically_ be more
                // efficient if they're computed simultaneously with assistance
                // from the registry itself, rather than individually evaluated for
                // each of these restrictions.
                registry_wx0: s_prime.native.registry_wx0_poly.eval(u),
                registry_wx1: s_prime.native.registry_wx1_poly.eval(u),
                registry_wy: inner_error.native.registry_wy_poly.eval(u),
                a_poly: ab.native.a_poly.eval(u),
                b_poly: ab.native.b_poly.eval(u),
                registry_xy: query.native.registry_xy_poly.eval(u),
            },
        };
        let rx = native::stages::eval::Stage::<C, R, HEADER_SIZE>::rx(
            C::CircuitField::random(&mut *rng),
            &eval_witness,
        )?;
        let commitment = rx.commit_to_affine(C::host_generators(self.params));

        Ok((proof::RxTriple { rx, commitment }, eval_witness))
    }
}

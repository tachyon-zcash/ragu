//! Commit to the evaluations of every queried polynomial at $u$.
//!
//! This creates the [`proof::Eval`] component of the proof, which contains
//! evaluations of every committed or accumulated polynomial (thus far) at the
//! point $u$, except $f(u)$ which is _derived_ from said evaluations.

use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::{polynomials::Rank, staging::StageExt};
use ragu_core::{
    Result,
    drivers::Driver,
    maybe::{Always, Maybe},
};
use ragu_primitives::Element;
use rand::Rng;

use crate::{
    Application, Proof,
    circuits::{native::stages::eval, nested},
    proof,
};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    pub(super) fn compute_eval<'dr, D, RNG: Rng>(
        &self,
        rng: &mut RNG,
        u: &Element<'dr, D>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        s_prime: &proof::SPrime<C, R>,
        error_m: &proof::ErrorM<C, R>,
        ab: &proof::AB<C, R>,
        query: &proof::Query<C, R>,
    ) -> Result<(proof::Eval<C, R>, eval::Witness<C::CircuitField>)>
    where
        D: Driver<'dr, F = C::CircuitField, MaybeKind = Always<()>>,
    {
        let u = *u.value().take();

        let eval_witness = eval::Witness {
            left: eval::ChildEvaluationsWitness::from_proof(left, u),
            right: eval::ChildEvaluationsWitness::from_proof(right, u),
            current: eval::CurrentStepWitness {
                // TODO: the registry evaluations here could _theoretically_ be more
                // efficient if they're computed simultaneously with assistance
                // from the registry itself, rather than individually evaluated for
                // each of these restrictions.
                registry_wx0: s_prime.registry_wx0_poly.eval(u),
                registry_wx1: s_prime.registry_wx1_poly.eval(u),
                registry_wy: error_m.registry_wy_poly.eval(u),
                a_poly: ab.a_poly.eval(u),
                b_poly: ab.b_poly.eval(u),
                registry_xy: query.registry_xy_poly.eval(u),
            },
        };
        let native_rx = eval::Stage::<C, R, HEADER_SIZE>::rx(&eval_witness)?;
        let native_blind = C::CircuitField::random(&mut *rng);
        let native_commitment = native_rx.commit(C::host_generators(self.params), native_blind);

        let nested_eval_witness = nested::stages::eval::Witness {
            native_eval: native_commitment,
        };
        let nested_rx = nested::stages::eval::Stage::<C::HostCurve, R>::rx(&nested_eval_witness)?;
        let nested_blind = C::ScalarField::random(&mut *rng);
        let nested_commitment = nested_rx.commit(C::nested_generators(self.params), nested_blind);

        Ok((
            proof::Eval {
                native_rx,
                native_blind,
                native_commitment,
                nested_rx,
                nested_blind,
                nested_commitment,
            },
            eval_witness,
        ))
    }
}

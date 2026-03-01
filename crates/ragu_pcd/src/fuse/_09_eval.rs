//! Commit to the evaluations of every queried polynomial at $u$.
//!
//! This creates the [`proof::Eval`] component of the proof, which contains
//! evaluations of every committed or accumulated polynomial (thus far) at the
//! point $u$, except $f(u)$ which is _derived_ from said evaluations.

use ragu_arithmetic::Cycle;
use ragu_circuits::{
    polynomials::{Committable, Rank},
    staging::StageExt,
};
use ragu_core::{
    Result,
    drivers::Driver,
    maybe::{Always, Maybe},
};
use ragu_primitives::Element;
use rand::CryptoRng;

use crate::{
    Application, Proof,
    circuits::{native::stages::eval, nested},
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
                registry_wx0: s_prime.registry_wx0.poly().eval(u),
                registry_wx1: s_prime.registry_wx1.poly().eval(u),
                registry_wy: error_m.registry_wy.poly().eval(u),
                a_poly: ab.a.poly().eval(u),
                b_poly: ab.b.poly().eval(u),
                registry_xy: query.registry_xy.poly().eval(u),
            },
        };
        let native_rx = eval::Stage::<C, R, HEADER_SIZE>::rx(&eval_witness)?
            .commit(C::host_generators(self.params), rng);

        let nested_eval_witness = nested::stages::eval::Witness {
            native_eval: native_rx.commitment(),
        };
        let nested_rx = nested::stages::eval::Stage::<C::HostCurve, R>::rx(&nested_eval_witness)?
            .commit(C::nested_generators(self.params), rng);

        Ok((
            proof::Eval {
                native_rx,
                nested_rx,
            },
            eval_witness,
        ))
    }
}

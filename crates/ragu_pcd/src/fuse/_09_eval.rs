//! Commit to the evaluations of every queried polynomial at $u$.
//!
//! This sets the native `eval` stage containing the claimed evaluations at $u$
//! of every element that was also queried in the `query` stage. The evaluation
//! $f(u)$ is derived from the aforementioned evaluations.

use ragu_arithmetic::{CryptoRngCore, Cycle, ff::Field};
use ragu_circuits::{polynomials::Rank, staging::StageExt};
use ragu_core::{Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::Element;

use super::{NativeSPrime, RegistryWy};
use crate::{Application, Proof, internal::native, proof::ProofBuilder};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    pub(super) fn compute_eval<'dr, D, RNG: CryptoRngCore>(
        &self,
        rng: &mut RNG,
        u: &Element<'dr, D>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        s_prime: &NativeSPrime<C, R>,
        registry_wy: &RegistryWy<C, R>,
        builder: &mut ProofBuilder<'_, C, R>,
    ) -> Result<native::stages::eval::Witness<C::CircuitField>>
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
                registry_wx0: s_prime.registry_wx0_poly.eval(u),
                registry_wx1: s_prime.registry_wx1_poly.eval(u),
                registry_wy: registry_wy.poly.eval(u),
                a_poly: builder.native_a_poly().eval(u),
                b_poly: builder.native_b_poly().eval(u),
                registry_xy: builder.native_registry_xy_poly().eval(u),
            },
        };
        let rx = native::stages::eval::Stage::<C, R, HEADER_SIZE>::rx(
            C::CircuitField::random(&mut *rng),
            &eval_witness,
        )?;

        builder.set_native_eval_rx(rx);

        Ok(eval_witness)
    }
}

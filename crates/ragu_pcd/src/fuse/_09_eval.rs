//! Commit to the evaluations of every queried polynomial at $u$.
//!
//! This sets the native `eval` stage containing the claimed evaluations at $u$
//! of every element that was also queried in the `query` stage. The evaluation
//! $f(u)$ is derived from the aforementioned evaluations.

use ragu_arithmetic::{Cycle, ff::Field, par_join, rand::CryptoRng};
use ragu_circuits::{
    polynomials::{Rank, sparse},
    staging::StageExt,
};
use ragu_core::{Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::Element;

use super::{NativeSPrime, RegistryWy};
use crate::{Application, Proof, internal::native, proof::ProofBuilder};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    pub(super) fn compute_eval<'dr, D>(
        &self,
        u: &Element<'dr, D>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        s_prime: &NativeSPrime<C, R>,
        registry_wy: &RegistryWy<C, R>,
        builder: &ProofBuilder<'_, C, R, B>,
    ) -> native::stages::eval::Witness<C::CircuitField>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let u = *u.value().take();

        // ProofBuilder contains OnceCell fields and is therefore !Sync.
        // Extract shared references to the already-set polynomials so the
        // closures below capture &Polynomial (which is Sync) rather than
        // &ProofBuilder.
        let native_a_poly = builder.native_a_poly();
        let native_b_poly = builder.native_b_poly();
        let native_registry_xy_poly = builder.native_registry_xy_poly();

        // Evaluate left/right child witnesses concurrently with the
        // current-step polynomial evaluations at u.
        let (left_witness, right_witness, current) = par_join!(
            || native::stages::eval::ChildEvaluationsWitness::from_proof::<C, R, B>(left, u),
            || native::stages::eval::ChildEvaluationsWitness::from_proof::<C, R, B>(right, u),
            || native::stages::eval::CurrentStepWitness {
                registry_wx0: B::sparse_eval(&s_prime.registry_wx0_poly, u),
                registry_wx1: B::sparse_eval(&s_prime.registry_wx1_poly, u),
                registry_wy: B::sparse_eval(&registry_wy.poly, u),
                a_poly: B::sparse_eval(native_a_poly, u),
                b_poly: B::sparse_eval(native_b_poly, u),
                registry_xy: B::sparse_eval(native_registry_xy_poly, u),
            },
        );

        native::stages::eval::Witness {
            left: left_witness,
            right: right_witness,
            current,
        }
    }

    /// Samples a fresh eval-stage blinding and returns its rx together with the
    /// bridge eval commitment.
    ///
    /// The `pre_beta` rejection loop calls this once per attempt, re-deriving
    /// the challenge from a fresh commitment until it lands in range. Only the
    /// accepted rx is committed to the builder (via `set_native_eval_rx`), so
    /// this computes the commitment without populating the builder's cached eval
    /// cells.
    pub(super) fn sample_eval_commitment<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        eval_witness: &native::stages::eval::Witness<C::CircuitField>,
        builder: &ProofBuilder<'_, C, R, B>,
    ) -> Result<(sparse::Polynomial<C::CircuitField, R>, C::NestedCurve)> {
        let eval_rx = native::stages::eval::Stage::<C, R, HEADER_SIZE>::rx(
            C::CircuitField::random(&mut *rng),
            eval_witness,
        )?;
        let native_eval_commitment =
            B::sparse_commit_to_affine(&eval_rx, C::host_generators(self.params));
        let bridge_eval_commitment =
            builder.candidate_bridge_eval_commitment(native_eval_commitment)?;

        Ok((eval_rx, bridge_eval_commitment))
    }
}

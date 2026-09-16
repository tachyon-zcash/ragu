//! Proof fusion implementation for combining child proofs.
//!
//! Implements the core [`Application::fuse`] operation that takes two child
//! proofs and produces a new proof, computing each proof component in sequence.

mod _01_application;
mod _02_preamble;
mod _03_s_prime;
mod _04_inner_error;
mod _05_outer_error;
mod _06_ab;
mod _07_query;
mod _08_f;
mod _09_eval;
mod _10_p;
mod _11_circuits;
pub(crate) mod claims;
// PCS and folding properties use private fuse internals. The proof-binding
// properties live under `proof` for direct access to cached fields.
#[cfg(test)]
#[path = "../../tests/pcs.rs"]
mod pcs_tests;
#[cfg(test)]
#[path = "test_steps.rs"]
pub(crate) mod test_steps;
#[cfg(test)]
mod tests;
// The patcher seam (see `crate::fuzzing`). Its source lives with the rest of
// the fuzzing surface in `src/fuzzing/`, but it is mounted here because it
// calls this pipeline's `pub(super)` steps. The file gates itself behind
// `unstable-fuzzing` with an inner `#![cfg]`, so no feature attribute appears
// here.
#[path = "../fuzzing/patcher.rs"]
pub(crate) mod patcher;

use _10_p::NativeInputs;
use claims::{NativeFuseProofSource, NestedFuseProofSource};
use ragu_arithmetic::{Cycle, ff::Field, rand::CryptoRng};
use ragu_circuits::{
    polynomials::{Rank, sparse},
    staging::StageExt,
};
use ragu_core::{
    Result,
    drivers::{
        Driver,
        emulator::{Emulator, Wireless},
    },
    maybe::{Always, Maybe},
};
use ragu_primitives::{Element, EndoscalarChallenge, GadgetExt, Point, vec::CollectFixed};

use crate::{
    Application, Pcd, Proof, RAGU_TAG,
    internal::{
        nested::{self, pcs},
        transcript::Transcript,
    },
    proof::ProofBuilder,
    step::Step,
};

/// Observes an actual Eval attempt before range validation. Tests can inject
/// the astronomically rare out-of-range response without finding a Poseidon
/// preimage; accepted responses still come from the ordinary transcript.
#[cfg(test)]
struct EvalAttempt<'a, C: Cycle, R: Rank> {
    native: &'a sparse::Polynomial<C::CircuitField, R>,
    bridge: &'a sparse::Polynomial<C::ScalarField, R>,
    commitment: C::NestedCurve,
    candidate: C::CircuitField,
}

/// Adversarial suffix advice, supplied only after the corresponding challenge
/// has been squeezed. Earlier builder cells and transcript state are never
/// exposed: tests must detect attempts to substitute a different committed
/// object even when the ordinary pipeline regenerates all later advice.
#[cfg(test)]
trait SuffixAttack<C: Cycle, R: Rank> {
    /// Edit the point-stage commitments carried by the preamble bridge at
    /// its real commitment deadline. The native point stages already exist;
    /// fusion rebuilds the entire transcript and advice suffix from here.
    fn before_preamble_bridge(
        &mut self,
        _witness: &mut nested::stages::preamble::Witness<C::HostCurve>,
    ) {
    }

    /// Edit the point-stage commitment carried by the s-prime bridge before
    /// the bridge is committed and `y` is squeezed.
    fn before_s_prime_bridge(
        &mut self,
        _witness: &mut nested::stages::s_prime::Witness<C::HostCurve>,
    ) {
    }

    fn after_y(
        &mut self,
        _y: C::CircuitField,
        _native: &mut NativeSPrime<C, R>,
        _nested: &mut NestedSPrime<C, R>,
    ) {
    }

    /// Edit the completed accumulator fold before its commitments enter the
    /// point stages or transcript. Return true to rebuild the direct
    /// commitment caches from the edited polynomials. The ordinary fusion
    /// pipeline constructs every later stage, bridge, challenge and circuit.
    fn before_ab_commitment(
        &mut self,
        _native_a: &mut sparse::Polynomial<C::CircuitField, R>,
        _native_b: &mut sparse::Polynomial<C::CircuitField, R>,
        _nested_a: &mut sparse::Polynomial<C::ScalarField, R>,
        _nested_b: &mut sparse::Polynomial<C::ScalarField, R>,
    ) -> bool {
        false
    }

    /// Edit the point-stage commitment carried by the A/B bridge before the
    /// bridge is committed and `x` is squeezed.
    fn before_ab_bridge(
        &mut self,
        _witness: &mut nested::stages::ab::Witness<C::HostCurve>,
    ) -> bool {
        false
    }

    fn after_x(
        &mut self,
        _x: C::CircuitField,
        _z: C::CircuitField,
        _native_a: &mut sparse::Polynomial<C::CircuitField, R>,
        _native_b: &mut sparse::Polynomial<C::CircuitField, R>,
        _nested_a: &mut sparse::Polynomial<C::ScalarField, R>,
        _nested_b: &mut sparse::Polynomial<C::ScalarField, R>,
    ) {
    }

    fn after_alpha(
        &mut self,
        _w: C::CircuitField,
        _alpha: C::CircuitField,
        _nested_registry_xy: &mut sparse::Polynomial<C::ScalarField, R>,
    ) {
    }

    /// Edit the point-stage commitment carried by the quotient bridge before
    /// the bridge is committed and `u` is squeezed.
    fn before_f_bridge(&mut self, _witness: &mut nested::stages::f::Witness<C::HostCurve>) {}

    /// Return true to recompute the transient quotient commitment caches.
    fn after_u(
        &mut self,
        _u: C::CircuitField,
        _native: &mut sparse::Polynomial<C::CircuitField, R>,
        _nested: &mut sparse::Polynomial<C::ScalarField, R>,
    ) -> bool {
        false
    }

    /// Edit the challenge-binding witness before the Eval stage and its
    /// exported partial are committed. This is a test-only internal-advice
    /// tier: implementations that change a challenge-stage value must also
    /// rebuild the binding partials they intend to keep coherent.
    fn before_eval_commitment(
        &mut self,
        _native: &mut crate::internal::native::stages::eval::Witness<C>,
        _nested_challenges: &mut nested::stages::challenges::Witness<C::ScalarField>,
    ) {
    }

    fn after_pre_beta(
        &mut self,
        _pre_beta: C::CircuitField,
        _native: &mut crate::internal::native::stages::eval::Witness<C>,
        _nested: &mut nested::stages::eval::Evaluations<C::ScalarField>,
        _nested_challenges: &mut nested::stages::challenges::Witness<C::ScalarField>,
    ) {
    }

    /// Observe the completed proof together with the transient objects that
    /// ordinary fusion discards. This is immutable and runs only after every
    /// proof field and cache has been built, so it cannot repair a suffix.
    #[cfg(feature = "unstable-fuzzing")]
    fn inspect(&mut self, _witness: ExpandedWitness<'_, C, R>) {}
}

#[cfg(test)]
impl<C: Cycle, R: Rank> SuffixAttack<C, R> for () {}

/// Ephemeral native-field data for $f(X)$, used only during the fuse step.
struct NativeF<C: Cycle, R: Rank> {
    poly: sparse::Polynomial<C::CircuitField, R>,
    commitment: C::HostCurve,
}

/// Ephemeral $m(w, X, y)$ registry restriction, used only during the fuse step.
struct RegistryWy<C: Cycle, R: Rank> {
    poly: sparse::Polynomial<C::CircuitField, R>,
    commitment: C::HostCurve,
}

/// Ephemeral native-field data for $s'(X)$, used only during the fuse step.
struct NativeSPrime<C: Cycle, R: Rank> {
    registry_wx0_poly: sparse::Polynomial<C::CircuitField, R>,
    registry_wx0_commitment: C::HostCurve,
    registry_wx1_poly: sparse::Polynomial<C::CircuitField, R>,
    registry_wx1_commitment: C::HostCurve,
}

/// Ephemeral nested-field data for $f_n(X)$, used only during the fuse step.
struct NestedF<C: Cycle, R: Rank> {
    poly: sparse::Polynomial<C::ScalarField, R>,
    commitment: C::NestedCurve,
}

/// Ephemeral $m_n(w_n, X, y_n)$ nested registry restriction, used only
/// during the fuse step.
struct NestedRegistryWy<C: Cycle, R: Rank> {
    poly: sparse::Polynomial<C::ScalarField, R>,
    commitment: C::NestedCurve,
}

/// Ephemeral nested-field data for the $m_n(w_n, x_{i,n}, Y)$ restrictions,
/// used only during the fuse step.
struct NestedSPrime<C: Cycle, R: Rank> {
    registry_wx0_poly: sparse::Polynomial<C::ScalarField, R>,
    registry_wx0_commitment: C::NestedCurve,
    registry_wx1_poly: sparse::Polynomial<C::ScalarField, R>,
    registry_wx1_commitment: C::NestedCurve,
}

/// Test-only expanded fusion witness. The references deliberately preserve
/// the semantic groupings used while constructing the proof; the production
/// proof format continues to discard these objects.
#[cfg(all(test, feature = "unstable-fuzzing"))]
struct ExpandedWitness<'a, C: Cycle, R: Rank> {
    proof: &'a Proof<C, R>,
    left: &'a Proof<C, R>,
    right: &'a Proof<C, R>,
    native_s_prime: &'a NativeSPrime<C, R>,
    nested_s_prime: &'a NestedSPrime<C, R>,
    registry_wy: &'a RegistryWy<C, R>,
    nested_registry_wy: &'a NestedRegistryWy<C, R>,
    native_f: &'a NativeF<C, R>,
    nested_f: &'a NestedF<C, R>,
}

type NativeFuseEmulator<C> = Emulator<Wireless<Always<()>, <C as Cycle>::CircuitField>>;
type NestedFuseEmulator<C> = Emulator<Wireless<Always<()>, <C as Cycle>::ScalarField>>;

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// The nested batch this step opens, over the nested polynomials the
    /// builder has committed so far.
    fn nested_batch<'a>(
        &self,
        builder: &'a ProofBuilder<'_, C, R, B>,
        nested_s_prime: &'a NestedSPrime<C, R>,
        nested_registry_wy: &'a NestedRegistryWy<C, R>,
        left: &'a Proof<C, R>,
        right: &'a Proof<C, R>,
    ) -> pcs::Batch<'a, C, R> {
        pcs::Batch {
            left,
            right,
            registry_wx0: &nested_s_prime.registry_wx0_poly,
            registry_wx1: &nested_s_prime.registry_wx1_poly,
            registry_wy: &nested_registry_wy.poly,
            registry_xy: builder.nested_registry_xy_poly(),
            a: builder.nested_a_poly(),
            b: builder.nested_b_poly(),
        }
    }

    /// Commits the nested challenge stage: the lifts of this step's
    /// challenges, the base-case sign and the lift of `pre_beta`, unblinded,
    /// so that its nested-curve commitment is the fixed linear combination
    /// of generators the binding circuits recompute. Completes the witness
    /// used for the eval stage's binding partials with beta's lift and returns
    /// it for the nested circuits that load the stage.
    fn commit_nested_challenges(
        &self,
        challenges: nested::stages::challenges::Witness<C::ScalarField>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<nested::stages::challenges::Witness<C::ScalarField>> {
        builder.set_nested_challenges_rx(nested::stages::challenges::Stage::<C::HostCurve, R>::rx(
            C::ScalarField::ZERO,
            &challenges,
        )?);
        Ok(challenges)
    }

    /// The nested challenges this step's openings are at, derived from the
    /// native ones (see [`nested::challenge`]).
    fn nested_challenges<'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        w: &Element<'dr, D>,
        x: &Element<'dr, D>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
    ) -> Result<pcs::Challenges<C::ScalarField>> {
        Ok(pcs::Challenges {
            w: nested::challenge::<C>(*w.value().take())?,
            x: nested::challenge::<C>(*x.value().take())?,
            y: nested::challenge::<C>(*y.value().take())?,
            z: nested::challenge::<C>(*z.value().take())?,
            left: pcs::ChildChallenges::of(left)?,
            right: pcs::ChildChallenges::of(right)?,
        })
    }
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// Fuse two [`Pcd`] into one using a provided [`Step`].
    ///
    /// The provided `step` must have been previously registered with this
    /// [`Application`] via [`ApplicationBuilder::register`](crate::ApplicationBuilder::register).
    ///
    /// ## Parameters
    ///
    /// * `rng`: a random number generator used to sample randomness during
    ///   proof generation. The fact that this method takes a random number
    ///   generator is not an indication that the resulting proof-carrying data
    ///   is zero-knowledge. [`Application::rerandomize`] is intended to provide
    ///   that property, but the current construction does not yet establish it.
    /// * `step`: the [`Step`] instance that has been registered in this
    ///   [`Application`].
    /// * `witness`: the witness input for the [`Step`]
    /// * `left`: the left [`Pcd`] to fuse in this step; must correspond to the
    ///   [`Step::Left`] header.
    /// * `right`: the right [`Pcd`] to fuse in this step; must correspond to
    ///   the [`Step::Right`] header.
    pub fn fuse<'source, RNG: CryptoRng, S: Step<C>>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
        left: Pcd<C, R, S::Left>,
        right: Pcd<C, R, S::Right>,
    ) -> Result<(Pcd<C, R, S::Output>, S::Aux<'source>)> {
        self.fuse_inner(
            rng,
            step,
            witness,
            left,
            right,
            #[cfg(test)]
            |_, _| {},
            #[cfg(test)]
            |_| Ok(None),
            #[cfg(test)]
            &mut (),
        )
    }

    fn fuse_inner<'source, RNG: CryptoRng, S: Step<C>>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
        left: Pcd<C, R, S::Left>,
        right: Pcd<C, R, S::Right>,
        #[cfg(test)] edit_quotients: impl FnOnce(
            &mut sparse::Polynomial<C::CircuitField, R>,
            &mut sparse::Polynomial<C::ScalarField, R>,
        ),
        #[cfg(test)] mut eval_attempt: impl FnMut(
            EvalAttempt<'_, C, R>,
        ) -> Result<Option<C::CircuitField>>,
        #[cfg(test)] suffix_attack: &mut impl SuffixAttack<C, R>,
    ) -> Result<(Pcd<C, R, S::Output>, S::Aux<'source>)> {
        let mut builder =
            ProofBuilder::<C, R, B>::new(self.params, C::ScalarField::random(&mut *rng));

        let (left, right, application_data, application_aux) =
            self.compute_application_proof(rng, step, witness, left, right, &mut builder)?;

        let mut dr = Emulator::execute();
        let mut transcript = Transcript::new(&mut dr, C::circuit_poseidon(self.params), RAGU_TAG)?;

        let (preamble_witness, nested_preamble) = self.compute_preamble(
            rng,
            &left,
            &right,
            &mut builder,
            #[cfg(test)]
            |witness| suffix_attack.before_preamble_bridge(witness),
        )?;
        let bridge_preamble_commitment =
            Point::constant(&mut dr, builder.bridge_preamble_commitment())?;
        bridge_preamble_commitment.write(&mut dr, &mut transcript)?;
        let w = transcript.challenge(&mut dr)?;
        let native_registry = self.native_registry.at(*w.value().take());
        let nested_registry = self
            .nested_registry
            .at(nested::challenge::<C>(*w.value().take())?);

        #[allow(unused_mut)]
        let (mut native_s_prime, mut nested_s_prime, nested_s_prime_witness) = self
            .compute_s_prime(
                rng,
                &native_registry,
                &nested_registry,
                &left,
                &right,
                &mut builder,
                #[cfg(test)]
                |witness| suffix_attack.before_s_prime_bridge(witness),
            )?;
        let bridge_s_prime_commitment =
            Point::constant(&mut dr, builder.bridge_s_prime_commitment())?;
        bridge_s_prime_commitment.write(&mut dr, &mut transcript)?;
        let y = transcript.challenge(&mut dr)?;

        #[cfg(test)]
        suffix_attack.after_y(*y.value().take(), &mut native_s_prime, &mut nested_s_prime);

        let z = transcript.challenge(&mut dr)?;

        let native_source = NativeFuseProofSource {
            left: &left,
            right: &right,
        };
        let nested_source = NestedFuseProofSource {
            left: &left,
            right: &right,
        };

        let (
            native_inner_error_witness,
            native_claims,
            registry_wy,
            nested_inner_error_witness,
            nested_claims,
            nested_registry_wy,
        ) = self.inner_error_terms(
            rng,
            &native_registry,
            &nested_registry,
            &y,
            &z,
            &native_source,
            &nested_source,
            &mut builder,
        )?;
        let bridge_inner_error_commitment =
            Point::constant(&mut dr, builder.bridge_inner_error_commitment())?;
        bridge_inner_error_commitment.write(&mut dr, &mut transcript)?;

        // Clone-then-save: `save_state` consumes the transcript, but we need
        // the original to keep squeezing. Both paths apply the same permutation.
        let saved_transcript_state = transcript
            .clone()
            .save_state(&mut dr)
            .expect("save_state should succeed after absorbing")
            .into_elements()
            .into_iter()
            .map(|e| *e.value().take())
            .collect_fixed()?;

        let mu = transcript.challenge(&mut dr)?;
        let nu = transcript.challenge(&mut dr)?;

        let (
            native_outer_error_witness,
            native_a,
            native_b,
            nested_outer_error_witness,
            nested_a,
            nested_b,
        ) = self.outer_error_terms(
            rng,
            &preamble_witness,
            &native_inner_error_witness,
            native_claims,
            &nested_inner_error_witness,
            nested_claims,
            &nested_source,
            &nested_preamble,
            &y,
            &mu,
            &nu,
            saved_transcript_state,
            &mut builder,
        )?;
        let bridge_outer_error_commitment =
            Point::constant(&mut dr, builder.bridge_outer_error_commitment())?;
        bridge_outer_error_commitment.write(&mut dr, &mut transcript)?;
        let mu_prime = transcript.challenge(&mut dr)?;
        let nu_prime = transcript.challenge(&mut dr)?;

        #[allow(unused_mut)]
        let mut nested_ab_witness = self.compute_ab(
            rng,
            native_a,
            native_b,
            nested_a,
            nested_b,
            &nested_registry_wy,
            &native_source,
            &mu_prime,
            &nu_prime,
            &mut builder,
            #[cfg(test)]
            |native_a, native_b, nested_a, nested_b| {
                suffix_attack.before_ab_commitment(native_a, native_b, nested_a, nested_b)
            },
        )?;
        #[cfg(test)]
        {
            if suffix_attack.before_ab_bridge(&mut nested_ab_witness) {
                builder.set_bridge_ab_witness_for_test(&nested_ab_witness)?;
            }
        }
        let bridge_ab_commitment = Point::constant(&mut dr, builder.bridge_ab_commitment()?)?;
        bridge_ab_commitment.write(&mut dr, &mut transcript)?;
        let x = transcript.challenge(&mut dr)?;

        #[cfg(test)]
        {
            let (native_a, native_b, nested_a, nested_b) = builder.accumulator_polys_mut();
            suffix_attack.after_x(
                *x.value().take(),
                *z.value().take(),
                native_a,
                native_b,
                nested_a,
                nested_b,
            );
        }

        let (query_witness, nested_query) = self.compute_query(
            rng,
            &w,
            &x,
            &y,
            &z,
            &registry_wy,
            &nested_registry_wy,
            &left,
            &right,
            &mut builder,
        )?;
        let bridge_query_commitment = Point::constant(&mut dr, builder.bridge_query_commitment())?;
        bridge_query_commitment.write(&mut dr, &mut transcript)?;
        let alpha = transcript.challenge(&mut dr)?;

        #[cfg(test)]
        suffix_attack.after_alpha(
            *w.value().take(),
            *alpha.value().take(),
            builder.nested_registry_xy_poly_mut(),
        );

        let (native_f, nested_f, nested_f_witness) = self.compute_f(
            rng,
            &w,
            &y,
            &z,
            &x,
            &alpha,
            &native_s_prime,
            &registry_wy,
            &nested_s_prime,
            &nested_registry_wy,
            &mut builder,
            &left,
            &right,
            #[cfg(test)]
            edit_quotients,
            #[cfg(test)]
            |witness| suffix_attack.before_f_bridge(witness),
        )?;
        let bridge_f_commitment = Point::constant(&mut dr, builder.bridge_f_commitment())?;
        bridge_f_commitment.write(&mut dr, &mut transcript)?;
        let u = transcript.challenge(&mut dr)?;

        #[cfg(test)]
        let (native_f, nested_f) = {
            let (mut native_f, mut nested_f) = (native_f, nested_f);
            if suffix_attack.after_u(*u.value().take(), &mut native_f.poly, &mut nested_f.poly) {
                native_f.commitment =
                    B::sparse_commit_to_affine(&native_f.poly, C::host_generators(self.params));
                nested_f.commitment =
                    B::sparse_commit_to_affine(&nested_f.poly, C::nested_generators(self.params));
            }
            (native_f, nested_f)
        };

        let bound_challenges = [&w, &y, &z, &mu, &nu, &mu_prime, &nu_prime, &x, &alpha, &u]
            .map(|challenge| *challenge.value().take());
        let (eval_witness, nested_eval, nested_challenges_witness) = self.compute_eval(
            &bound_challenges,
            &left,
            &right,
            &native_s_prime,
            &registry_wy,
            &nested_s_prime,
            &nested_registry_wy,
            &builder,
        )?;
        #[cfg(test)]
        let (eval_witness, nested_challenges_witness) = {
            let (mut eval_witness, mut nested_challenges_witness) =
                (eval_witness, nested_challenges_witness);
            suffix_attack.before_eval_commitment(&mut eval_witness, &mut nested_challenges_witness);
            (eval_witness, nested_challenges_witness)
        };
        builder.set_nested_challenges_partial(eval_witness.partials.binding);

        // Rejection-sample the eval-stage blinding until the squeezed `pre_beta`
        // lands in range as an endoscalar challenge. Unlike the single-shot
        // challenges above, `pre_beta` must be ground: each attempt re-blinds the
        // eval commitment and re-derives `pre_beta` from a fresh transcript
        // clone, retrying until `EndoscalarChallenge::sample` accepts. Baking the
        // grind into `sample` means a challenge cannot be produced without it.
        //
        // `pre_beta` is the terminal native Fiat-Shamir challenge (`v` is
        // computed, not squeezed), so the accepted transcript clone is dropped
        // rather than threaded onward; the internal circuits re-derive every
        // challenge in-circuit from the values recorded on the builder.
        let (pre_beta, (eval_rx, bridge_eval_rx, bridge_eval_commitment)) =
            EndoscalarChallenge::sample(&mut dr, |dr| {
                // Fresh eval-stage blindings each attempt: re-deriving the eval
                // commitment is what makes `pre_beta` independent across
                // retries.
                let (eval_rx, bridge_eval_rx, bridge_eval_commitment) =
                    self.sample_eval_commitment(rng, &eval_witness, &nested_eval)?;

                let mut transcript = transcript.clone();
                let bridge_eval_commitment_point = Point::constant(dr, bridge_eval_commitment)?;
                bridge_eval_commitment_point.write(dr, &mut transcript)?;
                let pre_beta = transcript.challenge(dr)?;

                #[cfg(test)]
                let pre_beta = match eval_attempt(EvalAttempt {
                    native: &eval_rx,
                    bridge: &bridge_eval_rx,
                    commitment: bridge_eval_commitment,
                    candidate: *pre_beta.value().take(),
                })? {
                    Some(value) => Element::constant(dr, value),
                    None => pre_beta,
                };

                Ok((pre_beta, (eval_rx, bridge_eval_rx, bridge_eval_commitment)))
            })?;
        builder.set_native_eval_rx(eval_rx);
        builder.set_bridge_eval_rx(bridge_eval_rx, bridge_eval_commitment);

        let mut nested_challenges_witness = nested_challenges_witness;
        nested_challenges_witness.beta =
            nested::challenge::<C>(*pre_beta.element().value().take())?;

        #[cfg(test)]
        let (eval_witness, nested_eval, nested_challenges_witness) = {
            let (mut eval_witness, mut nested_eval) = (eval_witness, nested_eval);
            suffix_attack.after_pre_beta(
                *pre_beta.element().value().take(),
                &mut eval_witness,
                &mut nested_eval,
                &mut nested_challenges_witness,
            );
            (eval_witness, nested_eval, nested_challenges_witness)
        };

        // Every nested challenge is now known: commit the nested challenge
        // stage, unblinded. Its expected commitment is computed by this
        // step's native binders and completed with beta by the parent's.
        let nested_challenges =
            self.commit_nested_challenges(nested_challenges_witness, &mut builder)?;

        let (points, native_points, native_walk) = self.compute_p(
            rng,
            &pre_beta,
            &left,
            &right,
            &native_s_prime,
            &registry_wy,
            &native_f,
            &nested_s_prime,
            &nested_registry_wy,
            &nested_f,
            &mut builder,
        )?;

        // Set challenges on builder.
        builder.set_w(*w.value().take());
        builder.set_y(*y.value().take());
        builder.set_z(*z.value().take());
        builder.set_mu(*mu.value().take());
        builder.set_nu(*nu.value().take());
        builder.set_mu_prime(*mu_prime.value().take());
        builder.set_nu_prime(*nu_prime.value().take());
        builder.set_x(*x.value().take());
        builder.set_alpha(*alpha.value().take());
        builder.set_u(*u.value().take());
        builder.set_pre_beta(*pre_beta.element().value().take());

        self.compute_native_internal_circuits(
            rng,
            &preamble_witness,
            &native_outer_error_witness,
            &native_inner_error_witness,
            &query_witness,
            &eval_witness,
            &native_points,
            &native_walk,
            &mut builder,
        )?;

        let nested_query_witness = nested::stages::query::Witness {
            native_query: builder.native_query_commitment(),
            registry_xy: builder.native_registry_xy_commitment(),
            nested: nested_query,
        };
        let nested_eval_witness = nested::stages::eval::Witness {
            native_eval: builder.native_eval_commitment(),
            nested: nested_eval,
        };

        self.compute_nested_internal_circuits(
            rng,
            pre_beta.extract_native(),
            &points,
            &nested_preamble,
            &nested_s_prime_witness,
            &nested_inner_error_witness,
            &nested_outer_error_witness,
            &nested_ab_witness,
            &nested_query_witness,
            &nested_f_witness,
            &nested_eval_witness,
            &nested_challenges,
            &mut builder,
        )?;

        let proof = builder.build()?;

        #[cfg(all(test, feature = "unstable-fuzzing"))]
        suffix_attack.inspect(ExpandedWitness {
            proof: &proof,
            left: &left,
            right: &right,
            native_s_prime: &native_s_prime,
            nested_s_prime: &nested_s_prime,
            registry_wy: &registry_wy,
            nested_registry_wy: &nested_registry_wy,
            native_f: &native_f,
            nested_f: &nested_f,
        });

        Ok((proof.carry(application_data), application_aux))
    }
}

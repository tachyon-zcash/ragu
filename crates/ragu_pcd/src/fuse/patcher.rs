//! Handing the internal recursion circuits and their honest witnesses to a
//! patcher harness (issue #793).
//!
//! The engine's under-constraint machinery (`ragu_testing::patcher`) runs
//! against any [`Circuit`] through its public API, but the internal circuits'
//! honest witnesses exist only mid-fuse — they depend on every interstitial
//! witness and on the shared instance. A finished [`Proof`](crate::Proof)
//! does not carry them, so there is no post-hoc seam the way there is for
//! proof corruption in [`fuzz_utils`](crate::fuzz_utils).
//!
//! [`capture_internal_circuits`](Application::capture_internal_circuits) is
//! that seam: it reproduces the fuse witness-generation (calling the same
//! private helpers `fuse` does) and, instead of tracing each internal
//! circuit into a proof, hands it and its honest witness to an
//! [`InternalCircuitVisitor`]. A patcher harness supplies a visitor that
//! captures each circuit and hunts under-constraints; this module itself
//! depends on nothing in `ragu_testing`, exactly like `fuzz_utils`.
//!
//! Like the rest of the fuzzing surface it is gated behind `unstable-fuzzing`
//! and is **not** part of the stable API. It deliberately mirrors
//! [`fuse`](Application::fuse) rather than hooking into it, so the production
//! proving path is untouched; a change to `fuse` that this mirror does not
//! track will surface as a failing patcher test.

use ragu_arithmetic::{CryptoRngCore, Cycle, ff::Field};
use ragu_circuits::{Circuit, polynomials::Rank};
use ragu_core::{Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::{GadgetExt, Point, vec::CollectFixed};

use super::FuseProofSource;
use crate::{
    Application, Pcd, RAGU_TAG,
    internal::{native, native::total_circuit_counts, transcript::Transcript},
    proof::ProofBuilder,
    step::Step,
};

/// Receives each native internal recursion circuit and its honest witness
/// during [`capture_internal_circuits`](Application::capture_internal_circuits).
///
/// `make_witness` builds the circuit's honest witness on demand; it is a
/// builder rather than a value so the visitor can run the circuit through
/// more than one driver (e.g. capture *and* an independent playback), which
/// consuming a single witness would not allow. `name` identifies the circuit
/// for diagnostics.
pub trait InternalCircuitVisitor<C: Cycle> {
    /// Visit `circuit`, whose honest witness is `make_witness()`.
    ///
    /// # Errors
    ///
    /// Propagates any error the visitor raises, or from `make_witness`.
    fn visit<'w, Cir: Circuit<C::CircuitField>>(
        &mut self,
        name: &'static str,
        circuit: &Cir,
        make_witness: impl Fn() -> Result<Cir::Witness<'w>>,
    ) -> Result<()>;
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    /// Runs the fuse witness-generation and hands each native internal
    /// recursion circuit and its honest witness to `visitor`, in place of
    /// tracing them into a proof.
    ///
    /// This mirrors [`fuse`](Self::fuse) up to the internal-circuit step; the
    /// challenges, interstitial witnesses, and shared instance are computed
    /// exactly as the prover computes them. The `unified` instance is rebuilt
    /// fresh for each circuit from the finished builder (its coverage
    /// bookkeeping does not affect the emitted constraints), so no proof is
    /// produced and the children's proofs are not consumed for one.
    ///
    /// # Errors
    ///
    /// Propagates any error from witness generation or from the visitor.
    pub fn capture_internal_circuits<'source, RNG, S, V>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
        left: Pcd<C, R, S::Left>,
        right: Pcd<C, R, S::Right>,
        visitor: &mut V,
    ) -> Result<()>
    where
        RNG: CryptoRngCore,
        S: Step<C>,
        V: InternalCircuitVisitor<C>,
    {
        let mut builder = ProofBuilder::new(self.params, C::ScalarField::random(&mut *rng));

        let (left, right, _application_data, _application_aux) =
            self.compute_application_proof(rng, step, witness, left, right, &mut builder)?;

        let mut dr = Emulator::execute();
        let mut transcript = Transcript::new(&mut dr, C::circuit_poseidon(self.params), RAGU_TAG)?;

        let preamble_witness = self.compute_preamble(rng, &left, &right, &mut builder)?;
        let preamble_commitment = Point::constant(&mut dr, builder.bridge_preamble_commitment())?;
        preamble_commitment.write(&mut dr, &mut transcript)?;
        let w = transcript.challenge(&mut dr)?;
        let native_registry = self.native_registry.at(*w.value().take());

        let native_s_prime =
            self.compute_s_prime(rng, &native_registry, &left, &right, &mut builder)?;
        let s_prime_commitment = Point::constant(&mut dr, builder.bridge_s_prime_commitment())?;
        s_prime_commitment.write(&mut dr, &mut transcript)?;
        let y = transcript.challenge(&mut dr)?;
        let z = transcript.challenge(&mut dr)?;

        let source = FuseProofSource {
            left: &left,
            right: &right,
        };

        let (inner_error_witness, claims, registry_wy) =
            self.inner_error_terms(rng, &native_registry, &y, &z, &source, &mut builder)?;
        let inner_error_commitment =
            Point::constant(&mut dr, builder.bridge_inner_error_commitment())?;
        inner_error_commitment.write(&mut dr, &mut transcript)?;

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

        let (outer_error_witness, a, b) = self.outer_error_terms(
            rng,
            &preamble_witness,
            &inner_error_witness,
            claims,
            &y,
            &mu,
            &nu,
            saved_transcript_state,
            &mut builder,
        )?;
        let outer_error_commitment =
            Point::constant(&mut dr, builder.bridge_outer_error_commitment()?)?;
        outer_error_commitment.write(&mut dr, &mut transcript)?;
        let mu_prime = transcript.challenge(&mut dr)?;
        let nu_prime = transcript.challenge(&mut dr)?;

        self.compute_ab(a, b, &source, &mu_prime, &nu_prime, &mut builder)?;
        let ab_commitment = Point::constant(&mut dr, builder.bridge_ab_commitment()?)?;
        ab_commitment.write(&mut dr, &mut transcript)?;
        let x = transcript.challenge(&mut dr)?;

        let query_witness = self.compute_query(
            rng,
            &w,
            &x,
            &y,
            &z,
            &registry_wy,
            &left,
            &right,
            &mut builder,
        )?;
        let query_commitment = Point::constant(&mut dr, builder.bridge_query_commitment()?)?;
        query_commitment.write(&mut dr, &mut transcript)?;
        let alpha = transcript.challenge(&mut dr)?;

        let native_f = self.compute_f(
            rng,
            &w,
            &y,
            &z,
            &x,
            &alpha,
            &native_s_prime,
            &registry_wy,
            &mut builder,
            &left,
            &right,
        )?;
        let f_commitment = Point::constant(&mut dr, builder.bridge_f_commitment())?;
        f_commitment.write(&mut dr, &mut transcript)?;
        let u = transcript.challenge(&mut dr)?;

        let eval_witness = self.compute_eval(
            rng,
            &u,
            &left,
            &right,
            &native_s_prime,
            &registry_wy,
            &mut builder,
        )?;
        let eval_commitment = Point::constant(&mut dr, builder.bridge_eval_commitment()?)?;
        eval_commitment.write(&mut dr, &mut transcript)?;
        let pre_beta = transcript.challenge(&mut dr)?;

        self.compute_p(
            rng,
            &pre_beta,
            &left,
            &right,
            &native_s_prime,
            &registry_wy,
            &native_f,
            &mut builder,
        )?;

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
        builder.set_pre_beta(*pre_beta.value().take());

        builder.set_child_left_stage_rx(left.as_child_stage_rx());
        builder.set_child_right_stage_rx(right.as_child_stage_rx());

        // Rebuild the shared instance from the finished builder for each
        // circuit. Threading the accumulated coverage (as the prover does) is
        // unnecessary here: coverage is prover bookkeeping and does not affect
        // the constraints a circuit emits, so a fresh instance yields the same
        // capture.
        let make_unified =
            |builder: &ProofBuilder<'_, C, R>| -> Result<native::unified::Instance<C>> {
                Ok(native::unified::Instance {
                    bridge_preamble_commitment: builder.bridge_preamble_commitment(),
                    w: builder.w(),
                    bridge_s_prime_commitment: builder.bridge_s_prime_commitment(),
                    y: builder.y(),
                    z: builder.z(),
                    bridge_inner_error_commitment: builder.bridge_inner_error_commitment(),
                    mu: builder.mu(),
                    nu: builder.nu(),
                    bridge_outer_error_commitment: builder.bridge_outer_error_commitment()?,
                    mu_prime: builder.mu_prime(),
                    nu_prime: builder.nu_prime(),
                    c: builder.c(),
                    bridge_ab_commitment: builder.bridge_ab_commitment()?,
                    x: builder.x(),
                    bridge_query_commitment: builder.bridge_query_commitment()?,
                    alpha: builder.alpha(),
                    bridge_f_commitment: builder.bridge_f_commitment(),
                    u: builder.u(),
                    bridge_eval_commitment: builder.bridge_eval_commitment()?,
                    pre_beta: builder.pre_beta(),
                    v: builder.v(),
                    coverage: Default::default(),
                })
            };

        let hashes_1 = native::circuits::hashes_1::Circuit::<
            C,
            R,
            HEADER_SIZE,
            native::RevdotParameters,
        >::new(
            self.params,
            total_circuit_counts(self.num_application_steps).1,
        );
        visitor.visit("hashes_1", &hashes_1, || {
            Ok(native::circuits::hashes_1::Witness {
                unified: make_unified(&builder)?,
                preamble_witness: &preamble_witness,
                outer_error_witness: &outer_error_witness,
            })
        })?;

        let hashes_2 = native::circuits::hashes_2::Circuit::<
            C,
            R,
            HEADER_SIZE,
            native::RevdotParameters,
        >::new(self.params);
        visitor.visit("hashes_2", &hashes_2, || {
            Ok(native::circuits::hashes_2::Witness {
                unified: make_unified(&builder)?,
                outer_error_witness: &outer_error_witness,
            })
        })?;

        let inner_collapse = native::circuits::inner_collapse::Circuit::<
            C,
            R,
            HEADER_SIZE,
            native::RevdotParameters,
        >::new();
        visitor.visit("inner_collapse", &inner_collapse, || {
            Ok(native::circuits::inner_collapse::Witness {
                preamble_witness: &preamble_witness,
                unified: make_unified(&builder)?,
                outer_error_witness: &outer_error_witness,
                inner_error_witness: &inner_error_witness,
            })
        })?;

        let outer_collapse = native::circuits::outer_collapse::Circuit::<
            C,
            R,
            HEADER_SIZE,
            native::RevdotParameters,
        >::new();
        visitor.visit("outer_collapse", &outer_collapse, || {
            Ok(native::circuits::outer_collapse::Witness {
                unified: make_unified(&builder)?,
                preamble_witness: &preamble_witness,
                outer_error_witness: &outer_error_witness,
            })
        })?;

        let compute_v = native::circuits::compute_v::Circuit::<C, R, HEADER_SIZE>::new();
        visitor.visit("compute_v", &compute_v, || {
            Ok(native::circuits::compute_v::Witness {
                unified: make_unified(&builder)?,
                preamble_witness: &preamble_witness,
                query_witness: &query_witness,
                eval_witness: &eval_witness,
            })
        })?;

        Ok(())
    }
}

//! Evaluate the [`Step`] circuit, in its two phases.
//!
//! Before the preamble bridge is committed, [`begin_application_proof`]
//! fixes what the bridge carries about the application, by the step's
//! [`prepare`](Step::prepare) phase: the step's own online polynomials and
//! its application stage. It also sets the children's output headers,
//! encoded from their data, and the step's circuit id on the
//! [`ProofBuilder`]. The bridge does not carry those: the native preamble
//! commits them after $w$ (see [`preamble`]). After $w$ is squeezed,
//! [`compute_application_proof`] synthesizes the step circuit with
//! $\zeta = w$ and the six slots' polynomials (see [`online`]), and sets
//! the output header and the online openings on the builder, which the
//! native preamble commits too.
//!
//! The application trace and the application stage are the step's own
//! polynomials: the step folds their claims and opens them in its own
//! batch, so they are returned as ephemeral [`NativeApplication`] data
//! rather than carried in the proof. The stage's commitment enters the
//! transcript in the `preamble` bridge stage, before $w$, and the trace's in
//! the `s_prime` bridge stage, before the $y$ the claims are folded at.
//!
//! [`begin_application_proof`]: Application::begin_application_proof
//! [`compute_application_proof`]: Application::compute_application_proof
//! [`preamble`]: crate::internal::native::stages::preamble

use alloc::vec::Vec;

use ragu_circuits::{
    Blind, CircuitExt,
    polynomials::{Rank, sparse},
    registry::CircuitIndex,
    staging,
};
use ragu_core::{Cycle, Error, Result};
use rand::CryptoRng;
use udon::{curve::Affine as _, field::Field};

use crate::{
    Application, Header, Proof,
    internal::{
        ky,
        native::online,
        transcript::{Challenge, ChallengeW},
    },
    profile::ProfiledCycle,
    proof::ProofBuilder,
    step::{HeaderInput, Prepared, Step, internal::adapter::Adapter, oracles::OnlineWitness},
};

/// The step's own application stage, used only during the fuse step: the
/// staged values after the SYSTEM gate, with a random alpha.
pub(crate) struct NativeApplicationStage<C: Cycle, R: Rank> {
    /// The stage polynomial.
    pub(crate) rx: sparse::Polynomial<C::CircuitField, R>,
    /// Its commitment, carried by the `preamble` bridge stage.
    pub(crate) commitment: C::HostCurve,
}

/// The step's own application polynomials, used only during the fuse step:
/// the step folds their claims and opens them in its own batch.
pub(crate) struct NativeApplication<C: Cycle, R: Rank> {
    /// The step's application circuit.
    pub(crate) circuit_id: CircuitIndex,
    /// The step's application trace.
    pub(crate) rx: sparse::Polynomial<C::CircuitField, R>,
    /// The trace's commitment, carried by the `s_prime` bridge stage.
    pub(crate) commitment: C::HostCurve,
    /// The step's application stage.
    pub(crate) stage: NativeApplicationStage<C, R>,
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// The first phase: sets the step's own online polynomials on the
    /// builder, whose commitments the preamble bridge carries before $w$ is
    /// squeezed, and commits the step's application stage, which the bridge
    /// carries too. Also sets the children's output headers and the circuit
    /// id on the builder, which the native preamble commits after $w$.
    /// Returns what the step prepared, which the second phase hands to its
    /// circuit, and the stage.
    ///
    /// # Errors
    ///
    /// Propagates the step's errors, and returns [`Error::InvalidWitness`]
    /// if the step prepares a polynomial with more coefficients than the
    /// rank holds, or the zero polynomial, whose commitment the walk cannot
    /// take, or other than [`NUM_STAGED`](Step::NUM_STAGED) staged values.
    pub(super) fn begin_application_proof<'source, RNG: CryptoRng, S: Step<C>>(
        &self,
        rng: &mut RNG,
        step: &S,
        witness: &S::Witness<'source>,
        left: (&Proof<C, R>, &<S::Left as Header<C::CircuitField>>::Data),
        right: (&Proof<C, R>, &<S::Right as Header<C::CircuitField>>::Data),
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<(
        Prepared<C::CircuitField, S::Output>,
        NativeApplicationStage<C, R>,
    )> {
        builder.set_circuit_id(S::INDEX.circuit_index::<C::Profile>(self.num_application_steps)?);
        builder.set_left_header(ky::output_header::<C, S::Left, HEADER_SIZE>(
            left.1.clone(),
        )?);
        builder.set_right_header(ky::output_header::<C, S::Right, HEADER_SIZE>(
            right.1.clone(),
        )?);

        let left_polys = online::coefficients(left.0.online_polynomials());
        let right_polys = online::coefficients(right.0.online_polynomials());
        let prepared = step.prepare(
            witness,
            HeaderInput::new(left.1, &left_polys),
            HeaderInput::new(right.1, &right_polys),
        )?;
        let own: Vec<_> = prepared
            .polynomials()
            .iter()
            .map(|coeffs| {
                if coeffs.len() > R::num_coeffs() {
                    return Err(Error::InvalidWitness(
                        "an online polynomial has more coefficients than the rank holds".into(),
                    ));
                }
                if coeffs.iter().all(|c| *c == C::CircuitField::ZERO) {
                    return Err(Error::InvalidWitness(
                        "an online polynomial must not be zero".into(),
                    ));
                }
                Ok(ragu_circuits::polynomials::sparse::Polynomial::from_coeffs(
                    coeffs.clone(),
                ))
            })
            .collect::<Result<_>>()?;
        builder.set_online_polynomials(
            own.try_into().unwrap_or_else(|_| {
                unreachable!("the step returned NUM_ONLINE_FP_POLYS polynomials")
            }),
        );

        let staged = prepared.staged();
        if staged.len() != S::NUM_STAGED {
            return Err(Error::InvalidWitness(
                "a step must stage exactly NUM_STAGED values".into(),
            ));
        }
        // The application stage, after the SYSTEM gate, with a random alpha.
        // Its values are the step's secrets. Its commitment joins the
        // preamble bridge.
        let rx = staging::stage_rx::<_, R>(Blind::random(rng), 1, self.stage_size, staged)?;
        let commitment = self.host().commit(&rx);
        Ok((prepared, NativeApplicationStage { rx, commitment }))
    }

    /// The second phase: synthesizes the step circuit with $\zeta$, the
    /// slots' polynomials and what the first phase `prepared` and
    /// committed, and sets the output header and the online openings on the
    /// builder. Returns the output header's data, the step's auxiliary
    /// output and the step's own application polynomials.
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    pub(super) fn compute_application_proof<'source, RNG: CryptoRng, S: Step<C>>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
        left: (&Proof<C, R>, <S::Left as Header<C::CircuitField>>::Data),
        right: (&Proof<C, R>, <S::Right as Header<C::CircuitField>>::Data),
        zeta: Challenge<C::CircuitField, ChallengeW>,
        prepared: Prepared<C::CircuitField, S::Output>,
        stage: NativeApplicationStage<C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<(
        <S::Output as Header<C::CircuitField>>::Data,
        S::Aux<'source>,
        NativeApplication<C, R>,
    )> {
        // The slots' polynomials, cloned for the circuit's witness, whose
        // lifetime the step's own witness fixes.
        let online = OnlineWitness {
            zeta: *zeta,
            polys: online::polys(left.0, right.0, builder.online_polynomials()).map(Clone::clone),
            bridge_hash: {
                let (x, y) = builder
                    .bridge_hash_commitment()
                    .coordinates()
                    .ok_or_else(|| {
                        Error::InvalidWitness("the bridge hash is the point at infinity".into())
                    })?;
                [x, y]
            },
        };
        let (trace, aux) = Adapter::<C, S, R, HEADER_SIZE>::with_stage(step, self.stage_size)?
            .trace((left.1, right.1, witness, prepared, online))?
            .into_parts();
        let circuit_id = builder.circuit_id();
        let rx = self
            .native_registry
            .assemble(&trace, circuit_id, &mut *rng)?;
        let commitment = self.host().commit(&rx);

        let ((left_header, right_header, output_header), output_data, step_aux, queries) = aux;
        // The step's circuit must encode the headers the native preamble
        // commits next, which were fixed from the inputs' data before the
        // circuit ran.
        if left_header.into_inner()[..] != *builder.left_header()
            || right_header.into_inner()[..] != *builder.right_header()
        {
            return Err(Error::InvalidWitness(
                "the step encodes other input headers than its inputs' data".into(),
            ));
        }

        builder.set_output_header(output_header.into_inner());
        builder.set_online_openings(queries);

        Ok((
            output_data,
            step_aux,
            NativeApplication {
                circuit_id,
                rx,
                commitment,
                stage,
            },
        ))
    }
}

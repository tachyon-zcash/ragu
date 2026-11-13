//! Evaluate the [`Step`] circuit, in its two phases.
//!
//! Before the preamble bridge is committed, [`begin_application_proof`]
//! fixes what the bridge carries about the application: the children's
//! output headers, encoded from their data, the step's circuit id and, by
//! the step's [`prepare`](Step::prepare) phase, the step's own online
//! polynomials and its application stage. After $w$ is squeezed,
//! [`compute_application_proof`] synthesizes the step circuit with
//! $\zeta = w$ and the six slots' polynomials (see
//! [`online`]), and sets the application rx and
//! the online openings on the [`ProofBuilder`].
//!
//! [`begin_application_proof`]: Application::begin_application_proof
//! [`compute_application_proof`]: Application::compute_application_proof

use alloc::vec::Vec;

use ragu_circuits::{CircuitExt, polynomials::Rank, staging};
use ragu_core::{Error, Result};
use rand::CryptoRng;
use udon::{curve::Affine as _, field::Field};

use crate::{
    Application, Header, Proof,
    internal::{ky, online},
    profile::ProfiledCycle,
    proof::ProofBuilder,
    step::{HeaderInput, Prepared, Step, internal::adapter::Adapter, oracles::OnlineWitness},
};

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// The first phase: sets the children's output headers, the circuit id,
    /// the step's own online polynomials and its application stage on the
    /// builder, all of which the preamble bridge commits before $w$ is
    /// squeezed. Returns what the step prepared, which the second phase
    /// hands to its circuit.
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
    ) -> Result<Prepared<C::CircuitField, S::Output>> {
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
        builder.set_online_polynomials(own.try_into().unwrap_or_else(|_| {
            unreachable!("the step returned NUM_ONLINE_POLYNOMIALS polynomials")
        }));

        let staged = prepared.staged();
        if staged.len() != S::NUM_STAGED {
            return Err(Error::InvalidWitness(
                "a step must stage exactly NUM_STAGED values".into(),
            ));
        }
        // The application stage, after the SYSTEM gate, blinded: its values
        // are the step's secrets. Its commitment joins the preamble bridge.
        builder.set_native_application_stage_rx(staging::stage_rx::<_, R>(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            1,
            self.stage_size,
            staged,
        )?);
        Ok(prepared)
    }

    /// The second phase: synthesizes the step circuit with $\zeta$, the
    /// slots' polynomials and what the first phase `prepared` and
    /// committed, and sets the application rx and the online openings on
    /// the builder. Returns the output header's data and the
    /// step's auxiliary output.
    pub(super) fn compute_application_proof<'source, RNG: CryptoRng, S: Step<C>>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
        left: (&Proof<C, R>, <S::Left as Header<C::CircuitField>>::Data),
        right: (&Proof<C, R>, <S::Right as Header<C::CircuitField>>::Data),
        zeta: C::CircuitField,
        prepared: Prepared<C::CircuitField, S::Output>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<(
        <S::Output as Header<C::CircuitField>>::Data,
        S::Aux<'source>,
    )> {
        // The slots' polynomials, cloned for the circuit's witness, whose
        // lifetime the step's own witness fixes.
        let online = OnlineWitness {
            zeta,
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
        let rx = self.native_registry.assemble(
            &trace,
            S::INDEX.circuit_index::<C::Profile>(self.num_application_steps)?,
            &mut *rng,
        )?;

        let ((left_header, right_header), output_data, step_aux, queries) = aux;
        // The step's circuit must encode the headers the preamble committed,
        // which were fixed from the inputs' data before the circuit ran.
        if left_header.into_inner()[..] != *builder.left_header()
            || right_header.into_inner()[..] != *builder.right_header()
        {
            return Err(Error::InvalidWitness(
                "the step encodes other input headers than its inputs' data".into(),
            ));
        }

        builder.set_native_application_rx(rx);
        builder.set_online_openings(queries);

        Ok((output_data, step_aux))
    }
}

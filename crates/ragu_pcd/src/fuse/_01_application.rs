//! Evaluate the [`Step`] circuit, in its two phases.
//!
//! Before the preamble bridge is committed, [`begin_application_proof`]
//! fixes what the bridge carries about the application: the children's
//! output headers, encoded from their data, the step's circuit id and, by
//! the step's [`polynomials`](Step::polynomials) phase, the step's own
//! online polynomials. After $w$ is squeezed,
//! [`compute_application_proof`] synthesizes the step circuit with
//! $\zeta = w$ and the six slots' polynomials (see
//! [`online`]), and sets the application rx and
//! the online openings on the [`ProofBuilder`].
//!
//! [`begin_application_proof`]: Application::begin_application_proof
//! [`compute_application_proof`]: Application::compute_application_proof

use alloc::vec::Vec;

use ragu_circuits::{CircuitExt, polynomials::Rank};
use ragu_core::{Error, Result};
use rand::CryptoRng;
use udon::field::Field;

use crate::{
    Application, Header, Proof,
    header::HEADER_POLYNOMIALS,
    internal::{ky, online},
    profile::ProfiledCycle,
    proof::ProofBuilder,
    step::{HeaderInput, Step, internal::adapter::Adapter, oracles::OnlineWitness},
};

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// The first phase: sets the children's output headers, the circuit id
    /// and the step's own online polynomials on the builder, all of which
    /// the preamble bridge commits before $w$ is squeezed.
    ///
    /// # Errors
    ///
    /// Propagates the step's errors, and returns [`Error::InvalidWitness`]
    /// if the step returns other than its output header's declared number
    /// of polynomials, one with more coefficients than the rank holds, or
    /// the zero polynomial, whose commitment the walk cannot take.
    pub(super) fn begin_application_proof<'source, S: Step<C>>(
        &self,
        step: &S,
        witness: &S::Witness<'source>,
        left: (&Proof<C, R>, &<S::Left as Header<C::CircuitField>>::Data),
        right: (&Proof<C, R>, &<S::Right as Header<C::CircuitField>>::Data),
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        builder.set_circuit_id(S::INDEX.circuit_index::<C::Profile>(self.num_application_steps)?);
        builder.set_left_header(ky::output_header::<C, S::Left, HEADER_SIZE>(
            left.1.clone(),
        )?);
        builder.set_right_header(ky::output_header::<C, S::Right, HEADER_SIZE>(
            right.1.clone(),
        )?);

        let left_polys = online::coefficients(left.0.online_polys(), S::Left::NUM_POLYNOMIALS);
        let right_polys = online::coefficients(right.0.online_polys(), S::Right::NUM_POLYNOMIALS);
        let polys = step.polynomials(
            witness,
            HeaderInput {
                data: left.1,
                polynomials: &left_polys,
            },
            HeaderInput {
                data: right.1,
                polynomials: &right_polys,
            },
        )?;
        if polys.len() != S::Output::NUM_POLYNOMIALS {
            return Err(Error::InvalidWitness(
                "a step must return exactly its output header's declared polynomials".into(),
            ));
        }
        let mut own: Vec<_> = polys
            .into_iter()
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
                    coeffs,
                ))
            })
            .collect::<Result<_>>()?;
        own.resize_with(HEADER_POLYNOMIALS, online::padding);
        builder.set_online_polys(own.try_into().map_err(|_| {
            Error::InvalidWitness("the online polynomials do not fill the header's slots".into())
        })?);
        Ok(())
    }

    /// The second phase: synthesizes the step circuit with $\zeta$ and the
    /// slots' polynomials, and sets the application rx and the online
    /// openings on the builder. Returns the output header's data and the
    /// step's auxiliary output.
    pub(super) fn compute_application_proof<'source, RNG: CryptoRng, S: Step<C>>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
        left: (&Proof<C, R>, <S::Left as Header<C::CircuitField>>::Data),
        right: (&Proof<C, R>, <S::Right as Header<C::CircuitField>>::Data),
        zeta: C::CircuitField,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<(
        <S::Output as Header<C::CircuitField>>::Data,
        S::Aux<'source>,
    )> {
        // The slots' polynomials, cloned for the circuit's witness, whose
        // lifetime the step's own witness fixes.
        let online = OnlineWitness {
            zeta,
            polys: online::polys(left.0, right.0, builder.online_polys()).map(Clone::clone),
        };
        let (trace, aux) = Adapter::<C, S, R, HEADER_SIZE>::new(step)
            .trace((left.1, right.1, witness, online))?
            .into_parts();
        let rx = self.native_registry.assemble(
            &trace,
            S::INDEX.circuit_index::<C::Profile>(self.num_application_steps)?,
            &mut *rng,
        )?;

        let ((left_header, right_header), output_data, step_aux, queries) = aux;
        debug_assert_eq!(&left_header.into_inner()[..], builder.left_header());
        debug_assert_eq!(&right_header.into_inner()[..], builder.right_header());

        builder.set_native_application_rx(rx);
        builder.set_online_queries(queries);

        Ok((output_data, step_aux))
    }
}

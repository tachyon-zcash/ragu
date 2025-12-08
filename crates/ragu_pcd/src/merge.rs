use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::{CircuitExt, polynomials::Rank, staging::StageExt};
use ragu_core::{Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::{
    Element,
    vec::{CollectFixed, Len},
};
use rand::Rng;

use crate::{
    Application,
    components::fold_revdot::{self, ErrorTermsLen},
    internal_circuits::{self, NUM_REVDOT_CLAIMS},
    proof::{ApplicationProof, InternalCircuits, Pcd, PreambleProof, Proof},
    step::{Step, adapter::Adapter},
};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    /// Merge two PCD into one using a provided [`Step`].
    ///
    /// ## Parameters
    ///
    /// * `rng`: a random number generator used to sample randomness during
    ///   proof generation. The fact that this method takes a random number
    ///   generator is not an indication that the resulting proof-carrying data
    ///   is zero-knowledge; that must be ensured by performing
    ///   [`Application::rerandomize`] at a later point.
    /// * `step`: the [`Step`] instance that has been registered in this
    ///   [`Application`].
    /// * `witness`: the witness data for the [`Step`]
    /// * `left`: the left PCD to merge in this step; must correspond to the
    ///   [`Step::Left`] header.
    /// * `right`: the right PCD to merge in this step; must correspond to the
    ///   [`Step::Right`] header.
    pub fn merge<'source, RNG: Rng, S: Step<C>>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
        left: Pcd<'source, C, R, S::Left>,
        right: Pcd<'source, C, R, S::Right>,
    ) -> Result<(Proof<C, R>, S::Aux<'source>)> {
        let host_generators = self.params.host_generators();
        let nested_generators = self.params.nested_generators();

        // Compute the preamble (just a stub)
        let native_preamble_rx =
            internal_circuits::stages::native::preamble::Stage::<C, R>::rx(())?;
        let native_preamble_blind = C::CircuitField::random(&mut *rng);
        let native_preamble_commitment =
            native_preamble_rx.commit(host_generators, native_preamble_blind);

        // Compute nested preamble
        let nested_preamble_rx = internal_circuits::stages::nested::preamble::Stage::<
            C::HostCurve,
            R,
        >::rx(native_preamble_commitment)?;
        let nested_preamble_blind = C::ScalarField::random(&mut *rng);
        let nested_preamble_commitment =
            nested_preamble_rx.commit(nested_generators, nested_preamble_blind);

        // Compute w = H(nested_preamble_commitment)
        let w =
            crate::components::transcript::emulate_w::<C>(nested_preamble_commitment, self.params)?;

        // Generate dummy values for mu, nu, and error_terms (for now – these will be derived challenges)
        let mu = C::CircuitField::random(&mut *rng);
        let nu = C::CircuitField::random(&mut *rng);

        let error_terms = ErrorTermsLen::<NUM_REVDOT_CLAIMS>::range()
            .map(|_| C::CircuitField::random(&mut *rng))
            .collect_fixed()?;

        // Compute c by running the routine in a wireless emulator
        let c: C::CircuitField =
            Emulator::emulate_wireless((mu, nu, &error_terms), |dr, witness| {
                let (mu, nu, error_terms) = witness.cast();

                let mu = Element::alloc(dr, mu)?;
                let nu = Element::alloc(dr, nu)?;

                let mut error_terms = error_terms.map(|et| et.iter());
                let error_terms = ErrorTermsLen::<NUM_REVDOT_CLAIMS>::range()
                    .map(|_| {
                        Element::alloc(dr, error_terms.view_mut().map(|et| *et.next().unwrap()))
                    })
                    .try_collect_fixed()?;

                // TODO: Use zeros for ky_values for now.
                let ky_values = (0..NUM_REVDOT_CLAIMS)
                    .map(|_| Element::zero(dr))
                    .collect_fixed()?;

                Ok(*fold_revdot::compute_c::<_, NUM_REVDOT_CLAIMS>(
                    dr,
                    &mu,
                    &nu,
                    &error_terms,
                    &ky_values,
                )?
                .value()
                .take())
            })?;

        // Create the unified instance.
        let unified_instance = &internal_circuits::unified::Instance {
            nested_preamble_commitment,
            w,
            c,
            mu,
            nu,
        };

        // C staged circuit.
        let (c_rx, _) = internal_circuits::c::Circuit::<C, R, NUM_REVDOT_CLAIMS>::new(self.params)
            .rx::<R>(
                internal_circuits::c::Witness {
                    unified_instance,
                    error_terms,
                },
                self.circuit_mesh.get_key(),
            )?;

        // Application
        let application_circuit_id = S::INDEX.circuit_index(self.num_application_steps)?;
        let (application_rx, aux) = Adapter::<C, S, R, HEADER_SIZE>::new(step).rx::<R>(
            (left.data, right.data, witness),
            self.circuit_mesh.get_key(),
        )?;
        let ((left_header, right_header), aux) = aux;

        Ok((
            Proof {
                preamble: PreambleProof {
                    native_preamble_rx,
                    native_preamble_commitment,
                    native_preamble_blind,
                    nested_preamble_rx,
                    nested_preamble_commitment,
                    nested_preamble_blind,
                },
                internal_circuits: InternalCircuits { w, c, c_rx, mu, nu },
                application: ApplicationProof {
                    circuit_id: application_circuit_id,
                    left_header: left_header.into_inner(),
                    right_header: right_header.into_inner(),
                    rx: application_rx,
                },
            },
            aux,
        ))
    }
}

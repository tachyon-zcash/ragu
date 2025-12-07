use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::{CircuitExt, polynomials::Rank, staging::StageExt};
use ragu_core::{
    Result,
    drivers::{Driver, emulator::Emulator},
    maybe::{Always, Maybe, MaybeKind},
};
use ragu_primitives::{
    Element, GadgetExt, Point, Sponge,
    vec::{CollectFixed, ConstLen, FixedVec, Len},
};
use rand::Rng;

use alloc::vec::Vec;

use crate::{
    Application,
    components::{
        ErrorTermsLen,
        compute_c::{ComputeRevdotClaim, ErrorMatrix, RevdotClaimInput},
    },
    internal_circuits,
    proof::{ApplicationProof, InternalCircuits, Pcd, PreambleProof, Proof},
    step::{Step, adapter::Adapter},
};

// TODO: This should be derived from the actual number of circuits in the mesh.
pub const NUM_REVDOT_CLAIMS: usize = 3;

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
        let circuit_poseidon = self.params.circuit_poseidon();

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
        let w: C::CircuitField =
            Emulator::emulate_wireless(nested_preamble_commitment, |dr, comm| {
                let point = Point::alloc(dr, comm)?;
                let mut sponge = Sponge::new(dr, circuit_poseidon);
                point.write(dr, &mut sponge)?;
                Ok(*sponge.squeeze(dr)?.value().take())
            })?;

        // Generate dummy values for mu, nu, and error_terms (for now – these will be derived challenges)
        let mu = C::CircuitField::random(&mut *rng);
        let nu = C::CircuitField::random(&mut *rng);
        let mu_inv = mu.invert().unwrap();
        let error_terms: Vec<C::CircuitField> = (0..ErrorTermsLen::<NUM_REVDOT_CLAIMS>::len())
            .map(|_| C::CircuitField::random(&mut *rng))
            .collect();

        // Compute c by running the routine in a wireless emulator
        let c: C::CircuitField =
            Emulator::emulate_wireless((mu, nu, mu_inv, error_terms.clone()), |dr, _| {
                let mu = Element::alloc(dr, Always::maybe_just(|| mu))?;
                let nu = Element::alloc(dr, Always::maybe_just(|| nu))?;
                let mu_inv = Element::alloc(dr, Always::maybe_just(|| mu_inv))?;

                let error_matrix = ErrorMatrix::new(
                    (0..ErrorTermsLen::<NUM_REVDOT_CLAIMS>::len())
                        .map(|i| Element::alloc(dr, Always::maybe_just(|| error_terms[i])))
                        .try_collect_fixed()?,
                );

                let ky_values_vec: Vec<_> =
                    (0..NUM_REVDOT_CLAIMS).map(|_| Element::zero(dr)).collect();
                let ky_values =
                    FixedVec::<_, ConstLen<NUM_REVDOT_CLAIMS>>::new(ky_values_vec).expect("len");

                let input = RevdotClaimInput {
                    mu,
                    nu,
                    mu_inv,
                    error_matrix,
                    ky_values,
                };
                let c = dr.routine(ComputeRevdotClaim::<NUM_REVDOT_CLAIMS>, input)?;
                Ok(*c.value().take())
            })?;

        // Create the unified instance.
        let unified_instance = &internal_circuits::unified::Instance {
            nested_preamble_commitment,
            w,
            c,
        };

        // C staged circuit.
        let (c_rx, _) =
            internal_circuits::c::Circuit::<C, R, NUM_REVDOT_CLAIMS>::new(circuit_poseidon)
                .rx::<R>(
                    internal_circuits::c::Witness {
                        unified_instance,
                        mu,
                        nu,
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
                internal_circuits: InternalCircuits { w, c, c_rx },
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

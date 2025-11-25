//! # `ragu_pcd`

#![cfg_attr(not(test), no_std)]
#![allow(clippy::type_complexity)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![doc(html_favicon_url = "https://tachyon.z.cash/assets/ragu/v1_favicon32.png")]
#![doc(html_logo_url = "https://tachyon.z.cash/assets/ragu/v1_rustdoc128.png")]

extern crate alloc;

use alloc::boxed::Box;
use arithmetic::{Cycle, eval, factor_iter};
use ff::Field;
use ragu_circuits::{
    CircuitExt,
    composition::staging::{
        b_stage::EphemeralStageB,
        d_stage::{DStage, EphemeralStageD, IndirectionStageD},
        e_stage::{EStage, EphemeralStageE, IndirectionStageE, NUM_EVALS},
        g_stage::{EphemeralStageG, GStage, IndirectionStageG, KYStage},
    },
    mesh::{Mesh, MeshBuilder, omega_j},
    polynomials::{Rank, structured, unstructured},
    staging::StageExt,
};
use ragu_core::{
    Error, Result,
    drivers::emulator::{Emulator, Wireless},
    maybe::{Always, Maybe, MaybeKind},
};
use ragu_pasta::{Fp, PoseidonFp};
use ragu_primitives::{Element, GadgetExt, Point, Sponge};
use rand::{Rng, rngs::OsRng};

use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::{any::TypeId, marker::PhantomData};

use crate::proof::{
    AccumulatorInstance, AccumulatorWitness, ChallengePoint, CommittedPolynomial,
    CommittedStructured, ConsistencyEvaluations, EvaluationPoint, FinalEvaluations,
};
use circuits::{dummy::Dummy, internal_circuit_index};
use header::Header;
pub use proof::{Pcd, Proof};
use step::{Step, adapter::Adapter};

mod circuits;
pub mod header;
mod proof;
pub mod step;

/// Builder for an [`Application`] for proof-carrying data.
pub struct ApplicationBuilder<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize> {
    circuit_mesh: MeshBuilder<'params, C::CircuitField, R>,
    num_application_steps: usize,
    header_map: BTreeMap<header::Prefix, TypeId>,
    _marker: PhantomData<[(); HEADER_SIZE]>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Default
    for ApplicationBuilder<'_, C, R, HEADER_SIZE>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize>
    ApplicationBuilder<'params, C, R, HEADER_SIZE>
{
    /// Create an empty [`ApplicationBuilder`] for proof-carrying data.
    pub fn new() -> Self {
        ApplicationBuilder {
            circuit_mesh: MeshBuilder::new(),
            num_application_steps: 0,
            header_map: BTreeMap::new(),
            _marker: PhantomData,
        }
    }

    /// Register a new application-defined [`Step`] in this context. The
    /// provided [`Step`]'s [`INDEX`](Step::INDEX) should be the next sequential
    /// index that has not been inserted yet.
    pub fn register<S: Step<C> + 'params>(mut self, step: S) -> Result<Self> {
        if S::INDEX.circuit_index(None) != self.num_application_steps {
            return Err(Error::Initialization(
                "steps must be registered in sequential order".into(),
            ));
        }

        self.prevent_duplicate_prefixes::<S::Output>()?;
        self.prevent_duplicate_prefixes::<S::Left>()?;
        self.prevent_duplicate_prefixes::<S::Right>()?;

        self.circuit_mesh = self
            .circuit_mesh
            .register_circuit(Adapter::<C, S, R, HEADER_SIZE>::new(step))?;
        self.num_application_steps += 1;

        Ok(self)
    }

    fn prevent_duplicate_prefixes<H: Header<C::CircuitField>>(&mut self) -> Result<()> {
        match self.header_map.get(&H::PREFIX) {
            Some(ty) => {
                if *ty != TypeId::of::<H>() {
                    return Err(Error::Initialization(
                        "two different Header implementations using the same prefix".into(),
                    ));
                }
            }
            None => {
                self.header_map.insert(H::PREFIX, TypeId::of::<H>());
            }
        }

        Ok(())
    }

    /// Perform finalization and optimization steps to produce the
    /// [`Application`].
    pub fn finalize(
        mut self,
        params: &'params C,
    ) -> Result<Application<'params, C, R, HEADER_SIZE>> {
        // TODO: JIT-register the actual recursion circuits into the mesh before finalization.

        // TODO: https://github.com/tachyon-zcash/ragu/issues/94.
        //
        // Before registering the recursion circuits, precompute the domain size,
        // then register the recursion circuits and pass them the domain size
        // accrordingly. After, registering recursion circuits, we pass them the
        // domain size, and the recursion circuits need to validate the omega
        // is in the expected domain.

        // First, insert all of the internal steps.
        self.circuit_mesh =
            self.circuit_mesh
                .register_circuit(Adapter::<C, _, R, HEADER_SIZE>::new(
                    step::rerandomize::Rerandomize::<()>::new(),
                ))?;

        // Then, insert all of the "internal circuits" used for recursion plumbing.
        self.circuit_mesh = self.circuit_mesh.register_circuit(Dummy::<HEADER_SIZE>)?;

        Ok(Application {
            circuit_mesh: self.circuit_mesh.finalize(params.circuit_poseidon())?,
            num_application_steps: self.num_application_steps,
            host_generators: params.host_generators(),
            nested_generators: params.nested_generators(),
            _marker: PhantomData,
        })
    }
}

/// The recursion context that is used to create and verify proof-carrying data.
pub struct Application<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize> {
    circuit_mesh: Mesh<'params, C::CircuitField, R>,
    num_application_steps: usize,
    host_generators: &'params C::HostGenerators,
    nested_generators: &'params C::NestedGenerators,
    _marker: PhantomData<[(); HEADER_SIZE]>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE>
where
    C: Cycle<CircuitField = ragu_pasta::Fp>,
{
    /// Creates a trivial proof for the empty [`Header`] implementation `()`.
    /// This may or may not be identical to any previously constructed (trivial)
    /// proof, and so is not guaranteed to be freshly randomized.
    ///
    /// Uses deterministic blinding factors (ONE) to ensure commitments are never the
    /// identity point while remaining cacheable. This is the base case for PCD accumulation.
    pub fn trivial(&self) -> Proof<C, R> {
        let rx = Dummy::<HEADER_SIZE>
            .rx((), self.circuit_mesh.get_key())
            .expect("should not fail")
            .0;

        // Zero polynomials with determinstic blinding factor to avoid identity commitments.
        let a_poly = structured::Polynomial::default();
        let a_blinding = C::CircuitField::ONE;

        let b_poly = structured::Polynomial::default();
        let b_blinding = C::CircuitField::ONE;

        let p_poly = unstructured::Polynomial::default();
        let p_blinding = C::CircuitField::ONE;

        // Trivial zero challenge points.
        let x = C::CircuitField::ZERO;
        let y = C::CircuitField::ZERO;

        let s_poly = self.circuit_mesh.xy(x, y);
        let s_blinding = C::CircuitField::ONE;

        // Zero evaluations (consistent with zero polynomials).
        let u = C::CircuitField::ZERO;
        let v = C::CircuitField::ZERO;

        let c = a_poly.revdot(&b_poly);

        let s_commitment = s_poly.commit(self.host_generators, s_blinding);
        let a_commitment = a_poly.commit(self.host_generators, a_blinding);
        let b_commitment = b_poly.commit(self.host_generators, b_blinding);
        let p_commitment = p_poly.commit(self.host_generators, p_blinding);

        Proof {
            rx,
            circuit_id: internal_circuit_index(
                self.num_application_steps,
                circuits::DUMMY_CIRCUIT_ID,
            ),
            left_header: vec![C::CircuitField::ZERO; HEADER_SIZE],
            right_header: vec![C::CircuitField::ZERO; HEADER_SIZE],
            witness: AccumulatorWitness {
                s_poly,
                s_blinding,
                a_poly,
                a_blinding,
                b_poly,
                b_blinding,
                p_poly,
                p_blinding,
            },
            instance: AccumulatorInstance {
                a: a_commitment,
                b: b_commitment,
                c,
                p: p_commitment,
                u: ChallengePoint(u),
                v: EvaluationPoint(v),
                s: s_commitment,
                x: ChallengePoint(x),
                y: ChallengePoint(y),
            },
            endoscalars: Vec::new(),
            deferreds: Vec::new(),
            staged_circuits: Vec::new(),
            _marker: PhantomData,
        }
    }

    /// Creates a random trivial proof for the empty [`Header`] implementation
    /// `()`. This takes more time to generate because it cannot be cached
    /// within the [`Application`].
    fn random<'source, RNG: Rng>(&self, rng: &mut RNG) -> Pcd<'source, C, R, ()> {
        let rx = Dummy::<HEADER_SIZE>
            .rx((), self.circuit_mesh.get_key())
            .expect("should not fail")
            .0;

        let a_poly = structured::Polynomial::<C::CircuitField, R>::random(&mut *rng);
        let a_blinding = C::CircuitField::random(&mut *rng);

        let b_poly = structured::Polynomial::<C::CircuitField, R>::random(&mut *rng);
        let b_blinding = C::CircuitField::random(&mut *rng);

        let p_poly = unstructured::Polynomial::<C::CircuitField, R>::random(&mut *rng);
        let p_blinding = C::CircuitField::random(&mut *rng);

        let x = C::CircuitField::random(&mut *rng);
        let y = C::CircuitField::random(&mut *rng);

        let s_poly = self.circuit_mesh.xy(x, y);
        let s_blinding = C::CircuitField::random(&mut *rng);

        let u = C::CircuitField::random(&mut *rng);
        let v = p_poly.eval(u);
        let c = a_poly.revdot(&b_poly);

        let s_commitment = s_poly.commit(self.host_generators, s_blinding);
        let a_commitment = a_poly.commit(self.host_generators, a_blinding);
        let b_commitment = b_poly.commit(self.host_generators, b_blinding);
        let p_commitment = p_poly.commit(self.host_generators, p_blinding);

        Pcd {
            proof: Proof {
                rx,
                circuit_id: internal_circuit_index(
                    self.num_application_steps,
                    circuits::DUMMY_CIRCUIT_ID,
                ),
                left_header: vec![C::CircuitField::ZERO; HEADER_SIZE],
                right_header: vec![C::CircuitField::ZERO; HEADER_SIZE],
                witness: AccumulatorWitness {
                    s_poly,
                    s_blinding,
                    a_poly,
                    a_blinding,
                    b_poly,
                    b_blinding,
                    p_poly,
                    p_blinding,
                },
                instance: AccumulatorInstance {
                    a: a_commitment,
                    b: b_commitment,
                    c,
                    p: p_commitment,
                    u: ChallengePoint(u),
                    v: EvaluationPoint(v),
                    s: s_commitment,
                    x: ChallengePoint(x),
                    y: ChallengePoint(y),
                },
                endoscalars: Vec::new(),
                deferreds: Vec::new(),
                staged_circuits: Vec::new(),
                _marker: PhantomData,
            },
            data: (),
        }
    }

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
        _rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
        left: Pcd<'source, C, R, S::Left>,
        right: Pcd<'source, C, R, S::Right>,
    ) -> Result<(Proof<C, R>, S::Aux<'source>)> {
        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: Initialize transcript.
        ///////////////////////////////////////////////////////////////////////////////////////

        // Simulate a dummy transcript object using Poseidon sponge construction, using an
        // emulator driver to run the sponge permutation. The permutations are treated as
        // as a fixed-length hash for fiat-shamir challenge derivation.
        //
        // TODO: Replace with a real transcript abstraction.
        let mut em = Emulator::execute();
        let mut transcript = Sponge::new(&mut em, &PoseidonFp);

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: Process endoscalars.
        ///////////////////////////////////////////////////////////////////////////////////////

        // TODO: Determine the endoscaling operations, representing deferreds from the
        // other curve.

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: Process `StagedObjects` for staging consistency from the previous cycle.
        ///////////////////////////////////////////////////////////////////////////////////////

        // Checks each staged circuit's constraint polynomial r(X) satisfies the mesh consistency equation.
        for staged_data in &left.proof.staged_circuits {
            let y_challenge = left.proof.instance.y.0;
            let sy = self.circuit_mesh.wy(staged_data.circuit_id, y_challenge);
            let ky_at_y = arithmetic::eval(&staged_data.ky, y_challenge);
            let lhs = staged_data.final_rx.revdot(&sy);
            if lhs != ky_at_y {
                return Err(Error::InvalidWitness(
                    "Staged circuit constraint check failed (left proof): rx.revdot(sy) != ky(y)"
                        .into(),
                ));
            }
        }

        for staged_data in &right.proof.staged_circuits {
            let y_challenge = right.proof.instance.y.0;
            let sy = self.circuit_mesh.wy(staged_data.circuit_id, y_challenge);
            let ky_at_y = arithmetic::eval(&staged_data.ky, y_challenge);
            let lhs = staged_data.final_rx.revdot(&sy);
            if lhs != ky_at_y {
                return Err(Error::InvalidWitness(
                    "Staged circuit constraint check failed (right proof): rx.revdot(sy) != ky(y)"
                        .into(),
                ));
            }
        }

        ///////////////////////////////////////////////////////////////////////////////////////
        // Phase: Process the application circuits. The witness polynomials
        // r(X) are over the `C::CircuitField`, and produce commitments to `C::HostCurve`
        // curve points.
        ///////////////////////////////////////////////////////////////////////////////////////

        ///////////////////////////////////////////////////////////////////////////////////////
        // Task: Execute application logic via `Step::witness()` through the Adapter.
        ///////////////////////////////////////////////////////////////////////////////////////

        // Create adapter which wraps the step and implements the `Circuit`.
        if let Some(index) = S::INDEX.get_application_index() {
            if index >= self.num_application_steps {
                return Err(Error::Initialization(
                    "attempted to use application Step index that exceeds Application registered steps".into(),
                ));
            }
        }

        let circuit_id = S::INDEX.circuit_index(Some(self.num_application_steps));
        let circuit = Adapter::<C, S, R, HEADER_SIZE>::new(step);

        // Compute the witness r(X) polynomial for this step's execution.
        let (rx_poly, aux) = circuit.rx::<R>(
            (left.data, right.data, witness),
            self.circuit_mesh.get_key(),
        )?;

        let ((output_header, left_header, right_header), step_aux) = aux;

        // Commit to r(X) with random blinding.
        let blinding = C::CircuitField::random(OsRng);
        let commitment = rx_poly.clone().commit(self.host_generators, blinding);

        // Compute k(Y) polynomial using serialized headers.
        let ky_poly = circuit.ky((
            output_header.clone(),
            left_header.clone(),
            right_header.clone(),
        ))?;

        // Convert the adapter into a `CircuitObject` to access circuit polynomial methods.
        let _circuit_object = circuit.into_object::<R>()?;

        ///////////////////////////////////////////////////////////////////////////////////////
        // Task: Collect all A polynomials (application and previous accumulators).
        ///////////////////////////////////////////////////////////////////////////////////////

        let mut a_polys: Vec<CommittedStructured<R, C>> = vec![];
        let mut ky_polys: Vec<Vec<C::CircuitField>> = vec![];

        // Append r(X) witness polynomial from the application circuit.
        a_polys.push(CommittedPolynomial {
            poly: rx_poly.clone(),
            blind: blinding,
            commitment,
        });

        // Append the previous accumulator A polynomials.
        a_polys.push(CommittedPolynomial {
            poly: left.proof.witness.a_poly.clone(),
            blind: left.proof.witness.a_blinding,
            commitment: left.proof.instance.a,
        });
        a_polys.push(CommittedPolynomial {
            poly: right.proof.witness.a_poly.clone(),
            blind: right.proof.witness.a_blinding,
            commitment: right.proof.instance.a,
        });

        // Append k(Y) polynomial from the application circuit.
        ky_polys.push(ky_poly);

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: B STAGE.
        ///////////////////////////////////////////////////////////////////////////////////////

        // Collect application circuit commitments (Vesta points).
        let a_commitments = a_polys
            .iter()
            .map(|c| c.commitment)
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| Error::CircuitBoundExceeded(self.num_application_steps))?;

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the Vesta commitments.
        let b_inner_rx =
            <EphemeralStageB<C::HostCurve, 3> as StageExt<C::ScalarField, R>>::rx(&a_commitments)?;

        // NESTED COMMITMENT: Commit to the epehemeral polynomial using Pallas generators.
        let b_blinding = C::ScalarField::random(OsRng);
        let b_rx_nested_commitment = b_inner_rx.commit(self.nested_generators, b_blinding);

        let b_point = Point::constant(&mut em, b_rx_nested_commitment)?;
        b_point.write(&mut em, &mut transcript)?;

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: D STAGE. This uses a two-layer nested commitments.
        ///////////////////////////////////////////////////////////////////////////////////////

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: W challenge derivation.
        ///////////////////////////////////////////////////////////////////////////////////////

        // TRANSCRIPT: Squeeze w challenge.
        let w = transcript.squeeze(&mut em)?;
        let w_challenge = *w.value().take();

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: S' Mesh Polynomials.
        ///////////////////////////////////////////////////////////////////////////////////////

        // COMPUTE S': For each previous accumulator, compute M(w, x_i, Y) for checking mesh consistency.
        let s1_poly_acc1 = self.circuit_mesh.wx(w_challenge, left.proof.instance.x.0);
        let s1_blinding_acc1 = C::CircuitField::random(OsRng);
        let s1_commitment_acc1 = s1_poly_acc1.commit(self.host_generators, s1_blinding_acc1);

        let s1_poly_acc2 = self.circuit_mesh.wx(w_challenge, right.proof.instance.x.0);
        let s1_blinding_acc2 = C::CircuitField::random(OsRng);
        let s1_commitment_acc2 = s1_poly_acc2.commit(self.host_generators, s1_blinding_acc2);

        let s_prime: [CommittedPolynomial<_, C>; 2] = [
            CommittedPolynomial {
                poly: s1_poly_acc1,
                blind: s1_blinding_acc1,
                commitment: s1_commitment_acc1,
            },
            CommittedPolynomial {
                poly: s1_poly_acc2,
                blind: s1_blinding_acc2,
                commitment: s1_commitment_acc2,
            },
        ];

        let s_prime_commitments = [s_prime[0].commitment, s_prime[1].commitment];

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: S' Nested Commitment.
        //////////////////////////////////////////////////////////////////////////////////////

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the S' Vesta commitments.
        let d1_rx = <EphemeralStageD<C::HostCurve, 2> as StageExt<C::ScalarField, R>>::rx(
            &s_prime_commitments,
        )?;

        // NESTED COMMITMENT: Commit to the epehemeral polynomial using Pallas generators (nested curve).
        let d1_binding = C::ScalarField::random(OsRng);
        let d1_nested_commitment = d1_rx.commit(self.nested_generators, d1_binding);

        let d1_point = Point::constant(&mut em, d1_nested_commitment)?;
        d1_point.write(&mut em, &mut transcript)?;

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Y and Z challenge derivation.
        ///////////////////////////////////////////////////////////////////////////////////////

        // TRANSCRIPT: Squeeze y challenge.
        let y = transcript.squeeze(&mut em)?;
        let y_challenge = *y.value().take();

        // TRANSCRIPT: Squeeze z challenge.
        let z = transcript.squeeze(&mut em)?;
        let z_challenge = *z.value().take();

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: S'' Mesh Polynomial.
        ///////////////////////////////////////////////////////////////////////////////////////

        // COMPUTE S'': M(w, X, y) polynomial for final mesh consistency checks.
        let s2_poly = self.circuit_mesh.wy(w_challenge, y_challenge);
        let s2_blinding = C::CircuitField::random(OsRng);
        let s2_commitment = s2_poly.commit(self.host_generators, s2_blinding);

        let s_prime_prime: CommittedPolynomial<_, C> = CommittedPolynomial {
            poly: s2_poly,
            blind: s2_blinding,
            commitment: s2_commitment,
        };

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: S'' Nested Commitment
        //////////////////////////////////////////////////////////////////////////////////////

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the S'' Vesta commitment.
        let d2_rx = <EphemeralStageD<C::HostCurve, 1> as StageExt<C::ScalarField, R>>::rx(&[
            s2_commitment,
        ])?;

        // NESTED COMMITMENT: Commit to the epehemeral polynomial using Pallas generators (nested curve).
        let d2_binding = C::ScalarField::random(OsRng);
        let d2_nested_commitment = d2_rx.commit(self.nested_generators, d2_binding);

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Compute B polynomials for revdot verification.
        //
        //  For each application circuit: B_i(X) = A_i(X) * z + t(X,z) + M(circuit_id, X, y),
        //  and this construction ensures: A_i (revdot) B_i = k_i(y).
        ///////////////////////////////////////////////////////////////////////////////////////

        let tz = R::tz(z_challenge);

        let mut b_polys: Vec<CommittedStructured<R, C>> = a_polys
            .iter()
            .take(1)
            .zip([circuit_id].iter())
            .map(|(a, &circuit_id)| {
                let mut b_poly = a.poly.clone();
                b_poly.dilate(z_challenge);
                b_poly.add_assign(&tz);
                b_poly.add_assign(
                    &self
                        .circuit_mesh
                        .wy(omega_j(circuit_id as u32), y_challenge),
                );

                let b_blinding = C::CircuitField::random(OsRng);
                let b_commitment = b_poly.commit(self.host_generators, b_blinding);

                CommittedPolynomial {
                    poly: b_poly,
                    blind: b_blinding,
                    commitment: b_commitment,
                }
            })
            .collect();

        // Append existing accumulator B polynomials.
        b_polys.push(CommittedPolynomial {
            poly: left.proof.witness.b_poly.clone(),
            blind: left.proof.witness.b_blinding,
            commitment: left.proof.instance.b,
        });
        b_polys.push(CommittedPolynomial {
            poly: right.proof.witness.b_poly.clone(),
            blind: right.proof.witness.b_blinding,
            commitment: right.proof.instance.b,
        });

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Compute error / slack term (from folding multiple revdot checks)
        // before computing the u and v evaluations.
        ///////////////////////////////////////////////////////////////////////////////////////

        // The prover computes all of the error terms (cross products).
        let mut cross_products = Vec::new();
        for (i, a) in a_polys.iter().enumerate() {
            for (j, b) in b_polys.iter().enumerate() {
                if i != j {
                    let cross = a.poly.revdot(&b.poly);
                    cross_products.push(cross);
                }
            }
        }

        let cross_products = cross_products
            .clone()
            .try_into()
            .map_err(|_| Error::CircuitBoundExceeded(self.num_application_steps))?;

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Compute D staging polynomial.
        ///////////////////////////////////////////////////////////////////////////////////////

        let d_staging_witness = (
            [w_challenge, y_challenge, z_challenge],
            [d1_nested_commitment, d2_nested_commitment],
            cross_products,
        );

        let d_rx = <DStage<C::NestedCurve> as StageExt<Fp, R>>::rx(d_staging_witness)?;

        ///////////////////////////////////////////////////////////////////////////////////////
        // LAYER OF INDIRECTION: We now introduce another nested commitment layer to produce
        // an Fp-hashable nested commitment for the transcript.
        let d_rx_blinding = C::CircuitField::random(OsRng);
        let d_rx_commitment = d_rx.commit(self.host_generators, d_rx_blinding);

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the D staged circuit Vesta commitment.
        let d_rx_inner =
            <IndirectionStageD<C::HostCurve> as StageExt<C::ScalarField, R>>::rx(d_rx_commitment)?;

        // NESTED COMMITMENT: Commit to the epehemeral polynomial using Pallas generators (nested curve).
        let d_rx_nested_commitment_blinding = C::ScalarField::random(OsRng);
        let d_rx_nested_commitment =
            d_rx_inner.commit(self.nested_generators, d_rx_nested_commitment_blinding);

        let d_point = Point::constant(&mut em, d_rx_nested_commitment)?;
        d_point.write(&mut em, &mut transcript)?;
        ///////////////////////////////////////////////////////////////////////////////////////

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: E STAGE. This uses a two-layer nested commitments.
        ///////////////////////////////////////////////////////////////////////////////////////

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: mu and nu challenge derivation for checking revdot claims are correct.
        ///////////////////////////////////////////////////////////////////////////////////////

        // TRANSCRIPT: Squeeze mu challenge.
        let mu = transcript.squeeze(&mut em)?;
        let mu_challenge = *mu.value().take();

        // TRANSCRIPT: Squeeze nu challenge.
        let nu = transcript.squeeze(&mut em)?;
        let nu_challenge = *nu.value().take();

        let mu_inv = mu_challenge.invert().unwrap();
        let munu = mu_challenge * nu_challenge;

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Folding A and B polynomials into single polynomials.
        ///////////////////////////////////////////////////////////////////////////////////////

        let a_poly = structured::Polynomial::fold(a_polys.iter().map(|a| &a.poly), mu_inv);
        let a_blinding = C::CircuitField::random(OsRng);
        let a_commitment = a_poly.commit(self.host_generators, a_blinding);

        let a_folded: CommittedPolynomial<_, C> = CommittedPolynomial {
            poly: a_poly,
            blind: a_blinding,
            commitment: a_commitment,
        };

        let b_poly = structured::Polynomial::fold(b_polys.iter().map(|b| &b.poly), munu);
        let b_blinding = C::CircuitField::random(OsRng);
        let b_commitment = b_poly.commit(self.host_generators, b_blinding);

        let b_folded: CommittedPolynomial<_, C> = CommittedPolynomial {
            poly: b_poly,
            blind: b_blinding,
            commitment: b_commitment,
        };

        let a_and_b_commmitments = [a_folded.commitment, b_folded.commitment];

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: A and B Nested Commitment
        //////////////////////////////////////////////////////////////////////////////////////

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the A and B Vesta commitments.
        let e1_rx = <EphemeralStageE<C::HostCurve, 2> as StageExt<C::ScalarField, R>>::rx(
            &a_and_b_commmitments,
        )?;

        // NESTED COMMITMENT: Commit to the epehemeral polynomial using Pallas generators (nested curve).
        let e1_binding = C::ScalarField::random(OsRng);
        let e1_nested_commitment = e1_rx.commit(self.nested_generators, e1_binding);

        let e1_point = Point::constant(&mut em, e1_nested_commitment)?;
        e1_point.write(&mut em, &mut transcript)?;

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: x challenge derivation.
        ///////////////////////////////////////////////////////////////////////////////////////

        // TRANSCRIPT: Squeeze x challenge.
        let x = transcript.squeeze(&mut em)?;
        let x_challenge = *x.value().take();

        let xz = x_challenge * z_challenge;
        let txz_claimed = R::txz(x_challenge, z_challenge);

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Compute S for mesh consistency.
        ///////////////////////////////////////////////////////////////////////////////////////

        let s_polynomial = self.circuit_mesh.xy(x_challenge, y_challenge);
        let s_blinding = C::CircuitField::random(OsRng);
        let s_commitment = s_polynomial.commit(self.host_generators, s_blinding);

        let s: CommittedPolynomial<_, C> = CommittedPolynomial {
            poly: s_polynomial,
            blind: s_blinding,
            commitment: s_commitment,
        };

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the S Vesta commitment.
        let e2_inner_rx =
            <EphemeralStageE<C::HostCurve, 1> as StageExt<C::ScalarField, R>>::rx(&[s_commitment])?;

        // NESTED COMMITMENT: Commit to the epehemeral polynomial using Pallas generators (nested curve).
        let e2_blinding = C::ScalarField::random(OsRng);
        let e2_nested_commitment = e2_inner_rx.commit(self.nested_generators, e2_blinding);

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Compute evaluations.
        ///////////////////////////////////////////////////////////////////////////////////////

        let circuit_evaluations: [Fp; 1] =
            [self
                .circuit_mesh
                .wxy(omega_j(circuit_id as u32), x_challenge, y_challenge)];

        let consistency_evaluations = ConsistencyEvaluations::<C> {
            acc1_s_at_w: left.proof.witness.s_poly.eval(w_challenge),
            acc2_s_at_w: right.proof.witness.s_poly.eval(w_challenge),
            s1_acc1_at_y: s_prime[0].poly.eval(y_challenge),
            s1_acc2_at_y: s_prime[1].poly.eval(y_challenge),
            s2_at_x: s_prime_prime.poly.eval(x_challenge),
        };

        let a_polys_evals_x: Vec<Fp> = a_polys
            .iter()
            .map(|a_poly| a_poly.poly.eval(x_challenge))
            .collect();
        let a_polys_evals_xz: Vec<Fp> = a_polys
            .iter()
            .take(1)
            .map(|a_poly| a_poly.poly.eval(xz))
            .collect();
        let acc_b_evals_x = [
            left.proof.witness.b_poly.eval(x_challenge),
            right.proof.witness.b_poly.eval(x_challenge),
        ];

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Compute batched polynomial evaluation claims.
        ///////////////////////////////////////////////////////////////////////////////////////

        let batched_a_eval = {
            a_polys_evals_x
                .iter()
                .rev()
                .fold(Fp::zero(), |acc, &eval| acc * mu_inv + eval)
        };
        let batched_b_eval = {
            let circuit_b_evals = a_polys_evals_xz
                .iter()
                .zip(circuit_evaluations.iter())
                .map(|(&eval_xz, &circuit_eval)| eval_xz + txz_claimed + circuit_eval);

            let b_evals: Vec<_> = circuit_b_evals
                .chain(acc_b_evals_x.iter().copied())
                .collect();

            b_evals
                .iter()
                .rev()
                .fold(Fp::zero(), |acc, &eval| acc * munu + eval)
        };

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Absorb all evaluations into the transcript before driving alpha.
        ///////////////////////////////////////////////////////////////////////////////////////

        for eval in circuit_evaluations {
            let _ = Element::constant(&mut em, eval).write(&mut em, &mut transcript);
        }

        let _ = Element::constant(&mut em, consistency_evaluations.acc1_s_at_w)
            .write(&mut em, &mut transcript);
        let _ = Element::constant(&mut em, consistency_evaluations.acc2_s_at_w)
            .write(&mut em, &mut transcript);
        let _ = Element::constant(&mut em, consistency_evaluations.s1_acc1_at_y)
            .write(&mut em, &mut transcript);
        let _ = Element::constant(&mut em, consistency_evaluations.s1_acc2_at_y)
            .write(&mut em, &mut transcript);
        let _ = Element::constant(&mut em, consistency_evaluations.s2_at_x)
            .write(&mut em, &mut transcript);

        for eval in a_polys_evals_x.iter().as_slice() {
            let _ = Element::constant(&mut em, *eval).write(&mut em, &mut transcript);
        }

        for eval in a_polys_evals_xz.iter().as_slice() {
            let _ = Element::constant(&mut em, *eval).write(&mut em, &mut transcript);
        }

        for eval in acc_b_evals_x {
            let _ = Element::constant(&mut em, eval).write(&mut em, &mut transcript);
        }

        let _ = Element::constant(&mut em, batched_a_eval).write(&mut em, &mut transcript);
        let _ = Element::constant(&mut em, batched_b_eval).write(&mut em, &mut transcript);

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Collect evals – intermediate evaluations at challenge points used to
        // construct the batched claims.
        ///////////////////////////////////////////////////////////////////////////////////////

        let mut intermediate_evals = Vec::with_capacity(NUM_EVALS);

        intermediate_evals.extend_from_slice(&circuit_evaluations);

        intermediate_evals.push(consistency_evaluations.acc1_s_at_w);
        intermediate_evals.push(consistency_evaluations.acc2_s_at_w);
        intermediate_evals.push(consistency_evaluations.s1_acc1_at_y);
        intermediate_evals.push(consistency_evaluations.s1_acc2_at_y);
        intermediate_evals.push(consistency_evaluations.s2_at_x);

        intermediate_evals.extend(a_polys_evals_x.iter().copied());
        intermediate_evals.extend(a_polys_evals_xz.iter().copied());

        intermediate_evals.extend_from_slice(&acc_b_evals_x);

        intermediate_evals.push(batched_a_eval);
        intermediate_evals.push(batched_b_eval);

        let intermediate_evals_array: [Fp; NUM_EVALS] = intermediate_evals
            .try_into()
            .expect("intermediate_evals should have exactly NUM_EVALS elements");

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Compute E staging polynomial.
        ///////////////////////////////////////////////////////////////////////////////////////

        let e_staging_witness = (
            [mu_challenge, nu_challenge, x_challenge],
            [e1_nested_commitment, e2_nested_commitment],
            intermediate_evals_array,
        );

        let e_rx = <EStage<C::NestedCurve> as StageExt<Fp, R>>::rx(e_staging_witness)?;

        ///////////////////////////////////////////////////////////////////////////////////////
        // LAYER OF INDIRECTION: We now introduce another nested commitment layer to produce
        // an Fp-hashable nested commitment for the transcript.
        let e_rx_blinding = C::CircuitField::random(OsRng);
        let e_rx_commitment = e_rx.commit(self.host_generators, e_rx_blinding);

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the D staged circuit Vesta commitment.
        let e_rx_inner =
            <IndirectionStageE<C::HostCurve> as StageExt<C::ScalarField, R>>::rx(e_rx_commitment)?;

        // NESTED COMMITMENT: Commit to the epehemeral polynomial using Pallas generators (nested curve).
        let e_rx_nested_commitment_blinding = C::ScalarField::random(OsRng);
        let e_rx_nested_commitment =
            e_rx_inner.commit(self.nested_generators, e_rx_nested_commitment_blinding);

        let e_point = Point::constant(&mut em, e_rx_nested_commitment)?;
        e_point.write(&mut em, &mut transcript)?;
        ///////////////////////////////////////////////////////////////////////////////////////

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: G STAGE.
        ///////////////////////////////////////////////////////////////////////////////////////

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: alpha challenge derivation.
        ///////////////////////////////////////////////////////////////////////////////////////

        // TRANSCRIPT: Squeeze alpha challenge.
        let alpha = transcript.squeeze(&mut em)?;
        let alpha_challenge = *alpha.value().take();

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Compute and commit to the F polynomial which aggregates quotient
        // polynomials using the alpha challenge.
        ///////////////////////////////////////////////////////////////////////////////////////

        let f_polynomial = {
            let mut queries: Vec<Box<dyn Iterator<Item = Fp>>> = vec![
                factor_iter(a_folded.poly.iter_coeffs(), x_challenge),
                factor_iter(b_folded.poly.iter_coeffs(), x_challenge),
                factor_iter(
                    left.proof.witness.p_poly.iter_coeffs(),
                    left.proof.instance.u.0,
                ),
                factor_iter(
                    right.proof.witness.p_poly.iter_coeffs(),
                    right.proof.instance.u.0,
                ),
                factor_iter(left.proof.witness.s_poly.iter_coeffs(), w_challenge),
                factor_iter(right.proof.witness.s_poly.iter_coeffs(), w_challenge),
                factor_iter(s.poly.iter_coeffs(), omega_j(circuit_id as u32)),
                factor_iter(s.poly.iter_coeffs(), w_challenge),
                factor_iter(s_prime[0].poly.iter_coeffs(), left.proof.instance.y.0),
                factor_iter(s_prime[1].poly.iter_coeffs(), right.proof.instance.y.0),
                factor_iter(s_prime[0].poly.iter_coeffs(), y_challenge),
                factor_iter(s_prime[1].poly.iter_coeffs(), y_challenge),
                factor_iter(s_prime_prime.poly.iter_coeffs(), left.proof.instance.x.0),
                factor_iter(s_prime_prime.poly.iter_coeffs(), right.proof.instance.x.0),
                factor_iter(s_prime_prime.poly.iter_coeffs(), x_challenge),
            ];

            for a_poly in &a_polys {
                queries.push(factor_iter(a_poly.poly.iter_coeffs(), x_challenge));
            }

            for a_poly in a_polys.iter().take(1) {
                queries.push(factor_iter(a_poly.poly.iter_coeffs(), xz));
            }

            let mut f_poly = Vec::with_capacity(R::num_coeffs());
            'poly: loop {
                let mut this_coeff = Fp::ZERO;
                for query in queries.iter_mut() {
                    this_coeff *= alpha_challenge;
                    if let Some(coeff) = query.next() {
                        this_coeff += coeff;
                    } else {
                        break 'poly;
                    }
                }
                f_poly.push(this_coeff);
            }
            f_poly.reverse();
            unstructured::Polynomial::<Fp, R>::from_coeffs(f_poly)
        };

        let f_blinding = C::CircuitField::random(OsRng);
        let f_commitment = f_polynomial.commit(self.host_generators, f_blinding);

        let f: CommittedPolynomial<_, C> = CommittedPolynomial {
            poly: f_polynomial,
            blind: f_blinding,
            commitment: f_commitment,
        };

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the F Vesta commitment.
        let g1_inner_rx =
            <EphemeralStageG<C::HostCurve, 1> as StageExt<C::ScalarField, R>>::rx(&[f.commitment])?;

        // NESTED COMMITMENT: Commit to the epehemeral polynomial using Pallas generators (nested curve).
        let g1_blinding = C::ScalarField::random(OsRng);
        let g1_nested_commitment: <C as Cycle>::NestedCurve =
            g1_inner_rx.commit(self.nested_generators, g1_blinding);

        let g1_point = Point::constant(&mut em, g1_nested_commitment)?;
        g1_point.write(&mut em, &mut transcript)?;

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: u challenge derivation.
        ///////////////////////////////////////////////////////////////////////////////////////

        // TRANSCRIPT: Squeeze u challenge.
        let u = transcript.squeeze(&mut em)?;
        let u_challenge = *u.value().take();

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Supply the u evaluation claims.
        ///////////////////////////////////////////////////////////////////////////////////////

        let evaluations_final = FinalEvaluations::<C> {
            a: a_folded.poly.eval(u_challenge),
            b: b_folded.poly.eval(u_challenge),
            acc1_p: left.proof.witness.p_poly.eval(u_challenge),
            acc2_p: right.proof.witness.p_poly.eval(u_challenge),
            acc1_s: left.proof.witness.s_poly.eval(u_challenge),
            acc2_s: right.proof.witness.s_poly.eval(u_challenge),
            s: s.poly.eval(u_challenge),
            s1: [
                s_prime[0].poly.eval(u_challenge),
                s_prime[1].poly.eval(u_challenge),
            ],
            s2: s_prime_prime.poly.eval(u_challenge),
        };

        let a_polys_final_evals: Vec<Fp> = a_polys
            .iter()
            .map(|a_poly| a_poly.poly.eval(u_challenge))
            .collect();

        for eval in a_polys_final_evals.iter().as_slice() {
            let _ = Element::constant(&mut em, *eval).write(&mut em, &mut transcript);
        }

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: b challenge derivation. This checks all evaluations are correct by
        // folding the claims together.
        ///////////////////////////////////////////////////////////////////////////////////////

        // TRANSCRIPT: Squeeze b challenge.
        let b = transcript.squeeze(&mut em)?;
        let b_challenge = *b.value().take();

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Collect evals' – evaluations at final batching point u challenge.
        ///////////////////////////////////////////////////////////////////////////////////////

        let mut final_evals = Vec::with_capacity(16);

        final_evals.push(evaluations_final.a);
        final_evals.push(evaluations_final.b);
        final_evals.push(evaluations_final.acc1_p);
        final_evals.push(evaluations_final.acc2_p);
        final_evals.push(evaluations_final.acc1_s);
        final_evals.push(evaluations_final.acc2_s);
        final_evals.push(evaluations_final.s);
        final_evals.push(evaluations_final.s1[0]);
        final_evals.push(evaluations_final.s1[1]);
        final_evals.push(evaluations_final.s2);

        final_evals.extend(a_polys_final_evals.iter().copied());

        pub const NUM_FINAL_EVALS: usize = 13;
        let final_evals_array: [Fp; NUM_FINAL_EVALS] = final_evals
            .try_into()
            .expect("intermediate_evals should have exactly `NUM_FINAL_EVALS` elements");

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Compute G staging polynomial.
        ///////////////////////////////////////////////////////////////////////////////////////

        let g_staging_witness = (
            [alpha_challenge, u_challenge],
            [g1_nested_commitment],
            final_evals_array,
        );

        let g_rx = <GStage<C::NestedCurve> as StageExt<Fp, R>>::rx(g_staging_witness)?;

        ///////////////////////////////////////////////////////////////////////////////////////
        // LAYER OF INDIRECTION: We now introduce another nested commitment layer to produce
        // an Fp-hashable nested commitment for the transcript.
        let g_rx_blinding = C::CircuitField::random(OsRng);
        let g_rx_commitment = g_rx.commit(self.host_generators, g_rx_blinding);

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the D staged circuit Vesta commitment.
        let g_rx_inner =
            <IndirectionStageG<C::HostCurve> as StageExt<C::ScalarField, R>>::rx(g_rx_commitment)?;

        // NESTED COMMITMENT: Commit to the epehemeral polynomial using Pallas generators (nested curve).
        let g_rx_nested_commitment_blinding = C::ScalarField::random(OsRng);
        let g_rx_nested_commitment =
            g_rx_inner.commit(self.nested_generators, g_rx_nested_commitment_blinding);

        let g_point = Point::constant(&mut em, g_rx_nested_commitment)?;
        g_point.write(&mut em, &mut transcript)?;
        ///////////////////////////////////////////////////////////////////////////////////////

        /////////////////////////////////////////////////////////////////////////////////////
        // TASK: Compute v: batched polynomial evaluation check that verifies
        // all polynomial evaluations are consistent by batching them together
        /////////////////////////////////////////////////////////////////////////////////////

        // Build arrays for V computation witness.
        let mut eval_points = Vec::new();
        let mut intermediate_evals = Vec::new();
        let mut final_evals_for_queries = Vec::new();
        let mut inverses = Vec::new();

        // TODO: This should be it's own routine as well.
        let (_v, p_poly, p_blind) = {
            let mut v = Fp::ZERO;

            let mut proc = |point: Fp, eval, eval_prime| {
                v *= alpha_challenge;
                v += (u_challenge - point).invert().unwrap() * (eval_prime - eval);

                eval_points.push(point);
                intermediate_evals.push(eval);
                final_evals_for_queries.push(eval_prime);
                inverses.push((u_challenge - point).invert().unwrap());
            };

            // Handle each of the queries.

            // Batched A and B evaluations at x.
            proc(x_challenge, batched_a_eval, evaluations_final.a);
            proc(x_challenge, batched_b_eval, evaluations_final.b);

            // Accumulator p polynomials at their u points.
            proc(
                left.proof.instance.u.0,
                left.proof.instance.v.0,
                evaluations_final.acc1_p,
            );
            proc(
                right.proof.instance.u.0,
                right.proof.instance.v.0,
                evaluations_final.acc2_p,
            );

            // Accumulator s polynomials at w.
            proc(
                w_challenge,
                consistency_evaluations.acc1_s_at_w,
                evaluations_final.acc1_s,
            );
            proc(
                w_challenge,
                consistency_evaluations.acc2_s_at_w,
                evaluations_final.acc2_s,
            );

            // Circuit evaluations at their IDs.
            proc(
                omega_j(circuit_id as u32),
                circuit_evaluations[0],
                evaluations_final.s,
            );

            // s2 at x.
            proc(
                w_challenge,
                consistency_evaluations.s2_at_x,
                evaluations_final.s,
            );

            // s1 polynomials at accumulator y points.
            proc(
                left.proof.instance.y.0,
                consistency_evaluations.acc1_s_at_w,
                evaluations_final.s1[0],
            );
            proc(
                right.proof.instance.y.0,
                consistency_evaluations.acc2_s_at_w,
                evaluations_final.s1[1],
            );

            // s1 polynomials at y.
            proc(
                y_challenge,
                consistency_evaluations.s1_acc1_at_y,
                evaluations_final.s1[0],
            );
            proc(
                y_challenge,
                consistency_evaluations.s1_acc2_at_y,
                evaluations_final.s1[1],
            );

            // s2 at accumulator x points.
            proc(
                left.proof.instance.x.0,
                consistency_evaluations.s1_acc1_at_y,
                evaluations_final.s2,
            );
            proc(
                right.proof.instance.x.0,
                consistency_evaluations.s1_acc2_at_y,
                evaluations_final.s2,
            );

            // a_polys evaluations at x.
            proc(
                x_challenge,
                consistency_evaluations.s2_at_x,
                evaluations_final.s2,
            );

            // Add proc calls for a_polys queries at x and xz
            for (eval_x, final_eval) in a_polys_evals_x.iter().zip(a_polys_final_evals.iter()) {
                proc(x_challenge, *eval_x, *final_eval);
            }
            // Only add xz proc calls for circuit polynomials
            for (eval_xz, final_eval) in a_polys_evals_xz
                .iter()
                .zip(a_polys_final_evals.iter().take(1))
            {
                proc(xz, *eval_xz, *final_eval);
            }

            let mut p_poly = f.poly.clone();
            let mut p_blind = f.blind;

            let mut add_poly =
                |f: &dyn Fn(&mut unstructured::Polynomial<Fp, R>), eval_prime: Fp, blind| {
                    p_poly.scale(b_challenge);
                    p_blind *= b_challenge;
                    v *= b_challenge;

                    f(&mut p_poly);
                    v += eval_prime;
                    p_blind += blind;
                };

            add_poly(
                &|p| p.add_structured(&a_folded.poly),
                evaluations_final.a,
                &a_folded.blind,
            );
            add_poly(
                &|p| p.add_structured(&b_folded.poly),
                evaluations_final.b,
                &b_folded.blind,
            );
            add_poly(
                &|p| p.add_assign(&left.proof.witness.p_poly),
                evaluations_final.acc1_p,
                &left.proof.witness.p_blinding,
            );
            add_poly(
                &|p| p.add_assign(&right.proof.witness.p_poly),
                evaluations_final.acc2_p,
                &right.proof.witness.p_blinding,
            );
            add_poly(
                &|p| p.add_assign(&left.proof.witness.s_poly),
                evaluations_final.acc1_s,
                &left.proof.witness.s_blinding,
            );
            add_poly(
                &|p| p.add_assign(&right.proof.witness.s_poly),
                evaluations_final.acc2_s,
                &right.proof.witness.s_blinding,
            );
            add_poly(&|p| p.add_assign(&s.poly), evaluations_final.s, &s.blind);
            add_poly(
                &|p| p.add_assign(&s_prime[0].poly),
                evaluations_final.s1[0],
                &s_prime[0].blind,
            );
            add_poly(
                &|p| p.add_assign(&s_prime[1].poly),
                evaluations_final.s1[1],
                &s_prime[1].blind,
            );
            add_poly(
                &|p| p.add_structured(&s_prime_prime.poly),
                evaluations_final.s2,
                &s_prime_prime.blind,
            );

            // Add proc calls for a_polys
            for (a_poly, final_eval) in a_polys.iter().zip(a_polys_final_evals.iter()) {
                add_poly(
                    &|p| p.add_structured(&a_poly.poly),
                    *final_eval,
                    &a_poly.blind,
                );
            }

            (v, p_poly, p_blind)
        };

        // Convert to fixed arrays
        let _eval_points: [Fp; 19] = eval_points
            .try_into()
            .expect("eval_points length should match NUM_V_QUERIES");
        let _intermediate_evals: [Fp; 19] = intermediate_evals
            .try_into()
            .expect("intermediate_evals length should match NUM_V_QUERIES");
        let _final_evals_for_queries: [Fp; 19] = final_evals_for_queries
            .try_into()
            .expect("final_evals_for_queries length should match NUM_V_QUERIES");
        let _inverses: [Fp; 19] = inverses
            .try_into()
            .expect("inverses length should match NUM_V_QUERIES");

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Compute p(X) commitment.
        ///////////////////////////////////////////////////////////////////////////////////////

        let p_commitment = p_poly.commit(self.host_generators, p_blind);

        let p: CommittedPolynomial<_, C> = CommittedPolynomial {
            poly: p_poly,
            blind: p_blind,
            commitment: p_commitment,
        };

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the F Vesta commitment.
        let g2_inner_rx =
            <EphemeralStageG<C::HostCurve, 1> as StageExt<C::ScalarField, R>>::rx(&[p.commitment])?;

        // NESTED COMMITMENT: Commit to the epehemeral polynomial using Pallas generators (nested curve).
        let g2_blinding = C::ScalarField::random(OsRng);
        let g2_nested_commitment: <C as Cycle>::NestedCurve =
            g2_inner_rx.commit(self.nested_generators, g2_blinding);

        let g2_point = Point::constant(&mut em, g2_nested_commitment)?;
        g2_point.write(&mut em, &mut transcript)?;

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Build KY staging polyhnomial for ky polynomial coefficients.
        ///////////////////////////////////////////////////////////////////////////////////////

        /// Size of the KY polynomial coefficients array.
        /// This is 1 + HEADER_SIZE * 3 where HEADER_SIZE = 4.
        /// (output_header + left_header + right_header + 1 for the constant term)
        pub const KY_POLY_SIZE: usize = 13;

        // Append application circuits ky coefficients.
        let mut application_ky_coffs = Vec::new();
        for ky_poly in &ky_polys {
            application_ky_coffs.extend_from_slice(ky_poly);
        }

        let ky_coeff_array: [C::CircuitField; KY_POLY_SIZE] = application_ky_coffs
            .try_into()
            .map_err(|_| Error::CircuitBoundExceeded(KY_POLY_SIZE))?;

        // Build the K staging polynomial.
        let k_rx = <KYStage<C::NestedCurve, KY_POLY_SIZE> as StageExt<Fp, R>>::rx(ky_coeff_array)?;

        ///////////////////////////////////////////////////////////////////////////////////////
        // LAYER OF INDIRECTION: We now introduce another nested commitment layer to produce
        // an Fp-hashable nested commitment for the transcript.
        let k_rx_blinding = C::CircuitField::random(OsRng);
        let k_rx_commitment = k_rx.commit(self.host_generators, k_rx_blinding);

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the D staged circuit Vesta commitment.
        let k_rx_inner =
            <IndirectionStageG<C::HostCurve> as StageExt<C::ScalarField, R>>::rx(k_rx_commitment)?;

        // NESTED COMMITMENT: Commit to the epehemeral polynomial using Pallas generators (nested curve).
        let k_rx_nested_commitment_blinding = C::ScalarField::random(OsRng);
        let k_rx_nested_commitment =
            k_rx_inner.commit(self.nested_generators, k_rx_nested_commitment_blinding);

        // TODO: Determine what nested commitments *shouldn't* be absorbed into the transcript, like this?
        let k_point = Point::constant(&mut em, k_rx_nested_commitment)?;
        k_point.write(&mut em, &mut transcript)?;
        ///////////////////////////////////////////////////////////////////////////////////////

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: Return the proof.
        ///////////////////////////////////////////////////////////////////////////////////////

        Ok((
            Proof {
                circuit_id,
                left_header,
                right_header,
                rx: rx_poly,
                _marker: PhantomData,
                witness: left.proof.witness,
                instance: left.proof.instance,
                endoscalars: left.proof.endoscalars,
                deferreds: left.proof.deferreds,
                staged_circuits: left.proof.staged_circuits,
            },
            step_aux,
        ))
    }

    /// Rerandomize proof-carrying data.
    ///
    /// This will internally fold the [`Pcd`] with a random proof instance using
    /// an internal rerandomization step, such that the resulting proof is valid
    /// for the same [`Header`] but reveals nothing else about the original
    /// proof. As a result, [`Application::verify`] should produce the same
    /// result on the provided `pcd` as it would the output of this method.
    pub fn rerandomize<'source, RNG: Rng, H: Header<C::CircuitField>>(
        &self,
        pcd: Pcd<'source, C, R, H>,
        rng: &mut RNG,
    ) -> Result<Pcd<'source, C, R, H>> {
        let random_proof = self.random(rng);
        let data = pcd.data.clone();
        let rerandomized_proof = self.merge(
            rng,
            step::rerandomize::Rerandomize::new(),
            (),
            pcd,
            random_proof,
        )?;

        Ok(rerandomized_proof.0.carry(data))
    }

    /// Verifies some [`Pcd`] for the provided [`Header`].
    pub fn verify<RNG: Rng, H: Header<C::CircuitField>>(
        &self,
        pcd: &Pcd<'_, C, R, H>,
        mut rng: RNG,
    ) -> Result<bool> {
        let rx = &pcd.proof.rx;
        let circuit_id = omega_j(pcd.proof.circuit_id as u32);
        let y = C::CircuitField::random(&mut rng);
        let z = C::CircuitField::random(&mut rng);
        let sy = self.circuit_mesh.wy(circuit_id, y);
        let tz = R::tz(z);

        let mut rhs = rx.clone();
        rhs.dilate(z);
        rhs.add_assign(&sy);
        rhs.add_assign(&tz);

        let mut ky = Vec::with_capacity(1 + HEADER_SIZE * 3);

        let mut emulator: Emulator<Wireless<Always<()>, _>> = Emulator::wireless();
        let gadget = H::encode(&mut emulator, Always::maybe_just(|| pcd.data.clone()))?;
        let gadget = step::padded::for_header::<H, HEADER_SIZE, _>(&mut emulator, gadget)?;

        {
            let mut buf = Vec::with_capacity(HEADER_SIZE);
            gadget.write(&mut emulator, &mut buf)?;
            for elem in buf {
                ky.push(*elem.value().take());
            }
        }

        if pcd.proof.left_header.len() != HEADER_SIZE || pcd.proof.right_header.len() != HEADER_SIZE
        {
            return Err(Error::MalformedEncoding(
                "{left,right}_header has incorrect size".into(),
            ));
        }

        ky.extend(pcd.proof.left_header.iter().cloned());
        ky.extend(pcd.proof.right_header.iter().cloned());
        ky.push(C::CircuitField::ONE);

        ky.reverse();
        assert_eq!(ky.len(), 1 + HEADER_SIZE * 3);

        let valid = rx.revdot(&rhs) == eval(ky.iter(), y);

        Ok(valid)
    }

    /// Verifies some [`Pcd`] for the provided [`Header`].
    pub fn decide<RNG: Rng, H: Header<C::CircuitField>>(
        &self,
        pcd: &Pcd<'_, C, R, H>,
        mut _rng: RNG,
    ) -> Result<bool> {
        let witness = &pcd.proof.witness;
        let instance = &pcd.proof.instance;

        // 1. Check revdot: a.revdot(b) == c.
        let c_check = witness.a_poly.revdot(&witness.b_poly);
        if c_check != instance.c {
            return Ok(false);
        }

        // 2. Check polynomial evaluation: p_poly(u) == v.
        let v_check = witness.p_poly.eval(instance.u.0);
        if v_check != instance.v.0 {
            return Ok(false);
        }

        // 3. Check mesh consistency: s_poly == mesh.xy(x, y).
        let s_expected = self.circuit_mesh.xy(instance.x.0, instance.y.0);
        if witness.s_poly != s_expected {
            return Ok(false);
        }

        // 4. Verify commitment openings with pedersen vector commitment (later implement full IPA verification obviously).
        let a_commitment = witness
            .a_poly
            .commit(self.host_generators, witness.a_blinding);
        if a_commitment != instance.a {
            return Ok(false);
        }

        let b_commitment = witness
            .b_poly
            .commit(self.host_generators, witness.b_blinding);
        if b_commitment != instance.b {
            return Ok(false);
        }

        let p_commitment = witness
            .p_poly
            .commit(self.host_generators, witness.p_blinding);
        if p_commitment != instance.p {
            return Ok(false);
        }

        let s_commitment = witness
            .s_poly
            .commit(self.host_generators, witness.s_blinding);
        if s_commitment != instance.s {
            return Ok(false);
        }

        Ok(true)
    }
}

//! # `ragu_pcd`

#![cfg_attr(not(test), no_std)]
#![allow(clippy::type_complexity)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![doc(html_favicon_url = "https://tachyon.z.cash/assets/ragu/v1_favicon32.png")]
#![doc(html_logo_url = "https://tachyon.z.cash/assets/ragu/v1_rustdoc128.png")]

extern crate alloc;

use arithmetic::{Cycle, eval};
use ff::Field;
use ragu_circuits::{
    CircuitExt,
    composition::{
        b_stage::EphemeralStageB,
        d_stage::{DStage, EphemeralStageD, IndirectionStageD},
        e_stage::{EStage, EphemeralStageE, IndirectionStageE},
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
    CommittedStructured, ConsistencyEvaluations, EvaluationPoint,
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
        let mut _ky_polys: Vec<Vec<C::CircuitField>> = vec![];

        // Append r(X) witness polynomial from the application circuit.
        a_polys.push(CommittedPolynomial {
            poly: rx_poly.clone(),
            _blind: blinding,
            commitment,
        });

        // Append the previous accumulator A polynomials.
        a_polys.push(CommittedPolynomial {
            poly: left.proof.witness.a_poly.clone(),
            _blind: left.proof.witness.a_blinding,
            commitment: left.proof.instance.a,
        });
        a_polys.push(CommittedPolynomial {
            poly: right.proof.witness.a_poly.clone(),
            _blind: right.proof.witness.a_blinding,
            commitment: right.proof.instance.a,
        });

        // Append k(Y) polynomial from the application circuit.
        _ky_polys.push(ky_poly);

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
                _blind: s1_blinding_acc1,
                commitment: s1_commitment_acc1,
            },
            CommittedPolynomial {
                poly: s1_poly_acc2,
                _blind: s1_blinding_acc2,
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
            _blind: s2_blinding,
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
                    _blind: b_blinding,
                    commitment: b_commitment,
                }
            })
            .collect();

        // Append existing accumulator B polynomials.
        b_polys.push(CommittedPolynomial {
            poly: left.proof.witness.b_poly.clone(),
            _blind: left.proof.witness.b_blinding,
            commitment: left.proof.instance.b,
        });
        b_polys.push(CommittedPolynomial {
            poly: right.proof.witness.b_poly.clone(),
            _blind: right.proof.witness.b_blinding,
            commitment: right.proof.instance.b,
        });

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Compute error / slack term (from folding multiple revdot checks)
        // before computing the u and v evaluations.
        ///////////////////////////////////////////////////////////////////////////////////////

        // The prover computes all of the error terms (cross products).
        let len = a_polys.len();
        let mut cross_products = Vec::new();
        for i in 0..len {
            for j in 0..len {
                if i != j {
                    let cross = a_polys[i].poly.revdot(&b_polys[j].poly);
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
            _blind: a_blinding,
            commitment: a_commitment,
        };

        let b_poly = structured::Polynomial::fold(b_polys.iter().map(|b| &b.poly), munu);
        let b_blinding = C::CircuitField::random(OsRng);
        let b_commitment = b_poly.commit(self.host_generators, b_blinding);

        let b_folded: CommittedPolynomial<_, C> = CommittedPolynomial {
            poly: b_poly,
            _blind: b_blinding,
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

        let _s: CommittedPolynomial<_, C> = CommittedPolynomial {
            poly: s_polynomial,
            _blind: s_blinding,
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

        let mut intermediate_evals = Vec::with_capacity(23);

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

        let intermediate_evals_array: [Fp; 23] = intermediate_evals
            .try_into()
            .expect("intermediate_evals should have exactly 23 elements");

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

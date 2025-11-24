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
    composition::b_stage::EphemeralStageB,
    mesh::{Mesh, MeshBuilder, omega_j},
    polynomials::{Rank, structured, unstructured},
    staging::StageExt,
};
use ragu_core::{
    Error, Result,
    drivers::emulator::{Emulator, Wireless},
    maybe::{Always, Maybe, MaybeKind},
};
use ragu_pasta::PoseidonFp;
use ragu_primitives::{GadgetExt, Point, Sponge};
use rand::{Rng, rngs::OsRng};

use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::{any::TypeId, marker::PhantomData};

use crate::proof::{
    AccumulatorInstance, AccumulatorWitness, ChallengePoint, CommittedPolynomial,
    CommittedStructured, EvaluationPoint,
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
            _poly: rx_poly.clone(),
            _blind: blinding,
            commitment,
        });

        // Append the previous accumulator A polynomials.
        a_polys.push(CommittedPolynomial {
            _poly: left.proof.witness.a_poly.clone(),
            _blind: left.proof.witness.a_blinding,
            commitment: left.proof.instance.a,
        });
        a_polys.push(CommittedPolynomial {
            _poly: right.proof.witness.a_poly.clone(),
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

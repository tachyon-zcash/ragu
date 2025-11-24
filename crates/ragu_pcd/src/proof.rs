use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::{
    CircuitExt, CircuitObject,
    mesh::Mesh,
    polynomials::{Rank, structured, unstructured},
};

use alloc::boxed::Box;
use alloc::{vec, vec::Vec};
use core::marker::PhantomData;
use rand::Rng;

use super::{
    circuits::{DUMMY_CIRCUIT_ID, dummy::Dummy, internal_circuit_index},
    header::Header,
};

pub fn trivial<C: Cycle, R: Rank, const HEADER_SIZE: usize>(
    num_application_steps: usize,
    mesh: &Mesh<'_, C::CircuitField, R>,
    host_generators: &C::HostGenerators,
) -> Proof<C, R> {
    let rx = Dummy.rx((), mesh.get_key()).expect("should not fail").0;

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

    let s_poly = mesh.xy(x, y);
    let s_blinding = C::CircuitField::ONE;

    // Zero evaluations (consistent with zero polynomials).
    let u = C::CircuitField::ZERO;
    let v = C::CircuitField::ZERO;

    let c = a_poly.revdot(&b_poly);

    let s_commitment = s_poly.commit(host_generators, s_blinding);
    let a_commitment = a_poly.commit(host_generators, a_blinding);
    let b_commitment = b_poly.commit(host_generators, b_blinding);
    let p_commitment = p_poly.commit(host_generators, p_blinding);

    Proof {
        rx,
        circuit_id: internal_circuit_index(num_application_steps, DUMMY_CIRCUIT_ID),
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

pub fn random<C: Cycle, R: Rank, RNG: Rng, const HEADER_SIZE: usize>(
    num_application_steps: usize,
    mesh: &Mesh<'_, C::CircuitField, R>,
    host_generators: &C::HostGenerators,
    rng: &mut RNG,
) -> Proof<C, R> {
    let rx = Dummy.rx((), mesh.get_key()).expect("should not fail").0;

    let a_poly = structured::Polynomial::<C::CircuitField, R>::random(&mut *rng);
    let a_blinding = C::CircuitField::random(&mut *rng);

    let b_poly = structured::Polynomial::<C::CircuitField, R>::random(&mut *rng);
    let b_blinding = C::CircuitField::random(&mut *rng);

    let p_poly = unstructured::Polynomial::<C::CircuitField, R>::random(&mut *rng);
    let p_blinding = C::CircuitField::random(&mut *rng);

    let x = C::CircuitField::random(&mut *rng);
    let y = C::CircuitField::random(&mut *rng);

    let s_poly = mesh.xy(x, y);
    let s_blinding = C::CircuitField::random(&mut *rng);

    let u = C::CircuitField::random(&mut *rng);
    let v = p_poly.eval(u);
    let c = a_poly.revdot(&b_poly);

    let s_commitment = s_poly.commit(host_generators, s_blinding);
    let a_commitment = a_poly.commit(host_generators, a_blinding);
    let b_commitment = b_poly.commit(host_generators, b_blinding);
    let p_commitment = p_poly.commit(host_generators, p_blinding);

    Proof {
        rx,
        circuit_id: internal_circuit_index(num_application_steps, DUMMY_CIRCUIT_ID),
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

/// Represents a recursive proof for the correctness of some computation.
pub struct Proof<C: Cycle, R: Rank> {
    pub(crate) circuit_id: usize,
    pub(crate) left_header: Vec<C::CircuitField>,
    pub(crate) right_header: Vec<C::CircuitField>,
    pub(crate) rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) _marker: PhantomData<(C, R)>,

    // Split-accumulation witness.
    pub(crate) witness: AccumulatorWitness<C, R>,

    // Split-accumulation instance.
    pub(crate) instance: AccumulatorInstance<C>,

    // Endoscalar points to be processed in this curve in the cycle (native curve).
    pub(crate) endoscalars: Vec<C::HostCurve>,

    // Deferred points to be processed in the next curve in the cycle (nested curve).
    pub(crate) deferreds: Vec<C::NestedCurve>,

    /// Staged circuits created in round.
    pub staged_circuits: Vec<StagedCircuitData<C, R>>,
}

/// Data for a staged circuit that needs consistency verification.
pub struct StagedCircuitData<C: Cycle, R: Rank> {
    /// The final r(X) polynomial from the staged circuit.
    pub(crate) final_rx: structured::Polynomial<C::CircuitField, R>,

    /// The circuit ID (omega value) for mesh lookups.
    pub(crate) circuit_id: C::CircuitField,

    /// The ky polynomial (public inputs).
    pub(crate) ky: Vec<C::CircuitField>,

    /// The circuit object for computing s(X, y).
    pub circuit: Box<dyn CircuitObject<C::CircuitField, R>>,
}

impl<C: Cycle, R: Rank> Clone for Proof<C, R> {
    fn clone(&self) -> Self {
        Proof {
            circuit_id: self.circuit_id,
            left_header: self.left_header.clone(),
            right_header: self.right_header.clone(),
            rx: self.rx.clone(),
            _marker: PhantomData,
            witness: AccumulatorWitness {
                s_poly: self.witness.s_poly.clone(),
                s_blinding: self.witness.s_blinding,
                a_poly: self.witness.a_poly.clone(),
                a_blinding: self.witness.a_blinding,
                b_poly: self.witness.b_poly.clone(),
                b_blinding: self.witness.b_blinding,
                p_poly: self.witness.p_poly.clone(),
                p_blinding: self.witness.p_blinding,
            },
            instance: AccumulatorInstance {
                a: self.instance.a,
                b: self.instance.b,
                c: self.instance.c,
                p: self.instance.p,
                u: ChallengePoint(self.instance.u.0),
                v: EvaluationPoint(self.instance.v.0),
                s: self.instance.s,
                x: ChallengePoint(self.instance.x.0),
                y: ChallengePoint(self.instance.y.0),
            },
            endoscalars: self.endoscalars.clone(),
            deferreds: self.deferreds.clone(),
            staged_circuits: Vec::new(),
        }
    }
}

impl<C: Cycle, R: Rank> Proof<C, R> {
    /// Augment a recursive proof with some data, described by a [`Header`].
    pub fn carry<H: Header<C::CircuitField>>(self, data: H::Data<'_>) -> Pcd<'_, C, R, H> {
        Pcd { proof: self, data }
    }
}

/// Split-Accumulation private witness (prover's working structure).
#[derive(Debug)]
pub(crate) struct AccumulatorWitness<C: Cycle, R: Rank> {
    pub(crate) s_poly: unstructured::Polynomial<C::CircuitField, R>,
    pub(crate) s_blinding: C::CircuitField,

    pub(crate) a_poly: structured::Polynomial<C::CircuitField, R>,
    pub(crate) a_blinding: C::CircuitField,

    pub(crate) b_poly: structured::Polynomial<C::CircuitField, R>,
    pub(crate) b_blinding: C::CircuitField,

    pub(crate) p_poly: unstructured::Polynomial<C::CircuitField, R>,
    pub(crate) p_blinding: C::CircuitField,
}

/// Split-Accumulation public instance.
#[derive(Debug)]
pub struct AccumulatorInstance<C: Cycle> {
    // Structured commitments & revdot claim.
    pub a: C::HostCurve,
    pub b: C::HostCurve,
    pub c: C::CircuitField,

    // Batching commitment & evaluation claim.
    pub p: C::HostCurve,
    pub u: ChallengePoint<C::CircuitField>,
    pub v: EvaluationPoint<C::CircuitField>,

    // Mesh commitments & challenges.
    pub s: C::HostCurve,
    pub x: ChallengePoint<C::CircuitField>,
    pub y: ChallengePoint<C::CircuitField>,
}

#[derive(Debug)]
pub struct ChallengePoint<F>(pub F);

#[derive(Debug)]
pub struct EvaluationPoint<F>(pub F);

/// Represents proof-carrying data, a recursive proof for the correctness of
/// some accompanying data.
pub struct Pcd<'source, C: Cycle, R: Rank, H: Header<C::CircuitField>> {
    /// The recursive proof for the accompanying data.
    pub proof: Proof<C, R>,

    /// Arbitrary data encoded into a [`Header`].
    pub data: H::Data<'source>,
}

impl<C: Cycle, R: Rank, H: Header<C::CircuitField>> Clone for Pcd<'_, C, R, H> {
    fn clone(&self) -> Self {
        Pcd {
            proof: self.proof.clone(),
            data: self.data.clone(),
        }
    }
}

pub struct CommittedPolynomial<P, C: Cycle> {
    pub _poly: P,
    pub _blind: C::CircuitField,
    pub commitment: C::HostCurve,
}

pub type CommittedStructured<R, C> =
    CommittedPolynomial<structured::Polynomial<<C as Cycle>::CircuitField, R>, C>;
pub type _CommittedUnstructured<R, C> =
    CommittedPolynomial<unstructured::Polynomial<<C as Cycle>::CircuitField, R>, C>;

use arithmetic::Cycle;
use ragu_circuits::{
    mesh::Mesh,
    polynomials::{Rank, structured, unstructured},
};
use rand::thread_rng;

use alloc::vec::Vec;
use core::marker::PhantomData;
use ff::Field;

use super::header::Header;

/// Represents a recursive proof for the correctness of some computation.
pub struct Proof<C: Cycle, R: Rank> {
    pub(crate) _marker: PhantomData<(C, R)>,
    pub(crate) circuit_id: C::CircuitField,

    // Split-accumulation witness polynomials.
    pub(crate) witness: AccumulatorWitness<C, R>,

    // Split-accumulation instance polynomials.
    pub(crate) instance: AccumulatorInstance<C>,

    // Endoscalar points to be processed in this curve in the cycle (native curve).
    pub(crate) endoscalars: Vec<C::HostCurve>,

    // Deferred points to be processed in the next curve in the cycle (nested curve).
    pub(crate) deferreds: Vec<C::NestedCurve>,
}

impl<C: Cycle, R: Rank> Proof<C, R> {
    /// Create a trivial proof with zero accumulator polynomials.
    ///
    /// Uses deterministic blinding factors (ONE) to ensure commitments are never the
    /// identity point while remaining cacheable. This is the base case for PCD accumulation.
    pub fn trivial(mesh: &Mesh<C::CircuitField, R>, generators: &C::HostGenerators) -> Self {
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

        let s_commitment = s_poly.commit(generators, s_blinding);
        let a_commitment = a_poly.commit(generators, a_blinding);
        let b_commitment = b_poly.commit(generators, b_blinding);
        let p_commitment = p_poly.commit(generators, p_blinding);

        Proof {
            _marker: PhantomData,
            circuit_id: C::CircuitField::ZERO,
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
        }
    }

    /// Unlike `trivial()`, this uses random polynomials and random challenge points,
    /// creating a valid but arbitrary accumulator state for testing purposes.
    /// Cannot be cached due to fresh randomness.
    pub fn random(mesh: &Mesh<C::CircuitField, R>, generators: &C::HostGenerators) -> Self {
        let a_poly = structured::Polynomial::<C::CircuitField, R>::random(&mut thread_rng());
        let a_blinding = C::CircuitField::random(&mut thread_rng());

        let b_poly = structured::Polynomial::<C::CircuitField, R>::random(&mut thread_rng());
        let b_blinding = C::CircuitField::random(&mut thread_rng());

        let p_poly = unstructured::Polynomial::<C::CircuitField, R>::random(&mut thread_rng());
        let p_blinding = C::CircuitField::random(&mut thread_rng());

        let x = C::CircuitField::random(&mut thread_rng());
        let y = C::CircuitField::random(&mut thread_rng());

        let s_poly = mesh.xy(x, y);
        let s_blinding = C::CircuitField::random(&mut thread_rng());

        let u = C::CircuitField::random(&mut thread_rng());
        let v = p_poly.eval(u);
        let c = a_poly.revdot(&b_poly);

        let s_commitment = s_poly.commit(generators, s_blinding);
        let a_commitment = a_poly.commit(generators, a_blinding);
        let b_commitment = b_poly.commit(generators, b_blinding);
        let p_commitment = p_poly.commit(generators, p_blinding);

        Proof {
            _marker: PhantomData,
            circuit_id: C::CircuitField::ZERO,
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
        }
    }

    /// Augment a recursive proof with some data, described by a [`Header`].
    pub fn carry<H: Header<C::CircuitField>>(self, data: H::Data<'_>) -> Pcd<'_, C, R, H> {
        Pcd { proof: self, data }
    }
}

/// Represents proof-carrying data, a recursive proof for the correctness of
/// some accompanying data.
pub struct Pcd<'source, C: Cycle, R: Rank, H: Header<C::CircuitField>> {
    /// The recursive proof for the accompanying data.
    pub proof: Proof<C, R>,

    /// Arbitrary data encoded into a [`Header`].
    pub data: H::Data<'source>,
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

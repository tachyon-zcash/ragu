use crate::deferreds::DeferredWork;
use arithmetic::CurveAffine;
use arithmetic::FixedGenerators;
use ff::Field;
use ragu_circuits::{
    mesh::Mesh,
    polynomials::{Rank, structured, unstructured},
};
use ragu_core::Error;
use rand::thread_rng;
use std::marker::PhantomData;

/// The accumulator represents the state of a PCD proof at any point in the recursion.
///
/// Conceptually, it models state machine semantics: it's seeded with a base case
/// (initial uncompressed accumulator), engages in a recursive process that
/// accumulates prior uncompressed states for efficiency, and eventually applies a
/// decision procedure that compressed the accumulator for bandwidth efficiency.
///
/// At any time 'T', the accumulator's state is represented by an enum operating in either
/// uncompressed or compressed mode. A higher level abstraction that digests the accumulator
/// can then apply a state transition function to either perform another accumulation step
/// (continuing the recursion) or a decision procedure (terminating the recursion process).
#[derive(Clone, Debug)]
pub enum Accumulator<C: CurveAffine, R: Rank> {
    Uncompressed(Box<UncompressedAccumulator<C, R>>),
    Compressed(CompressedAccumulator<C>),
}

/// Uncompressed accumulator with full witness and deferred work.
/// Used during recursive proof composition (cheap to combine).
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct UncompressedAccumulator<C: CurveAffine, R: Rank> {
    pub(crate) witness: AccumulatorWitness<C, R>,
    pub instance: AccumulatorInstance<C>,
    pub public_inputs: Vec<C::Scalar>,
    pub(crate) deferred: DeferredWork<C>,
}

/// Compressed accumulator with succinct IPA openings.
/// Used for final output, transmission, or storage (small but expensive to verify).
#[derive(Clone, Debug)]
pub struct CompressedAccumulator<C: CurveAffine> {
    pub instance: AccumulatorInstance<C>,
    pub(crate) ipa_proof: PhantomData<C>,
    pub circuit_inputs: Vec<Vec<C::Scalar>>,
}

/// Split-Accumulation private witness.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) struct AccumulatorWitness<C: CurveAffine, R: Rank> {
    s_poly: unstructured::Polynomial<C::Scalar, R>,
    s_blinding: C::Scalar,

    a_poly: structured::Polynomial<C::Scalar, R>,
    a_blinding: C::Scalar,

    b_poly: structured::Polynomial<C::Scalar, R>,
    b_blinding: C::Scalar,

    p_poly: unstructured::Polynomial<C::Scalar, R>,
    p_blinding: C::Scalar,
}

/// Split-Accumulation public instance.
#[derive(Clone, Debug)]
pub struct AccumulatorInstance<C: CurveAffine> {
    pub s_commitment: C,
    pub x: ChallengePoint<C::Scalar>,
    pub y: ChallengePoint<C::Scalar>,
    pub a_commitment: C,
    pub b_commitment: C,
    pub c: C::Scalar,
    pub p_commitment: C,
    pub u: ChallengePoint<C::Scalar>,
    pub v: EvaluationPoint<C::Scalar>,
}

impl<C: CurveAffine, R: Rank> Accumulator<C, R> {
    /// Check if this is an uncompressed accumulator.
    pub fn is_uncompressed(&self) -> bool {
        matches!(self, Accumulator::Uncompressed(_))
    }

    /// Check if this is a compressed accumulator.
    pub fn is_compressed(&self) -> bool {
        matches!(self, Accumulator::Compressed(_))
    }

    /// Create a dummy uncompressed accumulator with placeholder values for testing, and base case.
    pub fn base(mesh: &Mesh<C::Scalar, R>, generators: &impl FixedGenerators<C>) -> Self {
        Accumulator::Uncompressed(Box::new(UncompressedAccumulator::base(mesh, generators)))
    }

    /// Generate random uncompressed accumulator for testing.
    pub fn random(mesh: &Mesh<C::Scalar, R>, generators: &impl FixedGenerators<C>) -> Self {
        Accumulator::Uncompressed(Box::new(UncompressedAccumulator::random(mesh, generators)))
    }
}

impl<C: CurveAffine, R: Rank> UncompressedAccumulator<C, R> {
    pub fn base(mesh: &Mesh<C::Scalar, R>, generators: &impl FixedGenerators<C>) -> Self {
        // Zero polynomials with synthetic blinding factors to avoid identity commitments.
        let a_poly = structured::Polynomial::default();
        let a_blinding = C::Scalar::random(&mut thread_rng());

        let b_poly = structured::Polynomial::default();
        let b_blinding = C::Scalar::random(&mut thread_rng());

        let p_poly = unstructured::Polynomial::default();
        let p_blinding = C::Scalar::random(&mut thread_rng());

        // Trivial zero challenge points.
        let x = C::Scalar::ZERO;
        let y = C::Scalar::ZERO;

        let s_poly = mesh.xy(x, y);
        let s_blinding = C::Scalar::random(&mut thread_rng());

        // Zero evaluations (consistent with zero polynomials).
        let u = C::Scalar::ZERO;
        let v = C::Scalar::ZERO;

        let c = a_poly.revdot(&b_poly);

        let s_commitment = s_poly.commit(generators, s_blinding);
        let a_commitment = a_poly.commit(generators, a_blinding);
        let b_commitment = b_poly.commit(generators, b_blinding);
        let p_commitment = p_poly.commit(generators, p_blinding);

        Self {
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
                s_commitment,
                x: ChallengePoint(x),
                y: ChallengePoint(y),
                a_commitment,
                b_commitment,
                c,
                p_commitment,
                u: ChallengePoint(u),
                v: EvaluationPoint(v),
            },
            deferred: DeferredWork::empty(),
            public_inputs: vec![],
        }
    }

    pub fn random(mesh: &Mesh<C::Scalar, R>, generators: &impl FixedGenerators<C>) -> Self {
        let a_poly = structured::Polynomial::<C::Scalar, R>::random(&mut thread_rng());
        let a_blinding = C::Scalar::random(&mut thread_rng());

        let b_poly = structured::Polynomial::<C::Scalar, R>::random(&mut thread_rng());
        let b_blinding = C::Scalar::random(&mut thread_rng());

        let p_poly = unstructured::Polynomial::<C::Scalar, R>::random(&mut thread_rng());
        let p_blinding = C::Scalar::random(&mut thread_rng());

        let x = C::Scalar::random(&mut thread_rng());
        let y = C::Scalar::random(&mut thread_rng());

        let s_poly = mesh.xy(x, y);
        let s_blinding = C::Scalar::random(&mut thread_rng());

        let u = C::Scalar::random(&mut thread_rng());
        let v = p_poly.eval(u);
        let c = a_poly.revdot(&b_poly);

        let s_commitment = s_poly.commit(generators, s_blinding);
        let a_commitment = a_poly.commit(generators, a_blinding);
        let b_commitment = b_poly.commit(generators, b_blinding);
        let p_commitment = p_poly.commit(generators, p_blinding);

        // Deferreds.
        let deferred = DeferredWork::random(1);

        Self {
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
                s_commitment,
                x: ChallengePoint(x),
                y: ChallengePoint(y),
                a_commitment,
                b_commitment,
                c,
                p_commitment,
                u: ChallengePoint(u),
                v: EvaluationPoint(v),
            },
            deferred,
            public_inputs: vec![],
        }
    }

    // TODO: Synergetic with https://github.com/ebfull/ragu/issues/5, we'll eventually introduce
    // accumulator-specific structural checks *somewhere* within the control flow. For instance,
    // verifying that all points lie on the curve and belong to the correct subgroup.

    // TODO: Add mininmal set of accessors and mutators, but this will be informed by real
    // call-site usage as the implementation is flushed out.
}

/// The circuit public inputs represent the canonical encoding of an `AccumulatorInstance`.
///
/// The instance is the formal description of the verifier-enforced portion of a statement,
/// and the public inputs effectively encode this instance. In other words, the public inputs
/// are the serialized form that verifiers use to check proofs without needing the full witness.
///
/// Serialization and deserialization are fallible conversions.
///
/// TODO: https://github.com/ebfull/ragu/issues/24.
impl<C: CurveAffine> AccumulatorInstance<C> {
    pub fn to_public_inputs(&self) -> Result<Vec<C::Scalar>, Error> {
        todo!()
    }

    pub fn from_public_inputs(_inputs: &[C::Scalar]) -> Result<Self, Error> {
        todo!()
    }
}

impl<C: CurveAffine> TryFrom<&[C::Scalar]> for AccumulatorInstance<C> {
    type Error = Error;
    fn try_from(inputs: &[C::Scalar]) -> Result<Self, Self::Error> {
        Self::from_public_inputs(inputs)
    }
}

impl<C: CurveAffine> TryFrom<Vec<C::Scalar>> for AccumulatorInstance<C> {
    type Error = Error;
    fn try_from(inputs: Vec<C::Scalar>) -> Result<Self, Self::Error> {
        Self::from_public_inputs(&inputs)
    }
}

#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub struct ChallengePoint<F>(pub F);

#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub struct EvaluationPoint<F>(pub F);

#[cfg(test)]
mod tests {
    use super::*;
    use arithmetic::Cycle;
    use ragu_circuits::polynomials::R;
    use ragu_pasta::{EqAffine, Pasta};

    #[test]
    fn test_accumulator_construction() {
        type TestRank = R<10>;
        let pasta = Pasta::default();
        let generators = pasta.host_generators();
        let mesh = Mesh::<pasta_curves::Fp, TestRank>::new(3);

        // Test base case construction
        let base = Accumulator::<EqAffine, TestRank>::base(&mesh, generators);
        match base {
            Accumulator::Uncompressed(acc) => {
                assert_ne!(acc.witness.s_blinding, pasta_curves::Fp::ZERO);
                assert_ne!(acc.witness.a_blinding, pasta_curves::Fp::ZERO);
                assert_ne!(acc.witness.b_blinding, pasta_curves::Fp::ZERO);
                assert_ne!(acc.witness.p_blinding, pasta_curves::Fp::ZERO);

                assert!(acc.deferred.is_empty());

                assert!(acc.public_inputs.is_empty());
            }
            _ => panic!("Expected uncompressed accumulator"),
        }
    }
}

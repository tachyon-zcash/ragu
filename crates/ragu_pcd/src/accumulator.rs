use arithmetic::CurveAffine;
use arithmetic::FixedGenerators;
use core::marker::PhantomData;
use ff::Field;
use ragu_circuits::{
    mesh::Mesh,
    polynomials::{Rank, structured, unstructured},
};
use ragu_core::Error;
use rand::thread_rng;

/// Accumulator for one side of the cycle, parameterized by the two curve types.
///
/// Conceptually, it models state machine semantics: it's seeded with a base case
/// (initial uncompressed accumulator), engages in a recursive process that
/// accumulates prior uncompressed states for efficiency, and can eventually apply a
/// decision procedure that compresses the accumulator for bandwidth efficiency.
///
/// At any time 'T', the accumulator's state is represented by an enum operating in either
/// uncompressed or compressed mode. A higher level abstraction that digests the accumulator
/// can then apply a state transition function to either perform another accumulation step
/// (continuing the recursion) or a decision procedure (terminating the recursion process).
pub struct CycleAccumulator<HostCurve, NestedCurve, R>
where
    HostCurve: CurveAffine,
    NestedCurve: CurveAffine,
    R: Rank,
{
    pub accumulator: UncompressedAccumulator<HostCurve, R>,

    /// Points we want to endoscale this round (native to the circuit).
    pub endoscalars: Vec<NestedCurve>,

    /// New non-native points produced this round (to be deferred).
    pub deferreds: Vec<HostCurve>,

    /// Staging polynomial commitments.
    pub staging: Vec<HostCurve>,
}

/// Uncompressed accumulator with full witness and deferred work.
#[derive(Clone, Debug)]
pub struct UncompressedAccumulator<C: CurveAffine, R: Rank> {
    /// Split-accumulation polynomials (s, a, b, p).
    pub witness: AccumulatorWitness<C, R>,

    /// Instance data (commitments, challenges, evaluations).
    pub instance: AccumulatorInstance<C>,
    // TODO: add `AccumulatorState` for rerandomization tracking.
}

/// Compressed accumulator with succinct IPA openings.
/// Used for final output, transmission, or storage (small but expensive to verify).
#[derive(Clone, Debug)]
pub struct CompressedAccumulator<C: CurveAffine> {
    pub instance: AccumulatorInstance<C>,
    ipa_proof: PhantomData<C>,
    pub circuit_inputs: Vec<Vec<C::Scalar>>,
}

/// Split-Accumulation private witness.
#[derive(Clone, Debug)]
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
    // Structured polynomials
    pub a: C,
    pub b: C,
    pub c: C::Scalar,

    // Unstructured polynomial (batches evaluation checks)
    pub p: C,
    pub u: ChallengePoint<C::Scalar>,
    pub v: EvaluationPoint<C::Scalar>,

    // Mesh polynomial
    pub s: C,
    pub x: ChallengePoint<C::Scalar>,
    pub y: ChallengePoint<C::Scalar>,
}

impl<HostCurve, NestedCurve, R> CycleAccumulator<HostCurve, NestedCurve, R>
where
    HostCurve: CurveAffine,
    NestedCurve: CurveAffine,
    R: Rank,
{
    /// Create a base CycleAccumulator with empty deferred work
    pub fn base(
        mesh: &Mesh<HostCurve::Scalar, R>,
        generators: &impl FixedGenerators<HostCurve>,
    ) -> Self {
        Self {
            accumulator: UncompressedAccumulator::base(mesh, generators),
            endoscalars: Vec::new(),
            deferreds: Vec::new(),
            staging: Vec::new(),
        }
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
    use ragu_circuits::{mesh::MeshBuilder, polynomials::R};
    use ragu_pasta::{EqAffine, Fp, Pasta};

    #[test]
    fn test_accumulator_construction() {
        type TestRank = R<10>;
        let pasta = Pasta::default();
        let generators = pasta.host_generators();
        let mesh: Mesh<'_, Fp, R<10>> = MeshBuilder::<Fp, TestRank>::new()
            .finalize()
            .expect("finalize mesh");

        let base = CycleAccumulator::<EqAffine, EqAffine, TestRank>::base(&mesh, generators);

        assert_ne!(base.accumulator.witness.s_blinding, Fp::ZERO);
        assert_ne!(base.accumulator.witness.a_blinding, Fp::ZERO);
        assert_ne!(base.accumulator.witness.b_blinding, Fp::ZERO);
        assert_ne!(base.accumulator.witness.p_blinding, Fp::ZERO);
        assert!(base.endoscalars.is_empty());
        assert!(base.deferreds.is_empty());
        assert!(base.staging.is_empty());
    }
}

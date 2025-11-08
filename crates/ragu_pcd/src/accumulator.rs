use arithmetic::CurveAffine;
use arithmetic::FixedGenerators;
use core::marker::PhantomData;
use ff::Field;
use ragu_circuits::CircuitObject;
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
pub struct Accumulator<HostCurve, NestedCurve, R>
where
    HostCurve: CurveAffine,
    NestedCurve: CurveAffine,
    R: Rank,
{
    /// Uncompressed accumulator object.
    pub accumulator: UncompressedAccumulator<HostCurve, R>,

    /// Points we want to endoscale this round (native to the circuit).
    pub endoscalars: Vec<HostCurve>,

    /// New non-native points produced this round (to be deferred).
    pub deferreds: Vec<NestedCurve>,

    /// Staged circuits created in round.
    pub staged_circuits: Vec<StagedCircuitData<HostCurve, R>>,
}

/// Data for a staged circuit that needs consistency verification.
pub struct StagedCircuitData<C: CurveAffine, R: Rank> {
    /// The final r(X) polynomial from the staged circuit.
    pub(crate) final_rx: structured::Polynomial<C::ScalarExt, R>,

    /// The ky polynomial (public inputs).
    pub(crate) ky: Vec<C::ScalarExt>,

    /// The circuit object for computing s(X, y).
    pub circuit: Box<dyn CircuitObject<C::ScalarExt, R>>,
}

/// Uncompressed accumulator with full witness and deferred work.
#[derive(Clone, Debug)]
pub struct UncompressedAccumulator<C: CurveAffine, R: Rank> {
    /// Split-accumulation polynomials (s, a, b, p).
    pub(crate) witness: AccumulatorWitness<C, R>,

    /// Instance data (commitments, challenges, evaluations).
    pub(crate) instance: AccumulatorInstance<C>,
}

/// Compressed accumulator with succinct IPA openings.
/// Used for final output, transmission, or storage (small but expensive to verify).
#[derive(Clone, Debug)]
pub struct CompressedAccumulator<C: CurveAffine> {
    pub instance: AccumulatorInstance<C>,
    ipa_proof: PhantomData<C>,
    pub circuit_inputs: Vec<Vec<C::ScalarExt>>,
}

/// Split-Accumulation private witness (prover's working structure).
#[derive(Clone, Debug)]
pub(crate) struct AccumulatorWitness<C: CurveAffine, R: Rank> {
    pub(crate) s_poly: unstructured::Polynomial<C::ScalarExt, R>,
    pub(crate) s_blinding: C::ScalarExt,

    pub(crate) a_poly: structured::Polynomial<C::ScalarExt, R>,
    pub(crate) a_blinding: C::ScalarExt,

    pub(crate) b_poly: structured::Polynomial<C::ScalarExt, R>,
    pub(crate) b_blinding: C::ScalarExt,

    pub(crate) p_poly: unstructured::Polynomial<C::ScalarExt, R>,
    pub(crate) p_blinding: C::ScalarExt,
}

/// Split-Accumulation public instance.
#[derive(Clone, Debug)]
pub struct AccumulatorInstance<C: CurveAffine> {
    // Structured commitments & revdot claim.
    pub a: C,
    pub b: C,
    pub c: C::ScalarExt,

    // Batching commitment & evaluation claim.
    pub p: C,
    pub u: ChallengePoint<C::ScalarExt>,
    pub v: EvaluationPoint<C::ScalarExt>,

    // Mesh commitments & challenges.
    pub s: C,
    pub x: ChallengePoint<C::ScalarExt>,
    pub y: ChallengePoint<C::ScalarExt>,
}

impl<C: CurveAffine, R: Rank> StagedCircuitData<C, R> {
    pub fn new(
        final_rx: structured::Polynomial<C::ScalarExt, R>,
        ky: Vec<C::ScalarExt>,
        circuit: Box<dyn CircuitObject<C::ScalarExt, R>>,
    ) -> Self {
        Self {
            final_rx,
            ky,
            circuit,
        }
    }
}

impl<HostCurve, NestedCurve, R> Accumulator<HostCurve, NestedCurve, R>
where
    HostCurve: CurveAffine,
    NestedCurve: CurveAffine,
    R: Rank,
{
    /// Create a base accumulator with empty deferred work
    pub fn base(
        mesh: &Mesh<HostCurve::ScalarExt, R>,
        generators: &impl FixedGenerators<HostCurve>,
    ) -> Self {
        Self {
            accumulator: UncompressedAccumulator::base(mesh, generators),
            endoscalars: Vec::new(),
            deferreds: Vec::new(),
            staged_circuits: Vec::new(),
        }
    }
}

impl<C: CurveAffine, R: Rank> UncompressedAccumulator<C, R> {
    pub fn base(mesh: &Mesh<C::ScalarExt, R>, generators: &impl FixedGenerators<C>) -> Self {
        // Zero polynomials with synthetic blinding factors to avoid identity commitments.
        let a_poly = structured::Polynomial::default();
        let a_blinding = C::ScalarExt::random(&mut thread_rng());

        let b_poly = structured::Polynomial::default();
        let b_blinding = C::ScalarExt::random(&mut thread_rng());

        let p_poly = unstructured::Polynomial::default();
        let p_blinding = C::ScalarExt::random(&mut thread_rng());

        // Trivial zero challenge points.
        let x = C::ScalarExt::ZERO;
        let y = C::ScalarExt::ZERO;

        let s_poly = mesh.xy(x, y);
        let s_blinding = C::ScalarExt::random(&mut thread_rng());

        // Zero evaluations (consistent with zero polynomials).
        let u = C::ScalarExt::ZERO;
        let v = C::ScalarExt::ZERO;

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

    pub fn random(mesh: &Mesh<C::ScalarExt, R>, generators: &impl FixedGenerators<C>) -> Self {
        let a_poly = structured::Polynomial::<C::ScalarExt, R>::random(&mut thread_rng());
        let a_blinding = C::ScalarExt::random(&mut thread_rng());

        let b_poly = structured::Polynomial::<C::ScalarExt, R>::random(&mut thread_rng());
        let b_blinding = C::ScalarExt::random(&mut thread_rng());

        let p_poly = unstructured::Polynomial::<C::ScalarExt, R>::random(&mut thread_rng());
        let p_blinding = C::ScalarExt::random(&mut thread_rng());

        let x = C::ScalarExt::random(&mut thread_rng());
        let y = C::ScalarExt::random(&mut thread_rng());

        let s_poly = mesh.xy(x, y);
        let s_blinding = C::ScalarExt::random(&mut thread_rng());

        let u = C::ScalarExt::random(&mut thread_rng());
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

impl<C: CurveAffine, R: Rank> AccumulatorWitness<C, R> {
    pub fn base() -> Self {
        // Zero polynomials with synthetic blinding factors to avoid identity commitments.
        let a_poly = structured::Polynomial::default();
        let a_blinding = C::ScalarExt::random(&mut thread_rng());

        let b_poly = structured::Polynomial::default();
        let b_blinding = C::ScalarExt::random(&mut thread_rng());

        let p_poly = unstructured::Polynomial::default();
        let p_blinding = C::ScalarExt::random(&mut thread_rng());

        let s_poly = unstructured::Polynomial::default();
        let s_blinding = C::ScalarExt::random(&mut thread_rng());

        AccumulatorWitness {
            s_poly,
            s_blinding,
            a_poly,
            a_blinding,
            b_poly,
            b_blinding,
            p_poly,
            p_blinding,
        }
    }
}

impl<C: CurveAffine, R: Rank> Default for AccumulatorWitness<C, R> {
    fn default() -> Self {
        Self::base()
    }
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
    pub fn to_public_inputs(&self) -> Result<Vec<C::ScalarExt>, Error> {
        todo!()
    }

    pub fn from_public_inputs(_inputs: &[C::ScalarExt]) -> Result<Self, Error> {
        todo!()
    }
}

impl<C: CurveAffine> TryFrom<&[C::ScalarExt]> for AccumulatorInstance<C> {
    type Error = Error;
    fn try_from(inputs: &[C::ScalarExt]) -> Result<Self, Self::Error> {
        Self::from_public_inputs(inputs)
    }
}

impl<C: CurveAffine> TryFrom<Vec<C::ScalarExt>> for AccumulatorInstance<C> {
    type Error = Error;
    fn try_from(inputs: Vec<C::ScalarExt>) -> Result<Self, Self::Error> {
        Self::from_public_inputs(&inputs)
    }
}

#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub struct ChallengePoint<F>(pub F);

#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub struct EvaluationPoint<F>(pub F);

/// Polynomial evaluatons at the final batching challenge point u.
pub struct FinalEvaluations<C: CurveAffine> {
    pub(crate) a: C::ScalarExt,
    pub(crate) b: C::ScalarExt,
    pub(crate) acc1_p: C::ScalarExt,
    pub(crate) acc2_p: C::ScalarExt,
    pub(crate) acc1_s: C::ScalarExt,
    pub(crate) acc2_s: C::ScalarExt,
    pub(crate) s: C::ScalarExt,
    pub(crate) s1: [C::ScalarExt; 2],
    pub(crate) s2: C::ScalarExt,
}

/// Cross polynomial evaluations at fiat-shamir challenges (w, x, y).
pub struct ConsistencyEvaluations<C: CurveAffine> {
    pub(crate) acc1_s_at_w: C::ScalarExt,
    pub(crate) acc2_s_at_w: C::ScalarExt,
    pub(crate) s1_acc1_at_y: C::ScalarExt,
    pub(crate) s1_acc2_at_y: C::ScalarExt,
    pub(crate) s2_at_x: C::ScalarExt,
}

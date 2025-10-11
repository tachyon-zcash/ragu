use arithmetic::CurveAffine;
use ff::Field;
use pasta_curves::group::Curve;
use rand::thread_rng;

/// Deferred work to be verified in the next recursion step (elliptic-curve and
/// field operations on the counterpart curve).
///
/// The accumulator state will obviously have layered complexity in the form of
/// deferreds to handle non-native field arithmetic. Deffereds represent expensive
/// verification checks that we defer to the next uncompressed recursion step in the
/// curve cycle by passing them forward as part of the accumulator state. The claimed
/// values are witnessed in the subsequent step, and verified in-circuit using cheap
/// equality constraints. We concretely model this two-phase alternating pattern:
///
/// * Step N (on Pallas): verify the previous accumulators (checking polynomial
///   relations), fold new circuits, return new accumulator and deffered work (Vesta),
/// * Step N + 1 (on Vesta): process deffered work and their claimed evaluations,
///   verify previous accumulators, fold new circuits, return new accumulator and deferred
///   work (Pallas).
///
/// The accumulator should contain a deferred structure embedding to represent this, capturing
/// a kind of operational state (not sure what a good name for this is, since it's neither a
/// witness nor an instance).
#[derive(Clone, Debug)]
pub struct DeferredWork<C: CurveAffine> {
    pub scalar_muls: Vec<DeferredScalarMul<C>>,
    pub inner_products: Vec<DeferredInnerProduct<C>>,
    pub poly_evals: Vec<DeferredPolyEval<C>>,
    pub hash_to_fields: Vec<DeferredTranscriptChallenge<C::Scalar>>,
}

#[derive(Clone, Debug)]
pub struct DeferredScalarMul<C: CurveAffine> {
    pub base: C,
    pub scalar: C::Scalar,
    pub result: C,
}

#[derive(Clone, Debug)]
pub struct DeferredInnerProduct<C: CurveAffine> {
    pub lhs: Vec<C::Scalar>,
    pub rhs: Vec<C::Scalar>,
    pub result: C::Scalar,
}

#[derive(Clone, Debug)]
pub struct DeferredPolyEval<C: CurveAffine> {
    pub poly_coeffs: Vec<C::Scalar>,
    pub point: C::Scalar,
    pub evaluation: C::Scalar,
}

#[derive(Clone, Debug)]
pub struct DeferredTranscriptChallenge<F> {
    pub transcript_data: Vec<u8>,
    pub challenge: F,
}

impl<C: CurveAffine> DeferredWork<C> {
    /// NOTE: For seeding random deferreds for testing purposes only.
    pub fn random(count: usize) -> Self {
        Self {
            scalar_muls: Self::random_scalar_mul(count),
            inner_products: Self::random_inner_product(count),
            poly_evals: Self::random_polynomial_evaluation(count),
            hash_to_fields: Self::random_transcript_challenge(count),
        }
    }

    pub fn random_scalar_mul(count: usize) -> Vec<DeferredScalarMul<C>> {
        (0..count)
            .map(|_| {
                let base = C::generator();
                let scalar = C::Scalar::random(&mut thread_rng());
                let result = (base * scalar).to_affine();

                DeferredScalarMul {
                    base,
                    scalar,
                    result,
                }
            })
            .collect()
    }

    pub fn random_inner_product(count: usize) -> Vec<DeferredInnerProduct<C>> {
        (0..count)
            .map(|_| {
                let lhs = vec![C::Scalar::random(&mut thread_rng())];
                let rhs = vec![C::Scalar::random(&mut thread_rng())];
                let result = lhs
                    .iter()
                    .zip(rhs.iter())
                    .map(|(l, r)| *l * *r)
                    .fold(C::Scalar::ZERO, |acc, x| acc + x);

                DeferredInnerProduct { lhs, rhs, result }
            })
            .collect()
    }

    pub fn random_polynomial_evaluation(count: usize) -> Vec<DeferredPolyEval<C>> {
        (0..count)
            .map(|_| {
                let poly_coeffs = vec![C::Scalar::random(&mut thread_rng())];
                let point = C::Scalar::random(&mut thread_rng());

                // NOTE: This implementation is not constant-time and is therefore susceptible to timing attacks.
                // In production, replace it with a constant-time, optimized Horner’s method.
                let evaluation = poly_coeffs
                    .iter()
                    .enumerate()
                    .fold(C::Scalar::ZERO, |acc, (i, &coeff)| {
                        acc + coeff * point.pow([i as u64])
                    });

                DeferredPolyEval {
                    poly_coeffs,
                    point,
                    evaluation,
                }
            })
            .collect()
    }

    pub fn random_transcript_challenge(
        count: usize,
    ) -> Vec<DeferredTranscriptChallenge<C::Scalar>> {
        (0..count)
            .map(|_| {
                let transcript_data: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
                let hash_challenge = C::Scalar::random(&mut thread_rng());

                DeferredTranscriptChallenge {
                    transcript_data,
                    challenge: hash_challenge,
                }
            })
            .collect()
    }
}

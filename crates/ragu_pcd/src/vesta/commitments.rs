//! Holds interstitial information for structured and unstructured polynomials.

use arithmetic::CurveAffine;
use ragu_circuits::polynomials::{structured, unstructured};

pub struct CommittedPolynomial<P, C: CurveAffine> {
    pub poly: P,
    pub blind: C::Scalar,
    pub commitment: C,
}

pub type CommittedStructured<R, C> =
    CommittedPolynomial<structured::Polynomial<<C as CurveAffine>::ScalarExt, R>, C>;
pub type CommittedUnstructured<R, C> =
    CommittedPolynomial<unstructured::Polynomial<<C as CurveAffine>::ScalarExt, R>, C>;

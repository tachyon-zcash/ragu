//! Holds interstitial information for structured and unstructured polynomials.

use arithmetic::CurveAffine;
use ragu_circuits::polynomials::{Rank, structured, unstructured};

pub struct A<C: CurveAffine, R: Rank> {
    pub(crate) poly: structured::Polynomial<C::Scalar, R>,
    pub(crate) blinding: C::Scalar,
    pub(crate) commitment: C,
}

pub struct B<C: CurveAffine, R: Rank> {
    pub(crate) poly: structured::Polynomial<C::Scalar, R>,
    pub(crate) blinding: C::Scalar,
    pub(crate) commitment: C,
}

pub struct SPrime<C: CurveAffine, R: Rank> {
    pub(crate) poly: unstructured::Polynomial<C::Scalar, R>,
    pub(crate) blinding: C::Scalar,
    pub(crate) commitment: C,
}

pub struct SPrimePrime<C: CurveAffine, R: Rank> {
    pub(crate) poly: structured::Polynomial<C::Scalar, R>,
    pub(crate) blinding: C::Scalar,
    pub(crate) commitment: C,
}

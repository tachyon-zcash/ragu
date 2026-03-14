//! Smart-pointer wrappers for committed polynomials.
//!
//! [`CommittedPolynomial`] bundles a polynomial, its blinding factor, and a
//! pre-computed commitment into one immutable type.

use ragu_arithmetic::CurveAffine;

/// A polynomial together with its blinding factor and eagerly-computed
/// commitment.
///
/// The commitment is computed at construction time, so all accessor methods
/// take `&self`.
#[derive(Clone)]
pub struct CommittedPolynomial<P, C: CurveAffine> {
    poly: P,
    blind: C::Scalar,
    commitment: C,
}

impl<P, C: CurveAffine> CommittedPolynomial<P, C> {
    /// Returns the underlying polynomial.
    pub fn poly(&self) -> &P {
        &self.poly
    }

    /// Returns the blinding scalar used at commitment time.
    pub fn blind(&self) -> C::Scalar {
        self.blind
    }

    /// Returns the pre-computed commitment.
    pub fn commitment(&self) -> C {
        self.commitment
    }

    /// Constructs a `CommittedPolynomial` from raw parts **without** verifying
    /// that the commitment is consistent with the polynomial and blind.
    ///
    /// Intended for cases where the commitment is known externally (e.g. from
    /// a proof transcript) or for tests that deliberately craft an inconsistent
    /// triple.
    pub fn from_parts(poly: P, blind: C::Scalar, commitment: C) -> Self {
        Self {
            poly,
            blind,
            commitment,
        }
    }
}

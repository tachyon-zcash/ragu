use ragu_primitives::vec::Len;

pub mod compute_c;

/// Number of error terms.
///
/// C = NUM_REVDOT_CLAIMS polynomials per fold,
/// so error terms = C * (C - 1) off-diagonal terms.
pub struct ErrorTermsLen<const NUM_REVDOT_CLAIMS: usize>;

impl<const NUM_REVDOT_CLAIMS: usize> Len for ErrorTermsLen<NUM_REVDOT_CLAIMS> {
    fn len() -> usize {
        NUM_REVDOT_CLAIMS * (NUM_REVDOT_CLAIMS - 1)
    }
}

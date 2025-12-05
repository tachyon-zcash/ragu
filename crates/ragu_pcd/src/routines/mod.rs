use ragu_primitives::vec::Len;

pub mod compute_c;

/// Represents triple a length determined at compile time.
pub struct TripleConstLen<const N: usize>;

impl<const N: usize> Len for TripleConstLen<N> {
    fn len() -> usize {
        N * 3
    }
}

/// Number of cross-product error terms.
///
/// L = NUM_CIRCUITS polynomials per fold,
/// so cross products = L * (L - 1) off-diagonal terms.
pub struct CrossProductsLen<const NUM_CIRCUITS: usize>;

impl<const NUM_CIRCUITS: usize> Len for CrossProductsLen<NUM_CIRCUITS> {
    fn len() -> usize {
        NUM_CIRCUITS * (NUM_CIRCUITS - 1)
    }
}

/// The length of a single k(Y) polynomial.
///
/// k(Y) is derived from the circuit instance: (output_header, left_header, right_header, 1).
/// Each header has HEADER_SIZE elements, plus one constant term.
pub struct KyPolyLen<const HEADER_SIZE: usize>;

impl<const HEADER_SIZE: usize> Len for KyPolyLen<HEADER_SIZE> {
    fn len() -> usize {
        3 * HEADER_SIZE + 1
    }
}

/// The total length of k(Y) coefficients across all circuits.
///
/// When evaluating multiple circuits, each contributes one k(Y) polynomial
/// of size `3 * HEADER_SIZE + 1`. This is the combined input size.
pub struct TotalKyCoeffsLen<const HEADER_SIZE: usize, const NUM_CIRCUITS: usize>;

impl<const HEADER_SIZE: usize, const NUM_CIRCUITS: usize> Len
    for TotalKyCoeffsLen<HEADER_SIZE, NUM_CIRCUITS>
{
    fn len() -> usize {
        NUM_CIRCUITS * (3 * HEADER_SIZE + 1)
    }
}

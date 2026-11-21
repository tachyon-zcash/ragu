//! IPA proof messages.
use alloc::vec::Vec;

use udon::curve::Affine;
/// Log-size unblinded IPA opening proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpaProof<C: Affine> {
    /// Unblinded commitment to the masking polynomial $s$ with $s(x) = 0$.
    pub s_commitment: C,
    /// Cross-term commitments $(L_j, R_j)$, one pair per round.
    pub rounds: Vec<(C, C)>,
    /// Final collapsed coefficient.
    pub c: C::Scalar,
}

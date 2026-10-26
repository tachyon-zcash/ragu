//! Polynomial-collection fixtures, registered as the four steps of one
//! application; see [`step`] for the two collection types and how a seed and
//! a fuse build them.

pub mod step;

use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::Cycle;
use ragu_core::Result;
use ragu_pcd::{AppHooks, Application, ApplicationBuilder, HANDLE_WIRES};
use udon::field::Field;

use self::step::{ConcatSequences, MergeSets, SeedSequence, SeedSet};

/// The shared header size: a suffix element plus the wider of the two headers,
/// which is the sequence's; the set header is a handle alone and fits inside.
pub const HEADER_SIZE: usize = step::SEQ_HEADER + 1;

/// A fuse derives its challenge from the three handles it witnesses, so the
/// width is what three of them write.
const CHALLENGE_WIDTH: usize = 3 * HANDLE_WIRES;

/// An [`Application`] at the shared layout.
pub type CollectionsApp<'params, C, R> =
    Application<'params, C, R, HEADER_SIZE, AppHooks<3, 3, 1, CHALLENGE_WIDTH>>;

/// All four collection steps registered and finalized.
pub fn collections_app<C: Cycle, R: Rank>(params: &C::Params) -> Result<CollectionsApp<'_, C, R>> {
    ApplicationBuilder::<C, R, HEADER_SIZE, AppHooks<3, 3, 1, CHALLENGE_WIDTH>>::new(params)
        .register(SeedSet::<C, R>::new())?
        .register(SeedSequence::<C, R>::new())?
        .register(MergeSets::<C, R>::new())?
        .register(ConcatSequences::<C, R>::new())?
        .finalize()
}

/// The coefficients, lowest first, of the monic polynomial whose roots are
/// `roots`.
fn poly_with_roots<F: Field>(roots: &[F]) -> Vec<F> {
    let mut coeffs = vec![F::ONE];
    for &root in roots {
        let mut next = vec![F::ZERO; coeffs.len() + 1];
        for (i, &c) in coeffs.iter().enumerate() {
            next[i + 1] += c;
            next[i] -= c * root;
        }
        coeffs = next;
    }
    coeffs
}

/// Writes the product of `a` and `b`, lowest coefficients first, into `out`.
fn poly_mul<F: Field>(a: &[F], b: &[F], out: &mut Vec<F>) {
    out.clear();
    if a.is_empty() || b.is_empty() {
        return;
    }
    out.resize(a.len() + b.len() - 1, F::ZERO);
    for (i, &x) in a.iter().enumerate() {
        for (j, &y) in b.iter().enumerate() {
            out[i + j] += x * y;
        }
    }
}

/// The monic set polynomial `∏ (X − m)` over `members`, multiplicity
/// included; the empty set is the constant `1`.
pub fn set_polynomial<F: Field, R: Rank>(members: &[F]) -> sparse::Polynomial<F, R> {
    sparse::Polynomial::from_coeffs(poly_with_roots(members))
}

/// A polynomial's coefficients with the zero tail dropped.
fn trimmed_coeffs<F: Field, R: Rank>(poly: &sparse::Polynomial<F, R>) -> Vec<F> {
    let mut coeffs: Vec<F> = poly.iter_coeffs().collect();
    while coeffs.last() == Some(&F::ZERO) {
        coeffs.pop();
    }
    coeffs
}

/// The merged polynomial `A·B`, computed with the library's FFT multiply.
pub fn merged_polynomial<F: Field, R: Rank>(
    a: &sparse::Polynomial<F, R>,
    b: &sparse::Polynomial<F, R>,
) -> sparse::Polynomial<F, R> {
    let mut out = Vec::new();
    poly_mul(&trimmed_coeffs(a), &trimmed_coeffs(b), &mut out);
    sparse::Polynomial::from_coeffs(out)
}

/// The sequence polynomial: member `i` is the coefficient of `Xⁱ`, with a
/// monic sentinel coefficient `1` above the last member, so a sequence of
/// `L` members has degree exactly `L`.
pub fn sequence_polynomial<F: Field, R: Rank>(members: &[F]) -> sparse::Polynomial<F, R> {
    let mut coeffs = members.to_vec();
    coeffs.push(F::ONE);
    sparse::Polynomial::from_coeffs(coeffs)
}

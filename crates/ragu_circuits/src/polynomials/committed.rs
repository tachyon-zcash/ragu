//! Smart-pointer wrappers for committed polynomials.
//!
//! [`CommittedPolynomial`] bundles a polynomial, its blinding factor, and a
//! pre-computed commitment into one immutable type.

use ff::Field;
use group::Curve as _;
use ragu_arithmetic::{CurveAffine, FixedGenerators};
use rand::CryptoRng;

/// Trait for types that can produce a Pedersen commitment in projective form.
///
/// Implement this to make a polynomial type usable with [`batch_commit`] and
/// [`batch_commit_with_blinds`].
pub trait Committable<C: CurveAffine> {
    /// Compute a commitment in projective (non-normalized) form.
    fn commit<G: FixedGenerators<C>>(&self, generators: &G, blind: C::ScalarExt) -> C::Curve;
}

/// Commit to `N` polynomials in a single batch, sampling fresh blinding
/// factors from `rng`.
///
/// Performs only one batch inversion for all affine normalizations. Returns an
/// array of [`CommittedPolynomial`]s in the same order as the input array.
pub fn batch_commit<P, G, C, RNG, const N: usize>(
    rng: &mut RNG,
    generators: &G,
    polys: [P; N],
) -> [CommittedPolynomial<P, C>; N]
where
    P: Committable<C>,
    G: FixedGenerators<C>,
    C: CurveAffine,
    RNG: CryptoRng,
{
    let blinds: [C::ScalarExt; N] = core::array::from_fn(|_| C::ScalarExt::random(&mut *rng));
    batch_commit_with_blinds(generators, polys, blinds)
}

/// Commit to `N` polynomials in a single batch using the provided blinding
/// factors.
///
/// Performs only one batch inversion for all affine normalizations. Returns an
/// array of [`CommittedPolynomial`]s in the same order as the input arrays.
pub fn batch_commit_with_blinds<P, G, C, const N: usize>(
    generators: &G,
    polys: [P; N],
    blinds: [C::ScalarExt; N],
) -> [CommittedPolynomial<P, C>; N]
where
    P: Committable<C>,
    G: FixedGenerators<C>,
    C: CurveAffine,
{
    let projectives: [C::Curve; N] =
        core::array::from_fn(|i| polys[i].commit(generators, blinds[i]));

    let mut affines: [C; N] = core::array::from_fn(|_| C::identity());
    C::Curve::batch_normalize(&projectives, &mut affines);

    let mut polys = polys.into_iter();
    let mut blinds = blinds.into_iter();
    let mut affines = affines.into_iter();

    core::array::from_fn(|_| {
        let poly = polys
            .next()
            .expect("iterator over N-element array yields N elements");
        let blind = blinds
            .next()
            .expect("iterator over N-element array yields N elements");
        let commitment = affines
            .next()
            .expect("iterator over N-element array yields N elements");

        CommittedPolynomial::from_parts(poly, blind, commitment)
    })
}

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

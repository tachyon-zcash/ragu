//! Polynomial commitments — mirrors Ragu's polynomial commitment scheme.
//!
//! Real Pedersen crypto on Vesta. Only the proof system is mocked.

use alloc::vec::Vec;
use core::ops::{Add, Mul, Neg};

use ff::Field;
use lazy_static::lazy_static;
use pasta_curves::{Eq, EqAffine, Fp};

const MAX_GENERATORS: usize = 8192;

lazy_static! {
    /// Coefficient generators `g[0..n]`.
    static ref GENERATORS: Vec<EqAffine> = {
        use pasta_curves::{arithmetic::CurveExt as _, group::Curve as _};
        let hasher = Eq::hash_to_curve("mock_ragu:generators");
        (0..MAX_GENERATORS)
            .map(|i| {
                let point = hasher(&i.to_le_bytes());
                point.to_affine()
            })
            .collect()
    };

    /// Blinding generator `h` (unknown discrete log relative to `g`).
    static ref BLINDING_GENERATOR: EqAffine = {
        use pasta_curves::{arithmetic::CurveExt as _, group::Curve as _};
        Eq::hash_to_curve("mock_ragu:blinding")(b"h").to_affine()
    };
}

/// Mirrors `ragu_arithmetic::poly_with_roots`.
#[must_use]
pub fn poly_with_roots(roots: &[Fp]) -> Vec<Fp> {
    let mut coeffs = alloc::vec![Fp::ONE];
    for &root in roots {
        let mut new_coeffs = alloc::vec![Fp::ZERO; coeffs.len() + 1];
        for (i, &c) in coeffs.iter().enumerate() {
            new_coeffs[i + 1] += c;
            new_coeffs[i] += c * root.neg();
        }
        coeffs = new_coeffs;
    }
    coeffs
}

/// Mirrors `ragu_circuits::polynomials::unstructured::Polynomial`.
#[derive(Clone, Debug, Eq)]
pub struct Polynomial(Vec<Fp>);

impl PartialEq for Polynomial {
    fn eq(&self, other: &Self) -> bool {
        self.commit() == other.commit()
    }
}

impl Polynomial {
    #[must_use]
    pub fn from_coeffs(coeffs: &[Fp]) -> Self {
        Self(coeffs.to_vec())
    }

    #[must_use]
    pub fn from_roots(roots: &[Fp]) -> Self {
        Self(poly_with_roots(roots))
    }

    #[must_use]
    pub fn multiply(&self, other: &Self) -> Self {
        let result_len = self.0.len() + other.0.len() - 1;
        let mut result = alloc::vec![Fp::ZERO; result_len];
        for (i, &a) in self.0.iter().enumerate() {
            for (j, &b) in other.0.iter().enumerate() {
                result[i + j] += a * b;
            }
        }
        Self(result)
    }

    #[must_use]
    pub fn coefficients(&self) -> &[Fp] {
        &self.0
    }

    /// Evaluate via Horner's method: `p(x) = c₀ + x(c₁ + x(c₂ + …))`.
    #[must_use]
    pub fn eval(&self, x: Fp) -> Fp {
        self.0.iter().rev().fold(Fp::ZERO, |acc, &c| acc * x + c)
    }

    /// `commit() = ∑ coeffᵢ·gᵢ` -- the unblinded coefficient commitment.
    #[must_use]
    pub fn commit(&self) -> Commitment {
        use pasta_curves::group::{Curve as _, Group as _};

        let generators = &*GENERATORS;
        assert!(
            self.0.len() <= generators.len(),
            "polynomial degree {} exceeds max generators {}",
            self.0.len() - 1,
            generators.len() - 1,
        );

        let mut acc = Eq::identity();
        for (&coeff, &point) in self.0.iter().zip(generators.iter()) {
            acc += Eq::from(point) * coeff;
        }

        Commitment(acc.to_affine())
    }
}

impl Default for Polynomial {
    fn default() -> Self {
        Self(alloc::vec![Fp::ONE])
    }
}

/// A Pedersen vector commitment (EC point on Vesta).
#[derive(Clone, Copy, Debug, Eq)]
pub struct Commitment(EqAffine);

impl PartialEq for Commitment {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Commitment {
    /// The identity (zero) point — the commitment of the empty polynomial.
    #[must_use]
    pub fn identity() -> Self {
        use pasta_curves::group::{Curve as _, Group as _};
        Self(Eq::identity().to_affine())
    }

    #[must_use]
    pub fn inner(&self) -> &EqAffine {
        &self.0
    }
}

impl Add for Commitment {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        use pasta_curves::group::Curve as _;
        Self((Eq::from(self.0) + Eq::from(rhs.0)).to_affine())
    }
}

impl Mul<Fp> for Commitment {
    type Output = Self;

    fn mul(self, rhs: Fp) -> Self {
        use pasta_curves::group::Curve as _;
        Self((Eq::from(self.0) * rhs).to_affine())
    }
}

impl From<Commitment> for [u8; 32] {
    fn from(c: Commitment) -> Self {
        use pasta_curves::group::GroupEncoding as _;
        c.0.to_bytes()
    }
}

impl TryFrom<&[u8; 32]> for Commitment {
    type Error = &'static str;

    fn try_from(bytes: &[u8; 32]) -> core::result::Result<Self, Self::Error> {
        use pasta_curves::group::GroupEncoding as _;
        Option::from(EqAffine::from_bytes(bytes))
            .map(Self)
            .ok_or("invalid curve point")
    }
}

/// Fixed commitment-scheme generators — the mock's stand-in for ragu's
/// `FixedGenerators`. The coefficient generators `gᵢ` (the basis
/// [`Polynomial::commit`](super::Polynomial::commit) commits against) and the
/// blinding generator `h` have unknown discrete-logarithm relationships with one
/// another. Each returns a [`Commitment`] -- the mock's wrapper around a Vesta
/// point -- so callers can combine them with the homomorphic `+` and `*`
/// operators (e.g. blind a commitment as `c + h() * blind`).
pub mod generators {
    use pasta_curves::{Eq, Fp};

    use super::{BLINDING_GENERATOR, Commitment, GENERATORS};

    /// The `i`-th coefficient generator `gᵢ`. A public constant.
    #[must_use]
    pub fn g(i: usize) -> Commitment {
        let generators = &*GENERATORS;
        assert!(
            i < generators.len(),
            "generator index {i} exceeds max generators {}",
            generators.len(),
        );
        Commitment(generators[i])
    }

    /// The blinding generator `h`, with unknown discrete log relative to the
    /// coefficient generators `gᵢ`. Blind a commitment as `c + h() * blind`, or
    /// use [`short_commit`] to commit a single value with blinding.
    #[must_use]
    pub fn h() -> Commitment {
        Commitment(*BLINDING_GENERATOR)
    }

    /// `Σ_{i<len} gᵢ` — the sum of the first `len` coefficient generators.
    ///
    /// A public constant for a fixed `len` (no secret input); the
    /// coefficient-side basis of the homomorphic shift `+ s·Σ gᵢ`, where the
    /// witnessed scalar `s` stays private.
    #[must_use]
    pub fn g_sum(len: usize) -> Commitment {
        use pasta_curves::group::{Curve as _, Group as _};
        let generators = &*GENERATORS;
        assert!(
            len <= generators.len(),
            "length {len} exceeds max generators {}",
            generators.len(),
        );
        let mut acc = Eq::identity();
        for &point in generators.iter().take(len) {
            acc += Eq::from(point);
        }
        Commitment(acc.to_affine())
    }

    /// Commit to a single value with blinding: `g(0)·value + h·blind`. Mirrors
    /// ragu's `FixedGenerators::short_commit`.
    #[must_use]
    pub fn short_commit(value: Fp, blind: Fp) -> Commitment {
        g(0) * value + h() * blind
    }
}

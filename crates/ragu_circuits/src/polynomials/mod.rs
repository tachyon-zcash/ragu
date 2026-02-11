//! Representations and views of polynomials used in Ragu's proof system.

pub mod structured;
pub mod txz;
pub mod unstructured;

use ff::Field;

mod private {
    pub trait Sealed {}
    impl<const RANK: u32> Sealed for super::R<RANK> {}
}

/// Description of the rank of the coefficient vector size for polynomials, used
/// to prevent accidental conflation between different polynomial types or over
/// different fields.
pub trait Rank:
    private::Sealed + Clone + Send + Sync + 'static + PartialEq + Eq + core::fmt::Debug + Default
{
    /// The rank can range from $2$ to $28$ (to avoid overflows on 32-bit
    /// architectures), but only [`ProductionRank`] and [`TestRank`] are
    /// currently implemented.
    const RANK: u32;

    /// Returns the $2^\text{RANK}$ number of coefficients in the polynomials
    /// for this rank. The corresponding degree is thus `Self::num_coeffs() - 1`.
    fn num_coeffs() -> usize {
        1 << Self::RANK
    }

    /// Returns the vector length $n$ which represents the maximum number of
    /// multiplication constraints allowed for circuits in this rank.
    fn n() -> usize {
        1 << (Self::RANK - 2)
    }

    /// Returns $\log_2(n) = \text{RANK} - 2$.
    fn log2_n() -> u32 {
        Self::RANK - 2
    }

    /// Computes the coefficients of
    /// $$t(X, z) = -\sum_{i=0}^{n - 1} X^{4n - 1 - i} (z^{2n - 1 - i} + z^{2n + i})$$
    /// for some $z \in \mathbb{F}$.
    ///
    /// This polynomial is designed to align with the structured coefficient
    /// layout, so it can be added directly to structured `b(X)` values. It is
    /// the fixed term needed for the revdot identity that ties the witness
    /// polynomial to the public input polynomial.
    fn tz<F: Field>(z: F) -> structured::Polynomial<F, Self> {
        let mut tmp = structured::Polynomial::new();
        if z != F::ZERO {
            let tmp = tmp.backward();
            let zinv = z.invert().unwrap();
            let zpow = z.pow_vartime([2 * Self::n() as u64]);
            let mut l = -zpow * zinv;
            let mut r = -zpow;
            for _ in 0..Self::n() {
                tmp.c.push(l + r);
                l *= zinv;
                r *= z;
            }
        }

        tmp
    }

    /// Computes the coefficients of
    /// $$t(x, Z) = -\sum_{i=0}^{n - 1} x^{4n - 1 - i} (Z^{2n - 1 - i} + Z^{2n + i})$$
    /// for some $x \in \mathbb{F}$.
    ///
    /// This is the symmetric counterpart to [`Rank::tz`]: here $x$ is the
    /// evaluation point and $Z$ remains the indeterminate.
    fn tx<F: Field>(x: F) -> structured::Polynomial<F, Self> {
        let mut tmp = structured::Polynomial::new();
        if x != F::ZERO {
            let tmp = tmp.backward();
            let mut xi = -x.pow([3 * Self::n() as u64]);
            for _ in 0..Self::n() {
                tmp.a.push(xi);
                tmp.b.push(xi);
                xi *= x;
            }
            tmp.a.reverse();
            tmp.b.reverse();
        }

        tmp
    }

    /// Computes
    /// $$t(x, z) = -\sum_{i=0}^{n - 1} x^{4n - 1 - i} (z^{2n - 1 - i} + z^{2n + i})$$
    /// for some $x, z \in \mathbb{F}$.
    ///
    /// The exponent pattern mirrors the structured polynomial layout, which
    /// is why this function delegates to the circuit-friendly evaluator in
    /// [`txz::Evaluate`].
    fn txz<F: Field>(x: F, z: F) -> F {
        if x == F::ZERO || z == F::ZERO {
            return F::ZERO;
        }

        use ragu_core::{
            drivers::{Driver, emulator::Emulator},
            maybe::Maybe,
        };
        use ragu_primitives::Element;

        *Emulator::emulate_wireless((x, z), |dr, xz| {
            let (x, z) = xz.cast();
            let x = Element::alloc(dr, x)?;
            let z = Element::alloc(dr, z)?;

            dr.routine(txz::Evaluate::<Self>::new(), (x, z))
        })
        .expect("should synthesize correctly without triggering inversion errors")
        .value()
        .take()
    }
}

/// `R<N>` implements [`Rank`] for supported values of $N$. The type aliases
/// [`ProductionRank`] ($N = 13$) and [`TestRank`] ($N = 7$) are provided for
/// convenience. Additional implementations can be added to `impl_rank_for_R!` as needed.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct R<const RANK: u32>;

/// The standard production rank for Ragu circuits.
///
/// Provides $2^{13} = 8192$ polynomial coefficients and supports up to
/// $2^{11} = 2048$ multiplication constraints.
pub type ProductionRank = R<13>;

/// A small rank for fast unit tests.
///
/// Provides $2^7 = 128$ polynomial coefficients and supports up to
/// $2^5 = 32$ multiplication constraints.
pub type TestRank = R<7>;

/// Macro to implement [`Rank`] for various `R<N>`.
macro_rules! impl_rank_for_R {
    ($($n:literal),*) => {
        $(
            #[doc(hidden)]
            impl Rank for R<$n> {
                const RANK: u32 = $n;
            }
        )*
    };
}

impl_rank_for_R! {7, 13}

#[test]
fn test_tz() {
    use ragu_pasta::Fp;

    type DemoR = TestRank;

    let mut poly = structured::Polynomial::<Fp, DemoR>::new();
    for _ in 0..DemoR::n() {
        poly.u.push(Fp::ONE);
        poly.v.push(Fp::ONE);
    }
    let z = Fp::random(&mut rand::rng());
    poly.dilate(z);
    poly.negate();

    let mut expected_tz = structured::Polynomial::<Fp, DemoR>::new();
    {
        let expected_tz = expected_tz.backward();
        for i in 0..DemoR::n() {
            expected_tz.c.push(poly.u[i] + poly.v[i]);
        }
    }

    let expected_tz = expected_tz.unstructured().coeffs;

    assert_eq!(expected_tz, DemoR::tz::<Fp>(z).unstructured().coeffs);
}

#[test]
fn test_txz_consistency() {
    use ragu_pasta::Fp;
    type DemoR = TestRank;
    let z = Fp::random(&mut rand::rng());
    let x = Fp::random(&mut rand::rng());
    let txz = DemoR::txz(x, z);
    let tx0 = DemoR::txz(x, Fp::ZERO);
    let t0z: Fp = DemoR::txz(Fp::ZERO, z);
    let t00 = DemoR::txz(Fp::ZERO, Fp::ZERO);
    assert_eq!(
        txz,
        ragu_arithmetic::eval(&DemoR::tz::<Fp>(z).unstructured().coeffs, x)
    );
    assert_eq!(
        tx0,
        ragu_arithmetic::eval(&DemoR::tz::<Fp>(Fp::ZERO).unstructured().coeffs, x)
    );
    assert_eq!(
        txz,
        ragu_arithmetic::eval(&DemoR::tx::<Fp>(x).unstructured().coeffs, z)
    );
    assert_eq!(
        t0z,
        ragu_arithmetic::eval(&DemoR::tx::<Fp>(Fp::ZERO).unstructured().coeffs, z)
    );

    assert_eq!(
        t00,
        ragu_arithmetic::eval(&DemoR::tz::<Fp>(Fp::ZERO).unstructured().coeffs, Fp::ZERO)
    );
    assert_eq!(
        t00,
        ragu_arithmetic::eval(&DemoR::tx::<Fp>(Fp::ZERO).unstructured().coeffs, Fp::ZERO)
    );
}

//! Representations and views of polynomials used in Ragu's proof system.

pub mod sparse;
pub mod txz;

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
    ///
    /// This also serves as the upper bound on the number of constraints a
    /// circuit may contain.
    fn num_coeffs() -> usize {
        1 << Self::RANK
    }

    /// Returns the vector length $n$ which represents the maximum number of
    /// gates allowed for circuits in this rank.
    fn n() -> usize {
        1 << (Self::RANK - 2)
    }

    /// Returns $\log_2(n) = \text{RANK} - 2$.
    fn log2_n() -> u32 {
        Self::RANK - 2
    }

    /// Computes the coefficients of $$t(X, z) = -\sum_{i=0}^{n - 1} X^{4n - 1 - i} (z^{2n - 1 - i} + z^{2n + i})$$ for some $z \in \mathbb{F}$.
    fn tz<F: Field>(z: F) -> sparse::Polynomial<F, Self> {
        let mut view = sparse::View::wiring();
        if z != F::ZERO {
            let zinv = z.invert().unwrap();
            let zpow = z.pow_vartime([2 * Self::n() as u64]);
            let mut l = -zpow * zinv;
            let mut r = -zpow;
            for _ in 0..Self::n() {
                view.c.push(l + r);
                l *= zinv;
                r *= z;
            }
        }

        view.build()
    }

    /// Computes the coefficients of $$t(x, Z) = -\sum_{i=0}^{n - 1} x^{4n - 1 - i} (Z^{2n - 1 - i} + Z^{2n + i})$$ for some $x \in \mathbb{F}$.
    fn tx<F: Field>(x: F) -> sparse::Polynomial<F, Self> {
        let mut view = sparse::View::wiring();
        if x != F::ZERO {
            let mut xi = -x.pow([3 * Self::n() as u64]);
            for _ in 0..Self::n() {
                view.a.push(xi);
                view.b.push(xi);
                xi *= x;
            }
            view.a.reverse();
            view.b.reverse();
        }

        view.build()
    }

    /// Computes $$t(x, z) = -\sum_{i=0}^{n - 1} x^{4n - 1 - i} (z^{2n - 1 - i} + z^{2n + i})$$ for some $x, z \in \mathbb{F}$.
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
/// $2^{11} = 2048$ gates.
pub type ProductionRank = R<13>;

/// A small rank for fast unit tests.
///
/// Provides $2^7 = 128$ polynomial coefficients and supports up to
/// $2^5 = 32$ gates.
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

    // Construct a polynomial with all a and b wires = ONE.
    let mut view = sparse::View::<_, DemoR, _>::trace();
    for _ in 0..DemoR::n() {
        view.a.push(Fp::ONE);
        view.b.push(Fp::ONE);
    }
    let mut poly = view.build();
    let z = Fp::random(&mut rand::rng());
    poly.dilate(z);
    poly.negate();
    let poly_dense = poly.to_dense();

    // Construct the expected tz via wiring view with c[i] = poly[2n+i] + poly[2n-1-i].
    let n = DemoR::n();
    let mut expected_view = sparse::View::<_, DemoR, _>::wiring();
    for i in 0..n {
        expected_view
            .c
            .push(poly_dense[2 * n + i] + poly_dense[2 * n - 1 - i]);
    }
    let expected_tz = expected_view.build().to_dense();

    assert_eq!(expected_tz, DemoR::tz::<Fp>(z).to_dense());
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
    assert_eq!(txz, DemoR::tz::<Fp>(z).eval(x));
    assert_eq!(tx0, DemoR::tz::<Fp>(Fp::ZERO).eval(x));
    assert_eq!(txz, DemoR::tx::<Fp>(x).eval(z));
    assert_eq!(t0z, DemoR::tx::<Fp>(Fp::ZERO).eval(z));

    assert_eq!(t00, DemoR::tz::<Fp>(Fp::ZERO).eval(Fp::ZERO));
    assert_eq!(t00, DemoR::tx::<Fp>(Fp::ZERO).eval(Fp::ZERO));
}

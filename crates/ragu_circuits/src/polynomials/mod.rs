//! Representations and views of polynomials used in Ragu's proof system.

use ff::Field;

mod omega;
pub mod structured;
mod txz;
pub mod unstructured;

mod private {
    pub trait Sealed {}
    impl<const RANK: u32> Sealed for super::R<RANK> {}
}

/// Description of the rank of the coefficient vector size for polynomials, used
/// to prevent accidental conflation between different polynomial types or over
/// different fields.
pub trait Rank:
    private::Sealed + Clone + Send + Sync + 'static + PartialEq + Eq + core::fmt::Debug
{
    /// Ragu currently only supports ranks between $2$ and $28$ to avoid
    /// overflows on 32-bit architectures.
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

    /// Computes the coefficients of $$t(X, z) = -\sum_{i=0}^{n - 1} X^{4n - 1 - i} (z^{2n - 1 - i} + z^{2n + i})$$ for some $z \in \mathbb{F}$.
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

    /// Computes the coefficients of $$t(x, Z) = -\sum_{i=0}^{n - 1} x^{4n - 1 - i} (Z^{2n - 1 - i} + Z^{2n + i})$$ for some $x \in \mathbb{F}$.
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

            dr.routine(txz::Evaluate::new(Self::log2_n()), (x, z))
        })
        .expect("should synthesize correctly without triggering inversion errors")
        .value()
        .take()
    }
}

/// Explicit implementations for various basis sizes supported for use in Ragu.
/// `R<N>` implements [`Rank`] for $N \in [2, 28]$.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct R<const RANK: u32>;

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

impl_rank_for_R! {2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28}

#[test]
fn test_tz() {
    use ragu_pasta::Fp;
    use rand::thread_rng;

    type DemoR = R<7>;

    let mut poly = structured::Polynomial::<Fp, DemoR>::new();
    for _ in 0..DemoR::n() {
        poly.u.push(Fp::ONE);
        poly.v.push(Fp::ONE);
    }
    let z = Fp::random(thread_rng());
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
    use rand::thread_rng;
    type DemoR = R<10>;
    let z = Fp::random(thread_rng());
    let x = Fp::random(thread_rng());
    let txz = DemoR::txz(x, z);
    let tx0 = DemoR::txz(x, Fp::ZERO);
    let t0z: Fp = DemoR::txz(Fp::ZERO, z);
    let t00 = DemoR::txz(Fp::ZERO, Fp::ZERO);
    assert_eq!(
        txz,
        arithmetic::eval(&DemoR::tz::<Fp>(z).unstructured().coeffs, x)
    );
    assert_eq!(
        tx0,
        arithmetic::eval(&DemoR::tz::<Fp>(Fp::ZERO).unstructured().coeffs, x)
    );
    assert_eq!(
        txz,
        arithmetic::eval(&DemoR::tx::<Fp>(x).unstructured().coeffs, z)
    );
    assert_eq!(
        t0z,
        arithmetic::eval(&DemoR::tx::<Fp>(Fp::ZERO).unstructured().coeffs, z)
    );

    assert_eq!(
        t00,
        arithmetic::eval(&DemoR::tz::<Fp>(Fp::ZERO).unstructured().coeffs, Fp::ZERO)
    );
    assert_eq!(
        t00,
        arithmetic::eval(&DemoR::tx::<Fp>(Fp::ZERO).unstructured().coeffs, Fp::ZERO)
    );
}

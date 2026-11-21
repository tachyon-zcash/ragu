//! The free coefficients of an rx polynomial.

use rand::CryptoRng;
use udon::field::Field;

/// The three coefficients of an rx polynomial that no wiring polynomial
/// reads: `a[0]` of the SYSTEM gate, and `a[n - 1]` and `d[n - 1]` of the
/// blind gate, the last gate of the rank
/// ([`Rank::blind_gate`](crate::polynomials::Rank::blind_gate)).
///
/// No circuit and no stage uses the blind gate, and every mask leaves these
/// three wires out, so a trace or a stage polynomial may hold any values
/// there. A parent proof exposes a child's polynomial three times, as a
/// commitment and as two evaluations, so three uniformly random coefficients
/// hide the rest of the polynomial from whoever sees those values.
/// [`random`](Self::random) draws all three.
///
/// A field element converts into the `Blind` that holds it as `alpha` and
/// leaves the blind gate zero. That is the polynomial a verifier rebuilds
/// when it recomputes a commitment from the values alone, and what tests
/// pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Blind<F> {
    /// The value at `a[0]`. Without it a stage polynomial could be zero, or
    /// could cancel in a linear combination of stage polynomials, and either
    /// would give a commitment at the point at infinity.
    pub alpha: F,
    /// The values at `a[n - 1]` and `d[n - 1]`.
    pub gate: [F; 2],
}

impl<F: Field> Blind<F> {
    /// Draws all three coefficients uniformly at random.
    pub fn random(rng: &mut impl CryptoRng) -> Self {
        let mut draw = || F::random(|bytes| rng.fill_bytes(bytes));
        Blind {
            alpha: draw(),
            gate: [draw(), draw()],
        }
    }

    /// The `Blind` with every coefficient zero.
    pub const ZERO: Self = Blind {
        alpha: F::ZERO,
        gate: [F::ZERO, F::ZERO],
    };
}

impl<F: Field> From<F> for Blind<F> {
    fn from(alpha: F) -> Self {
        Blind {
            alpha,
            gate: [F::ZERO, F::ZERO],
        }
    }
}

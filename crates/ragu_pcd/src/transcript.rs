//! **TEMPORARY** Extremely handwavy dummy transcript construction to motivate thinking
//! through the transcript objects for the accumulation.
//!
//! TODO: https://github.com/tachyon-zcash/ragu/issues/31.

use arithmetic::CurveAffine;
use ff::Field;

/// Generic transcript that operates over field F.
pub struct AccumulationTranscript<F: Field> {
    state: F,
}

impl<F: Field> AccumulationTranscript<F> {
    pub fn new() -> Self {
        Self { state: F::ZERO }
    }

    /// Hash point coordinates into state (when point base field matches transcript field).
    pub fn absorb_point<C: CurveAffine<Base = F>>(&mut self, point: C) {
        let coords = point.coordinates().unwrap();
        self.state += coords.x();
        self.state += coords.y();
    }

    /// Absorb a scalar field element into state.
    pub fn absorb_scalar(&mut self, scalar: F) {
        self.state += scalar;
    }

    /// Squeeze challenge scalar from transcript state.
    pub fn squeeze(&mut self) -> F {
        self.state = self.state.square();
        self.state
    }
}

impl<F: Field> Default for AccumulationTranscript<F> {
    fn default() -> Self {
        Self::new()
    }
}

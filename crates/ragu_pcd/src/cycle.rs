use arithmetic::CurveAffine;
use pasta_curves::{EpAffine, EqAffine};

/// Extends [`CurveAffine`] (the supertrait) with information about the
/// paired curve in the 2-cycle.
pub trait CurveCycle: CurveAffine {
    type Pair: CurveAffine<Base = Self::ScalarExt, ScalarExt = Self::Base>;
}

// Implement for Pallas
impl CurveCycle for EpAffine {
    type Pair = EqAffine;
}

// Implement for Vesta
impl CurveCycle for EqAffine {
    type Pair = EpAffine;
}

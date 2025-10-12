use arithmetic::CurveAffine;
use pasta_curves::{EpAffine, EqAffine};
use ragu_circuits::polynomials::Rank;

use crate::accumulator::Accumulator;

/// Extends [`CurveAffine`] (the supertrait) with information about the
/// paired curve in the 2-cycle.
pub trait CurveCycle: CurveAffine {
    type Pair: CurveAffine<Base = Self::ScalarExt, ScalarExt = Self::Base>;
}

/// Type aliases.
pub type PrimaryField<C> = <C as CurveAffine>::ScalarExt;
pub type PairedField<C> = <<C as CurveCycle>::Pair as CurveAffine>::ScalarExt;
pub type PrimaryBase<C> = <C as CurveAffine>::Base;
pub type PairedBase<C> = <<C as CurveCycle>::Pair as CurveAffine>::Base;

// Implement for Pallas.
impl CurveCycle for EpAffine {
    type Pair = EqAffine;
}

// Implement for Vesta.
impl CurveCycle for EqAffine {
    type Pair = EpAffine;
}

pub enum CycleState<C, R>
where
    C: CurveCycle,
    R: Rank,
{
    /// Currently on the primary curve (C).
    OnPrimary {
        primary: Accumulator<C, R>,
        paired: Accumulator<C::Pair, R>,
    },
    /// Currently on the paired curve (C::Pair).
    OnPaired {
        primary: Accumulator<C, R>,
        paired: Accumulator<C::Pair, R>,
    },
}

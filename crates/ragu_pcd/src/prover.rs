use std::marker::PhantomData;

use arithmetic::CurveAffine;
use ragu_circuits::polynomials::Rank;

// TODO: https://github.com/ebfull/ragu/issues/16.
pub struct AccumulationProver<C, R>
where
    C: CurveAffine,
    R: Rank,
{
    pub(crate) _curve_cycle: PhantomData<C>,
    _rank: PhantomData<R>,
}

impl<C: CurveAffine, R: Rank> AccumulationProver<C, R> {
    pub fn new() -> Self {
        Self {
            _curve_cycle: PhantomData,
            _rank: PhantomData,
        }
    }
}

impl<C: CurveAffine, R: Rank> Default for AccumulationProver<C, R> {
    fn default() -> Self {
        Self::new()
    }
}

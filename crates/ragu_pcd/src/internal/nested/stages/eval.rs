//! Eval stage for nested fuse operations.

use core::marker::PhantomData;

use ragu_arithmetic::CurveAffine;
use ragu_circuits::polynomials::Rank;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Point,
    io::Write,
    vec::{FixedVec, Len},
};

/// Witness data for this bridge stage.
pub struct Witness<C: CurveAffine, L: Len> {
    pub native_eval: C,
    /// The current step's witness-poly host commitments.
    pub witness_polys: FixedVec<C, L>,
}

/// This stage's points.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>, L: Len> {
    #[ragu(gadget)]
    pub native_eval: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub witness_polys: FixedVec<Point<'dr, D, C>, L>,
}

/// The eval bridge stage: `native_eval`, then one bridge per witnessed
/// polynomial.
pub struct Stage<C: CurveAffine, R, L> {
    _marker: PhantomData<(C, R, L)>,
}

impl<C: CurveAffine, R, L> Default for Stage<C, R, L> {
    fn default() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<C: CurveAffine, R: Rank, L: Len> ragu_circuits::staging::Stage<C::Base, R> for Stage<C, R, L> {
    type Parent = super::f::Stage<C, R, L>;
    type Witness<'source> = &'source Witness<C, L>;
    type OutputKind = Kind![C::Base; Output<'_, _, C, L>];

    fn values() -> usize {
        2 * (1 + L::len())
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        Ok(Output {
            native_eval: Point::alloc(dr, witness.as_ref().map(|w| w.native_eval))?,
            witness_polys: FixedVec::try_from_fn(|i| {
                Point::alloc(dr, witness.as_ref().map(|w| w.witness_polys[i]))
            })?,
        })
    }
}

#[cfg(test)]
mod tests {
    use ragu_pasta::EqAffine;
    use ragu_primitives::vec::ConstLen;

    use super::*;
    use crate::internal::tests::{R, assert_stage_values};

    #[test]
    fn stage_values_matches_wire_count() {
        assert_stage_values(&Stage::<EqAffine, R, ConstLen<0>>::default());
        assert_stage_values(&Stage::<EqAffine, R, ConstLen<4>>::default());
        assert_stage_values(&Stage::<EqAffine, R, ConstLen<8>>::default());
    }
}

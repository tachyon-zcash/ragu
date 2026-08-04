//! F stage for nested fuse operations.

use core::marker::PhantomData;

use ragu_arithmetic::CurveAffine;
use ragu_circuits::polynomials::Rank;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{Point, io::Write, vec::Len};

/// Number of curve points in this stage.
const NUM: usize = 1;

/// Witness data for this bridge stage.
pub struct Witness<C: CurveAffine> {
    pub native_f: C,
}

/// Prover-internal output gadget for this bridge stage.
///
/// This is stage communication data, not part of the circuit's
/// public instance.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    #[ragu(gadget)]
    pub native_f: Point<'dr, D, C>,
}

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
    type Parent = super::query::Stage<C, R, L>;
    type Witness<'source> = &'source Witness<C>;
    type OutputKind = Kind![C::Base; Output<'_, _, C>];

    fn values() -> usize {
        NUM * 2
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
            native_f: Point::alloc(dr, witness.as_ref().map(|w| w.native_f))?,
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
        assert_stage_values(&Stage::<EqAffine, R, ConstLen<4>>::default());
    }
}

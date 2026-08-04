//! S-prime stage for nested fuse operations.

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
const NUM: usize = 3;

/// Witness data for this bridge stage.
pub struct Witness<C: CurveAffine> {
    pub registry_wx0: C,
    pub registry_wx1: C,
    /// Stashed copy of the current step's native preamble commitment.
    ///
    /// The copying circuit loads a fresh trace of the child's stages
    /// and cannot access `BridgePreamble.native_preamble` at a
    /// different wire position from its own `BridgePreamble`. Stashing
    /// the value here lets a parent's copying circuit read it from
    /// `BridgeSPrime` instead.
    pub stashed_preamble: C,
}

/// Prover-internal output gadget for this bridge stage.
///
/// This is stage communication data, not part of the circuit's
/// public instance.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    #[ragu(gadget)]
    pub registry_wx0: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub registry_wx1: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub stashed_preamble: Point<'dr, D, C>,
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
    type Parent = super::preamble::Stage<C, R, L>;
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
            registry_wx0: Point::alloc(dr, witness.as_ref().map(|w| w.registry_wx0))?,
            registry_wx1: Point::alloc(dr, witness.as_ref().map(|w| w.registry_wx1))?,
            stashed_preamble: Point::alloc(dr, witness.as_ref().map(|w| w.stashed_preamble))?,
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

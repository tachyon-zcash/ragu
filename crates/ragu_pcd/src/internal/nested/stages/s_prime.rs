//! S-prime stage for nested fuse operations: the native `registry_wx`
//! commitments, and the commitment of the native points stage holding their
//! nested counterparts.

use core::marker::PhantomData;

use ragu_circuits::polynomials::Rank;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{Point, io::Write};
use udon::curve::EndomorphismAffine as Affine;

use crate::profile::Profile;

/// Number of curve points in this stage.
const NUM: usize = 3;

/// Witness data for this bridge stage.
pub struct Witness<C: Affine> {
    pub registry_wx0: C,
    pub registry_wx1: C,
    /// Commitment of the native points stage holding the nested
    /// `registry_wx` commitments, fixed here before $y$ is squeezed.
    pub native_points_registry_wx: C,
}

/// Prover-internal output gadget for this bridge stage.
///
/// This is stage communication data, not part of the circuit's
/// public instance.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> {
    #[ragu(gadget)]
    pub registry_wx0: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub registry_wx1: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub native_points_registry_wx: Point<'dr, D, C>,
}

#[derive(Default)]
pub struct Stage<C: Affine, R, P> {
    _marker: PhantomData<(C, R, P)>,
}

impl<C: Affine, R: Rank, P: Profile> ragu_circuits::staging::Stage<C::Base, R> for Stage<C, R, P> {
    type Parent = super::preamble::Stage<C, R, P>;
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
            native_points_registry_wx: Point::alloc(
                dr,
                witness.as_ref().map(|w| w.native_points_registry_wx),
            )?,
        })
    }
}

#[cfg(test)]
mod tests {
    use ragu_core::pasta::EqAffine;

    use super::*;
    use crate::{
        internal::tests::{R, assert_stage_values},
        profile::Standard,
    };

    #[test]
    fn stage_values_matches_wire_count() {
        assert_stage_values(&Stage::<EqAffine, R, Standard>::default());
    }
}

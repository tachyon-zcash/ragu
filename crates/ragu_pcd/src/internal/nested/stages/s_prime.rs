//! S-prime stage for nested fuse operations: the native `registry_wx`
//! commitments, the commitments of the native preamble stage, of the
//! step's own application trace and of its two fold randomizers, and the
//! commitment of the native points stage holding the `registry_wx`
//! commitments' and the fold randomizers' nested counterparts.
//!
//! The step folds its own application claim at the $y$ squeezed right after
//! this stage's commitment is absorbed, so the trace, and the preamble that
//! holds the claim's output header and online openings, are fixed before
//! the claim's challenges. Neither need be fixed before $w$: the claim's
//! registry restriction is the circuit's own, $m(\omega^{id}, X, y)$, which
//! does not involve $w$, and the preamble's own values are what the step's
//! circuit fixes at $\zeta = w$. The preamble's copies of the children's
//! values are fixed before $w$ all the same, through the children's
//! committed traces and the fold at $y$ (see
//! [`preamble`](crate::internal::native::stages::preamble)).

use core::marker::PhantomData;

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
use udon::curve::EndomorphismAffine as Affine;

use crate::profile::{
    Profile,
    online::stages::{Native, PhaseLen},
};

/// Number of curve points in this stage.
const NUM: usize = 7;

/// Witness data for this bridge stage.
pub struct Witness<C: Affine, P: Profile> {
    /// Native auxiliary commitments fixed at this boundary.
    pub online_points: FixedVec<C, PhaseLen<P, Native, 1>>,
    pub registry_wx0: C,
    pub registry_wx1: C,
    /// Commitment of the native preamble stage, committed after the step's
    /// circuit ran (see [`preamble`](crate::internal::native::stages::preamble)).
    pub native_preamble: C,
    /// Commitment of the step's own application trace.
    pub native_application: C,
    /// Commitment of the native points stage holding the nested
    /// `registry_wx` commitments, fixed here before $y$ is squeezed.
    pub native_points_registry_wx: C,
    /// Commitments of the step's own native fold randomizers $a_r$ and
    /// $b_r$ (see
    /// [`revdot`](crate::internal::revdot#the-randomizer)), fixed
    /// here before the fold's challenges.
    pub randomizer_a: C,
    pub randomizer_b: C,
}

/// Prover-internal output gadget for this bridge stage.
///
/// This is stage communication data, not part of the circuit's
/// public instance.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, P: Profile> {
    /// Native auxiliary points bound to the walk and common claim target.
    #[ragu(gadget)]
    pub online_points: FixedVec<Point<'dr, D, C>, PhaseLen<P, Native, 1>>,
    #[ragu(gadget)]
    pub registry_wx0: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub registry_wx1: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub native_preamble: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub native_application: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub native_points_registry_wx: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub randomizer_a: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub randomizer_b: Point<'dr, D, C>,
}

#[derive(Default)]
pub struct Stage<C: Affine, R, P> {
    _marker: PhantomData<(C, R, P)>,
}

impl<C: Affine, R: Rank, P: Profile> ragu_circuits::staging::Stage<C::Base, R> for Stage<C, R, P> {
    type Parent = super::preamble::Stage<C, R, P>;
    type Witness<'source> = &'source Witness<C, P>;
    type OutputKind = Kind![C::Base; Output<'_, _, C, P>];

    /// The stage's position in the profile's layout (see
    /// [`layout`](crate::internal::nested::layout)).
    fn skip_gates() -> usize {
        crate::internal::nested::layout::skip_gates::<C, R, P, Self>(
            crate::internal::nested::layout::Slot::SPrime,
        )
    }

    fn values() -> usize {
        (NUM + PhaseLen::<P, Native, 1>::len()) * 2
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
            online_points: FixedVec::try_from_fn(|i| {
                Point::alloc(dr, witness.as_ref().map(|w| w.online_points[i]))
            })?,
            registry_wx0: Point::alloc(dr, witness.as_ref().map(|w| w.registry_wx0))?,
            registry_wx1: Point::alloc(dr, witness.as_ref().map(|w| w.registry_wx1))?,
            native_preamble: Point::alloc(dr, witness.as_ref().map(|w| w.native_preamble))?,
            native_application: Point::alloc(dr, witness.as_ref().map(|w| w.native_application))?,
            native_points_registry_wx: Point::alloc(
                dr,
                witness.as_ref().map(|w| w.native_points_registry_wx),
            )?,
            randomizer_a: Point::alloc(dr, witness.as_ref().map(|w| w.randomizer_a))?,
            randomizer_b: Point::alloc(dr, witness.as_ref().map(|w| w.randomizer_b))?,
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

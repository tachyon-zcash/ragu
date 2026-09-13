//! Inner error stage for nested fuse operations.
//!
//! Alongside the two host-curve commitments it bridges, this stage carries
//! the layer-1 error terms of the nested revdot fold: for each group of the
//! children's nested claims, the off-diagonal revdot products of that group.
//! They are committed here, inside the bridge stage whose commitment the
//! transcript absorbs before squeezing $\mu$ and $\nu$. This preserves the
//! commit-before-challenge order without changing the transcript schedule.
//! Recursive verification additionally requires binding the derived
//! challenges and checking the fold; storing these terms does not enforce it.
//! The [`collapse`] circuit checks the fold.
//!
//! [`collapse`]: crate::internal::nested::circuits::collapse

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
    Element, Point,
    io::Write,
    vec::{FixedVec, Len},
};

use crate::internal::{
    fold_revdot::{NumErrorTerms, Parameters},
    nested::RevdotParameters,
};

/// Number of curve points in this stage.
const NUM: usize = 2;

type NumGroups = <RevdotParameters as Parameters>::NumGroups;
type GroupSize = <RevdotParameters as Parameters>::GroupSize;

/// Witness data for this bridge stage.
pub struct Witness<C: CurveAffine> {
    pub native_inner_error: C,
    pub registry_wy: C,
    /// Layer-1 error terms of the nested revdot fold.
    ///
    /// Outer: one entry per group. Inner: the group's off-diagonal revdot
    /// products, in [`inner_error_terms_with_backend`] order.
    ///
    /// [`inner_error_terms_with_backend`]: crate::internal::fold_revdot::inner_error_terms_with_backend
    pub error_terms: FixedVec<FixedVec<C::Base, NumErrorTerms<GroupSize>>, NumGroups>,
}

/// Prover-internal output gadget for this bridge stage.
///
/// This is stage communication data, not part of the circuit's
/// public instance.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    #[ragu(gadget)]
    pub native_inner_error: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub registry_wy: Point<'dr, D, C>,
    /// Layer-1 error terms of the nested revdot fold.
    #[ragu(gadget)]
    pub error_terms: FixedVec<FixedVec<Element<'dr, D>, NumErrorTerms<GroupSize>>, NumGroups>,
}

#[derive(Default)]
pub struct Stage<C: CurveAffine, R> {
    _marker: PhantomData<(C, R)>,
}

impl<C: CurveAffine, R: Rank> ragu_circuits::staging::Stage<C::Base, R> for Stage<C, R> {
    type Parent = super::s_prime::Stage<C, R>;
    type Witness<'source> = &'source Witness<C>;
    type OutputKind = Kind![C::Base; Output<'_, _, C>];

    fn values() -> usize {
        // (x, y) per point + N * (M² - M) error terms
        NUM * 2 + NumGroups::len() * NumErrorTerms::<GroupSize>::len()
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        let allocator = &mut ();
        let native_inner_error = Point::alloc(dr, witness.as_ref().map(|w| w.native_inner_error))?;
        let registry_wy = Point::alloc(dr, witness.as_ref().map(|w| w.registry_wy))?;
        let error_terms = FixedVec::try_from_fn(|i| {
            FixedVec::try_from_fn(|j| {
                Element::alloc(dr, allocator, witness.as_ref().map(|w| w.error_terms[i][j]))
            })
        })?;

        Ok(Output {
            native_inner_error,
            registry_wy,
            error_terms,
        })
    }
}

#[cfg(test)]
mod tests {
    use ragu_pasta::EqAffine;

    use super::*;
    use crate::internal::tests::{R, assert_stage_values};

    #[test]
    fn stage_values_matches_wire_count() {
        assert_stage_values(&Stage::<EqAffine, R>::default());
    }
}

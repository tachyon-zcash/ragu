//! Outer error stage for nested fuse operations.
//!
//! Alongside the host-curve commitment it bridges, this stage carries the
//! layer-2 data of the nested revdot fold: the off-diagonal revdot products
//! of the layer-1 folded claims, and the layer-1 folded claim values
//! themselves. It is committed before $\mu'$ and $\nu'$ are squeezed,
//! preserving the commit-before-challenge order for the second layer.
//! Recursive verification additionally requires binding the derived
//! challenges and checking the fold; storing these terms does not enforce it.
//! The [`collapse`] circuit checks both layers.
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
    vec::{CollectFixed, FixedVec, Len},
};

use crate::internal::{
    fold_revdot::{NumErrorTerms, Parameters},
    nested::RevdotParameters,
};

/// Number of curve points in this stage.
const NUM: usize = 1;

type NumGroups = <RevdotParameters as Parameters>::NumGroups;

/// Witness data for this bridge stage.
pub struct Witness<C: CurveAffine> {
    pub native_outer_error: C,
    /// Layer-2 error terms of the nested revdot fold: the off-diagonal revdot
    /// products of the layer-1 folded claims.
    pub error_terms: FixedVec<C::Base, NumErrorTerms<NumGroups>>,
    /// The layer-1 folded claim values, one per group.
    pub collapsed: FixedVec<C::Base, NumGroups>,
}

/// Prover-internal output gadget for this bridge stage.
///
/// This is stage communication data, not part of the circuit's
/// public instance.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    #[ragu(gadget)]
    pub native_outer_error: Point<'dr, D, C>,
    /// Layer-2 error terms of the nested revdot fold.
    #[ragu(gadget)]
    pub error_terms: FixedVec<Element<'dr, D>, NumErrorTerms<NumGroups>>,
    /// The layer-1 folded claim values, one per group.
    #[ragu(gadget)]
    pub collapsed: FixedVec<Element<'dr, D>, NumGroups>,
}

#[derive(Default)]
pub struct Stage<C: CurveAffine, R> {
    _marker: PhantomData<(C, R)>,
}

impl<C: CurveAffine, R: Rank> ragu_circuits::staging::Stage<C::Base, R> for Stage<C, R> {
    type Parent = super::inner_error::Stage<C, R>;
    type Witness<'source> = &'source Witness<C>;
    type OutputKind = Kind![C::Base; Output<'_, _, C>];

    fn values() -> usize {
        // (x, y) per point + N² - N error terms + N collapsed values
        NUM * 2 + NumErrorTerms::<NumGroups>::len() + NumGroups::len()
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
        let native_outer_error = Point::alloc(dr, witness.as_ref().map(|w| w.native_outer_error))?;
        let error_terms = NumErrorTerms::<NumGroups>::range()
            .map(|i| Element::alloc(dr, allocator, witness.as_ref().map(|w| w.error_terms[i])))
            .try_collect_fixed()?;
        let collapsed = NumGroups::range()
            .map(|i| Element::alloc(dr, allocator, witness.as_ref().map(|w| w.collapsed[i])))
            .try_collect_fixed()?;

        Ok(Output {
            native_outer_error,
            error_terms,
            collapsed,
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

//! Inner error stage for nested fuse operations.
//!
//! Alongside the two host-curve commitments it bridges, this stage carries
//! the layer-1 error terms of the nested revdot fold: for each group of the
//! children's nested claims, the coefficients of that group's quotient.
//! They are committed here, inside the bridge stage whose commitment the
//! transcript absorbs before squeezing the first-layer folding challenge.
//! Recursive verification additionally requires binding the derived
//! challenges and checking the fold; storing these terms does not enforce it.
//! The [`collapse`] circuit checks the fold. The stage also carries the
//! target of the nested fold randomizer's claim (see
//! [`revdot`](crate::internal::revdot#the-randomizer)).
//!
//! [`collapse`]: crate::internal::nested::circuits::collapse

use core::marker::PhantomData;

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
use udon::curve::EndomorphismAffine as Affine;

use crate::{
    internal::{
        nested::RevdotParameters,
        revdot::{NumErrorTerms, Parameters},
    },
    profile::Profile,
};

/// Number of curve points in this stage.
const NUM: usize = 2;

type NumGroups<P> = <RevdotParameters<P> as Parameters>::NumGroups;
type GroupSize<P> = <RevdotParameters<P> as Parameters>::GroupSize;

/// Witness data for this bridge stage.
pub struct Witness<C: Affine, P: Profile> {
    pub native_inner_error: C,
    pub registry_wy: C,
    /// Layer-1 error terms of the nested revdot fold.
    ///
    /// Outer: one entry per group. Inner: the group's quotient coefficients
    /// in ascending power order, as returned by [`inner_error_terms_with_backend`].
    ///
    /// [`inner_error_terms_with_backend`]: crate::internal::revdot::inner_error_terms_with_backend
    pub error_terms: FixedVec<FixedVec<C::Base, NumErrorTerms<GroupSize<P>>>, NumGroups<P>>,
    /// The revdot product of the step's own nested fold randomizers.
    pub randomizer_c: C::Base,
}

/// Prover-internal output gadget for this bridge stage.
///
/// This is stage communication data, not part of the circuit's
/// public instance.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, P: Profile> {
    #[ragu(gadget)]
    pub native_inner_error: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub registry_wy: Point<'dr, D, C>,
    /// Layer-1 error terms of the nested revdot fold.
    #[ragu(gadget)]
    pub error_terms: FixedVec<FixedVec<Element<'dr, D>, NumErrorTerms<GroupSize<P>>>, NumGroups<P>>,
    /// The revdot product of the step's own nested fold randomizers.
    #[ragu(gadget)]
    pub randomizer_c: Element<'dr, D>,
}

#[derive(Default)]
pub struct Stage<C: Affine, R, P> {
    _marker: PhantomData<(C, R, P)>,
}

impl<C: Affine, R: Rank, P: Profile> ragu_circuits::staging::Stage<C::Base, R> for Stage<C, R, P> {
    type Parent = super::s_prime::Stage<C, R, P>;
    type Witness<'source> = &'source Witness<C, P>;
    type OutputKind = Kind![C::Base; Output<'_, _, C, P>];

    fn values() -> usize {
        // (x, y) per point + N * (M - 1) quotient coefficients + the
        // randomizer's target
        NUM * 2 + NumGroups::<P>::len() * NumErrorTerms::<GroupSize<P>>::len() + 1
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
        let randomizer_c = Element::alloc(dr, allocator, witness.as_ref().map(|w| w.randomizer_c))?;

        Ok(Output {
            native_inner_error,
            registry_wy,
            error_terms,
            randomizer_c,
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

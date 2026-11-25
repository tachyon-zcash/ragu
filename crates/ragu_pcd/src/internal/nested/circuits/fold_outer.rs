//! The second layer of a nested fold verified in chunks.
//!
//! In a profile whose nested fold is verified in chunks
//! ([`Chunking`](crate::profile::Chunking)), the
//! [`fold_inner`](super::fold_inner) circuits hold every group's collapsed
//! value in the `outer_error` stage to the group's fold. This circuit folds
//! those collapsed values with the stage's error terms under the lifted
//! $\mu'$ and, outside the base case, enforces the result equal to the
//! instance's $c_n$, exactly as [`collapse`](super::collapse) does for a
//! fold it verifies whole. The base case's verdict is the sign the
//! challenge stage carries, as there.
//!
//! The circuit ends on the challenge stage, as the instance circuits do,
//! and outputs the nested unified instance, of which it covers $c_n$.

use core::marker::PhantomData;

use ragu_circuits::{
    WithAux,
    polynomials::Rank,
    staging::{MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Bound,
    maybe::Maybe,
};
use ragu_primitives::{Element, allocator::Standard};
use udon::curve::EndomorphismAffine as Affine;

use super::common;
use crate::{
    internal::{
        nested::{
            RevdotParameters, is_fold_chunked,
            stages::{self, challenges},
            unified,
        },
        revdot,
    },
    profile::Profile,
};

/// The second layer's circuit of a nested fold verified in chunks.
pub struct Circuit<C: Affine, R: Rank, P: Profile> {
    _marker: PhantomData<(C, R, P)>,
}

impl<C: Affine, R: Rank, P: Profile> Circuit<C, R, P> {
    /// Creates the circuit.
    ///
    /// # Panics
    ///
    /// Panics if the profile's `collapse` verifies the fold whole.
    pub fn new() -> Self {
        assert!(
            is_fold_chunked::<P>(),
            "a fold verified whole is `collapse`'s"
        );
        Self {
            _marker: PhantomData,
        }
    }
}

impl<C: Affine, R: Rank, P: Profile> MultiStageCircuit<C::Base, R> for Circuit<C, R, P> {
    type Last = stages::challenges::Stage<C, R, P>;
    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = common::Witness<'source, C, P>;
    type Output = unified::OutputKind<C>;
    type Aux<'source> = unified::Instance<C>;

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        unreachable!("instance for internal circuits is not invoked")
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>> {
        let (dr, stages) = common::load_all(dr, &witness)?;

        let allocator = &mut Standard::new();
        let mut unified = unified::OutputBuilder::new(witness.map(|w| w.instance));

        // The fold of the collapsed values is c_n, outside the base case.
        let fold = revdot::ClaimFolder::new(&stages.challenges.pairs[challenges::MU_PRIME].lift);
        let computed_c = fold.fold_outer::<RevdotParameters<P>>(
            dr,
            &stages.outer_error.error_terms,
            &stages.outer_error.collapsed,
        )?;
        let witnessed_c = unified.c.receive(dr, allocator)?;
        let is_base_case =
            stages
                .challenges
                .base_case
                .lift
                .is_equal(dr, allocator, &Element::one())?;
        is_base_case
            .not(dr)
            .conditional_enforce_equal(dr, allocator, &witnessed_c, &computed_c)?;

        let (output, instance) = unified.finish(dr, allocator)?;
        Ok(WithAux::new(output, instance))
    }
}

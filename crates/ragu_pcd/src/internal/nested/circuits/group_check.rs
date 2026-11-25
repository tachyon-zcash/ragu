//! The check circuit of one group of a grouped nested walk.
//!
//! A grouped walk keeps each group of steps in its own points stage
//! polynomial (see [`paging`](crate::internal::paging#groups)). The steps
//! of a group hold only the walk's arithmetic within the group. This
//! circuit holds the rest for one group, as [`collapse`](super::collapse)
//! does for a walk in one stage:
//!
//! - **The stage contracts.** Every point of the group's points stage lies
//!   on the curve.
//! - **The walked points.** Every input of the group equals the copy a
//!   bridge stage holds, which the transcript absorbed before the
//!   challenge the walk folds under.
//! - **The chain.** The group's entry equals its link and its exit equals
//!   the next link ([`paging::link`]), so the groups are one walk.
//!
//! `collapse` holds the first link to the commitment of $f$ and exports
//! the last link as the walk's result.
//!
//! The circuit loads every nested stage, as the instance circuits do, with
//! its own group's points stage polynomial. It exposes nothing, so its
//! claim's $k(y)$ is one, and its last stage is the challenge stage, whose
//! final mask covers it.
//!
//! No circuit of a profile whose walk is in one stage is a group check.

use core::marker::PhantomData;

use ragu_circuits::{
    WithAux,
    polynomials::Rank,
    staging::{MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
};
use ragu_primitives::{GadgetExt, consistent::Consistent};
use udon::curve::EndomorphismAffine as Affine;

use super::{collapse::held_inputs, common};
use crate::{
    internal::{
        nested::{stages, walk_grouping},
        paging,
    },
    profile::Profile,
};

/// The check circuit of group `group` of the walk.
pub struct Circuit<C: Affine, R: Rank, P: Profile> {
    group: usize,
    _marker: PhantomData<(C, R, P)>,
}

impl<C: Affine, R: Rank, P: Profile> Circuit<C, R, P> {
    /// Creates the check circuit of group `group`.
    ///
    /// # Panics
    ///
    /// Panics if the profile's walk is not grouped or has no such group.
    pub fn new(group: usize) -> Self {
        let grouping = walk_grouping::<P>();
        assert!(grouping.is_grouped(), "the profile's walk is in one stage");
        assert!(group < grouping.groups(), "the walk has no group {group}");
        Self {
            group,
            _marker: PhantomData,
        }
    }
}

impl<C: Affine, R: Rank, P: Profile> MultiStageCircuit<C::Base, R> for Circuit<C, R, P> {
    type Last = stages::challenges::Stage<C, R, P>;
    type Instance<'source> = ();
    type Witness<'source> = common::Witness<'source, C, P>;
    type Output = Kind![C::Base; ()];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Ok(())
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>> {
        let (dr, stages) = common::load_all(dr, &witness, Some(self.group))?;
        let points = stages
            .points
            .as_ref()
            .expect("the group's points stage was loaded");

        // The stage contracts: the group's points on the curve, the unused
        // slots of a short last group among them.
        points.enforce_consistent(dr)?;

        // The walked points: each input of the group is the copy a bridge
        // stage holds.
        let grouping = walk_grouping::<P>();
        let held = held_inputs(&stages);
        for (local, index) in grouping.inputs_of(self.group).enumerate() {
            points.inputs[local].enforce_equal(dr, held[index])?;
        }

        // The chain: the group starts from its link and ends at the next.
        let exit = &points.interstitials[grouping.pages_of(self.group) - 1];
        paging::link(dr, &stages.links.states, self.group, &points.initial, exit)?;

        Ok(WithAux::new((), D::unit()))
    }
}

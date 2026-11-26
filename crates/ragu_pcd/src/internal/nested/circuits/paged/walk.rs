//! The steps that hold the walk's points: one for each group of the walk.

use ragu_core::{Result, drivers::Driver};
use ragu_primitives::{GadgetExt as _, consistent::Consistent};
use udon::curve::EndomorphismAffine as Affine;

use super::{Inputs, cells};
use crate::{
    internal::{
        nested::{
            circuits::collapse::{Held, held_inputs},
            walk_grouping,
        },
        paging,
    },
    profile::Profile,
};

/// Step [`Walk`](super::Step::Walk): the points of group `group` of the
/// walk, which the group's own points stage polynomial holds.
///
/// - **The stage contracts.** Every point of the group's points stage lies
///   on the curve, the unused slots of a short last group among them.
/// - **The walked points.** Every input of the group equals the copy a
///   bridge stage holds, in the order of
///   [`held_inputs`], which is what fixes the walked points before the
///   challenge the walk folds under (see the collapse circuit's
///   [walked points](super::super::collapse#the-walked-points)). The step
///   loads the `preamble` stage, which holds most of the copies, and the
///   stages of the trunk. It takes the `inner_error` and `query` stages'
///   copies from the memory cells that the steps that load those stages
///   stored them in.
/// - **The chain.** The group starts from its link and ends at the next
///   ([`paging::link`]). The [instance circuit](super::instance) holds the
///   first link to the commitment of $f$ and reads the walk's result off
///   the last.
pub fn group<'dr, D, C, P>(
    dr: &mut D,
    inputs: &Inputs<'_, 'dr, D, C, P>,
    group: usize,
) -> Result<()>
where
    D: Driver<'dr, F = C::Base>,
    C: Affine,
    P: Profile,
{
    let stages = inputs.stages;
    let points = stages.points(group)?;
    points.enforce_consistent(dr)?;

    let cells = cells::<P>();
    let memory = &inputs.memory;
    let registry_wy = memory.load_point(dr, cells.registry_wy)?;
    let registry_xy = memory.load_point(dr, cells.registry_xy)?;
    let query_online_points = cells
        .query_online_points
        .iter()
        .map(|&cell| memory.load_point(dr, cell))
        .collect::<Result<alloc::vec::Vec<_>>>()?;
    let held = held_inputs(&Held {
        preamble: stages.preamble()?,
        s_prime: &stages.s_prime,
        ab: &stages.ab,
        f: &stages.f,
        registry_wy: &registry_wy,
        registry_xy: &registry_xy,
        query_online_points: &query_online_points,
    });
    let grouping = walk_grouping::<P>();
    for (local, index) in grouping.inputs_of(group).enumerate() {
        points.inputs[local].enforce_equal(dr, held[index])?;
    }

    let exit = &points.interstitials[grouping.pages_of(group) - 1];
    paging::link(dr, &stages.links.states, group, &points.initial, exit)
}

//! The steps that check the fold of the children's nested claims: the
//! parts of the [`collapse`](super::super::collapse) circuit.

use ragu_core::{Result, drivers::Driver};
use ragu_primitives::{Element, GadgetExt as _, vec::FixedVec};
use udon::curve::EndomorphismAffine as Affine;

use super::{ERROR_GROUPS, Inputs, cells, grid, has_binding, has_online_helper};
use crate::{
    internal::{
        ky,
        nested::{
            RevdotParameters,
            claims::{TwoProofKySource, ky_values},
            stages::challenges,
        },
        paging,
        program::ElementCell,
        revdot,
    },
    profile::Profile,
};

/// Step [`Child`](super::Step::Child): the $k(y_n)$ values of the claims of
/// child `child`, which the `preamble` stage determines, into the memory
/// for the steps that fold the claims.
///
/// The values are the ones the collapse circuit computes for the child
/// (see its [$k(y_n)$ values](super::super::collapse#ky_n-values)): the
/// $k(y_n)$ of the child's nested unified instance, of its compute-v claim,
/// of its online helper claim and of its binding claim, each at the
/// challenge stage's $y_n$. The step also stores the child's nested $c$,
/// $v$, $x$, $y$ and $u$, which the steps of the other branches take the
/// raw claim's value and the openings' points from.
///
/// For a profile with a native mesh the step holds the step's own online
/// point for the child's restriction to the child's outgoing point, as the
/// compute-v circuit does.
pub fn child<'dr, D, C, P>(
    dr: &mut D,
    inputs: &Inputs<'_, 'dr, D, C, P>,
    child: usize,
) -> Result<()>
where
    D: Driver<'dr, F = C::Base>,
    C: Affine,
    P: Profile,
{
    let stages = inputs.stages;
    let preamble = stages.preamble()?;
    let own = [&preamble.left, &preamble.right][child];

    if let Some(mesh) = P::NATIVE_MESH {
        preamble.online_points[mesh.inherited[child].polynomial]
            .enforce_equal(dr, &own.online_points[mesh.outgoing])?;
    }

    let y = stages.lift(challenges::Y);
    let instance = own.nested_instance();
    let unified = instance.ky(dr, y)?;
    let binding = ky::binding_ky(dr, y, &own.bound())?;
    let (compute_v, online_helper) = ky::nested_online_ky::<_, _, P>(
        dr,
        y,
        &instance,
        &unified,
        &own.online_values,
        &ky::native_online_stages::<P, _>(|index| own[index].clone()),
        &own.online_points,
        &own.mesh,
    )?;

    let cells = &cells::<P>().children[child];
    let memory = &inputs.memory;
    let nested = [
        &own.nested.c,
        &own.nested.v,
        &own.nested.x,
        &own.nested.y,
        &own.nested.u,
    ];
    for (cell, value) in cells.nested.iter().zip(nested) {
        memory.store_element(dr, *cell, value)?;
    }
    memory.store_element(dr, cells.unified, &unified)?;
    memory.store_element(dr, cells.compute_v, &compute_v)?;
    assert_eq!(online_helper.is_some(), has_online_helper::<P>());
    if let (Some(cell), Some(value)) = (cells.online_helper, &online_helper) {
        memory.store_element(dr, cell, value)?;
    }
    assert_eq!(binding.is_some(), has_binding::<P>());
    if let (Some(cell), Some(value)) = (cells.binding, &binding) {
        memory.store_element(dr, cell, value)?;
    }
    Ok(())
}

/// The children's $k(y_n)$ values, as the two [`Child`](super::Step::Child)
/// steps stored them.
fn children_ky<'dr, D, C, P>(
    dr: &mut D,
    inputs: &Inputs<'_, 'dr, D, C, P>,
) -> Result<TwoProofKySource<'dr, D>>
where
    D: Driver<'dr, F = C::Base>,
    C: Affine,
    P: Profile,
{
    let [left, right] = cells::<P>().children;
    let memory = &inputs.memory;
    let mut load = |cell: ElementCell| memory.load_element(dr, cell);
    let left_raw_c = load(left.nested[super::nested_value::C])?;
    let right_raw_c = load(right.nested[super::nested_value::C])?;
    let left_unified = load(left.unified)?;
    let right_unified = load(right.unified)?;
    let left_compute_v = load(left.compute_v)?;
    let right_compute_v = load(right.compute_v)?;
    let left_online_helper = left.online_helper.map(&mut load).transpose()?;
    let right_online_helper = right.online_helper.map(&mut load).transpose()?;
    let left_binding = left.binding.map(&mut load).transpose()?;
    let right_binding = right.binding.map(&mut load).transpose()?;
    Ok(TwoProofKySource::new(
        dr,
        left_raw_c,
        right_raw_c,
        left_unified,
        right_unified,
        left_compute_v,
        right_compute_v,
        left_online_helper,
        right_online_helper,
        left_binding,
        right_binding,
    ))
}

/// Step [`Errors`](super::Step::Errors): layer one of the fold of the
/// children's claims for page `page` of the grid's groups, and on the last
/// page layer two.
///
/// - **Layer one.** For each group of the page, the fold of the
///   `inner_error` stage's error terms with the group's $k(y_n)$ values
///   under the lifted $\mu$ equals the collapsed value the `outer_error`
///   stage holds for the group. The groups are independent, so a page
///   takes nothing from the page before.
/// - **Layer two**, on the last page. The fold of the collapsed values
///   with the `outer_error` stage's error terms under the lifted $\mu'$ is
///   the folded $c_n$, which the step stores. The
///   [instance circuit](super::instance) holds the instance's $c_n$ to it
///   outside the base case.
///
/// The last page also stores the three commitments the two stages hold,
/// for the circuits that cannot load the stages.
pub fn errors<'dr, D, C, P>(
    dr: &mut D,
    inputs: &Inputs<'_, 'dr, D, C, P>,
    page: usize,
) -> Result<()>
where
    D: Driver<'dr, F = C::Base>,
    C: Affine,
    P: Profile,
{
    let stages = inputs.stages;
    let (inner_error, outer_error) = (stages.inner_error()?, stages.outer_error()?);
    let (groups, size) = grid::<P>();
    let page_groups = paging::range(ERROR_GROUPS, page, groups);
    let last = page_groups.end == groups;

    // The grid holds the claims' targets with the fold randomizer's.
    let ky = children_ky(dr, inputs)?;
    let zero = Element::zero(dr);
    let mut ky = revdot::randomized::<_, RevdotParameters<P>>(
        ky_values::<P, _>(&ky),
        zero.clone(),
        inner_error.randomizer_c.clone(),
        zero,
    )
    .skip(page_groups.start * size);

    // Layer 1: each group's fold must be the collapsed value witnessed.
    let fold = revdot::ClaimFolder::new(stages.lift(challenges::MU));
    for group in page_groups {
        let ky = FixedVec::from_fn(|_| ky.next().expect("the grid holds every node"));
        fold.fold_inner::<RevdotParameters<P>>(dr, &inner_error.error_terms[group], &ky)?
            .enforce_equal(dr, &outer_error.collapsed[group])?;
    }
    if !last {
        return Ok(());
    }

    // Layer 2: the fold of the collapsed values is c_n.
    let fold = revdot::ClaimFolder::new(stages.lift(challenges::MU_PRIME));
    let computed_c = fold.fold_outer::<RevdotParameters<P>>(
        dr,
        &outer_error.error_terms,
        &outer_error.collapsed,
    )?;
    let cells = cells::<P>();
    let memory = &inputs.memory;
    memory.store_element(dr, cells.c, &computed_c)?;
    memory.store_point(dr, cells.registry_wy, &inner_error.registry_wy)?;
    memory.store_point(
        dr,
        cells.native_inner_error,
        &inner_error.native_inner_error,
    )?;
    memory.store_point(
        dr,
        cells.native_outer_error,
        &outer_error.native_outer_error,
    )
}

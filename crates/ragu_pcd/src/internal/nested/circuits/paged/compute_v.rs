//! The steps that recompute the nested batch evaluation $v_n$: the parts
//! of the [`compute_v`](super::super::compute_v) circuit.

use alloc::vec::Vec;

use ragu_circuits::polynomials::{Rank, txz::Evaluate};
use ragu_core::{Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::{Element, GadgetExt as _};
use udon::curve::EndomorphismAffine as Affine;

use super::{EVALUATIONS, FOLD_GROUPS, Inputs, QUOTIENTS, Sizes, cells, grid, nested_value};
use crate::{
    internal::{
        inverter::Inverter,
        nested::{
            InternalCircuitIndex, RevdotParameters,
            circuits::compute_v::{At, EvaluationProcessor, EvaluationSource, poly_queries},
            claims::{self, Processor},
            stages::challenges,
        },
        paging::{self, ElementHorner},
        revdot::EvaluationFolder,
    },
    profile::{Profile, online::circuit::mul_pow},
};

/// Collects the mask claims' folds under $z_n$, in claim order, and
/// passes over every other claim.
struct MaskFolds<'a, 'dr, D: Driver<'dr>> {
    dr: &'a mut D,
    z: &'a Element<'dr, D>,
    folds: Vec<Element<'dr, D>>,
}

impl<'a, 'dr, D: Driver<'dr>, P: Profile> Processor<P, &'a Element<'dr, D>>
    for MaskFolds<'a, 'dr, D>
{
    fn raw_claim(&mut self, _: &'a Element<'dr, D>, _: &'a Element<'dr, D>) {}

    fn internal_circuit_claim(
        &mut self,
        _: InternalCircuitIndex,
        _: impl Iterator<Item = &'a Element<'dr, D>>,
    ) {
    }

    fn mask_claim(
        &mut self,
        _: InternalCircuitIndex,
        rxs: impl Iterator<Item = &'a Element<'dr, D>>,
    ) -> Result<()> {
        self.folds.push(Element::fold(self.dr, rxs, self.z)?);
        Ok(())
    }
}

/// Step [`Masks`](super::Step::Masks): each mask claim's $a$ side at
/// $x_n z_n$, the fold under $z_n$ of the evaluations of the polynomials
/// the mask covers, into the memory for the pages of
/// [`Fold`](super::Step::Fold).
///
/// A mask claim's fold costs a gate for each polynomial the mask covers,
/// against none for a circuit claim's sum, so the folds are apart from the
/// pages that fold the grid.
///
/// The step also stores the commitments the `query` stage holds, for the
/// circuits that cannot load the stage.
pub fn masks<'dr, D, C, P>(dr: &mut D, inputs: &Inputs<'_, 'dr, D, C, P>) -> Result<()>
where
    D: Driver<'dr, F = C::Base>,
    C: Affine,
    P: Profile,
{
    let stages = inputs.stages;
    let query = stages.query()?;
    let source = EvaluationSource {
        left: &query.nested.left,
        right: &query.nested.right,
    };
    let folds = {
        let mut folds = MaskFolds {
            dr: &mut *dr,
            z: stages.lift(challenges::Z),
            folds: Vec::new(),
        };
        claims::build::<P, _, _>(&source, &mut folds)?;
        folds.folds
    };

    let cells = cells::<P>();
    let memory = &inputs.memory;
    assert_eq!(
        folds.len(),
        cells.masks.len(),
        "a cell for every mask claim"
    );
    for (cell, fold) in cells.masks.iter().zip(&folds) {
        memory.store_element(dr, *cell, fold)?;
    }
    memory.store_point(dr, cells.native_query, &query.native_query)?;
    memory.store_point(dr, cells.registry_xy, &query.registry_xy)?;
    for (cell, point) in cells.query_online_points.iter().zip(&*query.online_points) {
        memory.store_point(dr, *cell, point)?;
    }
    for (cell, point) in cells.query_online_stage.iter().zip(&*query.online_stage) {
        memory.store_point(dr, *cell, point)?;
    }
    Ok(())
}

/// Step [`Fold`](super::Step::Fold): the part of $a_n(x_n z_n)$ and of
/// $b_n(x_n)$ that page `page` of the grid's groups holds, added to the
/// part of the pages before.
///
/// The two values are the two-layer fold of the claims' evaluations
/// ([`EvaluationFolder`]). The fold is a sum over the grid's groups, so a
/// page adds its groups' terms ([`EvaluationFolder::fold_groups`]) to the
/// sums the page before stored, and stores the new sums. The last page
/// adds the last group's term, which holds the fold randomizer's alone,
/// and its two cells hold $a_n(x_n z_n)$ and $b_n(x_n)$.
///
/// The page builds the entries of its own groups' claims as the compute-v
/// circuit does, and takes each mask claim's fold from the memory.
pub fn fold<'dr, D, C, R, P>(
    dr: &mut D,
    inputs: &Inputs<'_, 'dr, D, C, P>,
    page: usize,
) -> Result<()>
where
    D: Driver<'dr, F = C::Base>,
    C: Affine,
    R: Rank,
    P: Profile,
{
    let stages = inputs.stages;
    let query = &stages.query()?.nested;
    let cells = cells::<P>();
    let memory = &inputs.memory;
    let (groups, size) = grid::<P>();
    // Every group but the last holds claims.
    let page_groups = paging::range(FOLD_GROUPS, page, groups - 1);
    let last = page_groups.end == groups - 1;

    // t(x_n z_n), the vanishing polynomial at x_n z_n.
    let x = stages.lift(challenges::X).enforce_invertible(dr)?;
    let z = stages.lift(challenges::Z).enforce_invertible(dr)?;
    let txz = dr.routine(Evaluate::<R>::new(), (x.clone(), z.clone()))?;

    let masks = cells
        .masks
        .iter()
        .map(|&cell| memory.load_element(dr, cell))
        .collect::<Result<Vec<_>>>()?;
    let source = EvaluationSource {
        left: &query.left,
        right: &query.right,
    };
    let (ax, bx) = {
        let claims = page_groups.start * (size - 1)..page_groups.end * (size - 1);
        let mut processor =
            EvaluationProcessor::over(dr, z.element(), &txz, &query.fixed_registry, claims, &masks);
        claims::build::<P, _, _>(&source, &mut processor)?;
        processor.build()
    };

    let folder = EvaluationFolder::<_, RevdotParameters<P>>::new(
        dr,
        stages.lift(challenges::MU),
        stages.lift(challenges::MU_PRIME),
    )?;
    let mut a = folder.fold_groups(dr, &ax, page_groups.clone(), &query.randomizer_a_at_xz)?;
    let mut b = folder.fold_groups(dr, &bx, page_groups, &query.randomizer_b_at_x)?;
    if let Some(before) = page.checked_sub(1) {
        let [a_before, b_before] = cells.fold[before];
        let a_before = memory.load_element(dr, a_before)?;
        let b_before = memory.load_element(dr, b_before)?;
        a = a.add(dr, &a_before);
        b = b.add(dr, &b_before);
    }
    if last {
        let a_last = folder.fold_a_last(dr, &query.randomizer_a_at_xz)?;
        a = a.add(dr, &a_last);
    }
    let [a_cell, b_cell] = cells.fold[page];
    memory.store_element(dr, a_cell, &a)?;
    memory.store_element(dr, b_cell, &b)
}

/// Step [`Quotients`](super::Step::Quotients): the part of $f_n(u_n)$ that
/// page `page` of the openings holds.
///
/// $f_n(u_n)$ is the Horner fold under the lifted $\alpha$ of the
/// quotients $(p_i(u_n) - v_i) / (u_n - x_i)$ of every opening, in the
/// order of [`poly_queries`]. A page takes the fold of the pages before
/// from its cell, folds its own openings' quotients onto it
/// ([`ElementHorner`]) and stores the result. It inverts the denominators
/// of its own openings alone.
///
/// The last page shifts the fold below the online batch's terms and adds
/// the online helper's quotient sum, which the prover supplies, as the
/// compute-v circuit does; its cell holds $f_n(u_n)$.
pub fn quotients<'dr, D, C, P>(
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
    let (query, eval) = (&stages.query()?.nested, &stages.eval()?.nested);
    let cells = cells::<P>();
    let memory = &inputs.memory;
    let [left, right] = &cells.children;

    let left_v = memory.load_element(dr, left.nested[nested_value::V])?;
    let right_v = memory.load_element(dr, right.nested[nested_value::V])?;
    let [a_cell, b_cell] = *cells.fold.last().expect("the fold has a page");
    let computed_ax = memory.load_element(dr, a_cell)?;
    let computed_bx = memory.load_element(dr, b_cell)?;
    let openings: Vec<_> =
        poly_queries(eval, query, &left_v, &right_v, &computed_ax, &computed_bx).collect();
    assert_eq!(
        openings.len(),
        Sizes::of::<P>().openings,
        "the pages are cut over every opening"
    );
    let range = paging::range(QUOTIENTS, page, openings.len());
    let last = range.end == openings.len();
    let openings = &openings[range];

    // The inverted denominators the page's openings take, each once.
    let internal = InternalCircuitIndex::all::<P>();
    let mut inverter = Inverter::with_base(stages.lift(challenges::U).clone());
    let mut points: Vec<At> = Vec::new();
    for &(_, _, at) in openings {
        if points.contains(&at) {
            continue;
        }
        let mut child = |dr: &mut D, cell| {
            let value = memory.load_element(dr, cell)?;
            inverter.add(dr, &value)
        };
        match at {
            At::LeftU => child(dr, left.nested[nested_value::U])?,
            At::LeftY => child(dr, left.nested[nested_value::Y])?,
            At::LeftX => child(dr, left.nested[nested_value::X])?,
            At::RightU => child(dr, right.nested[nested_value::U])?,
            At::RightY => child(dr, right.nested[nested_value::Y])?,
            At::RightX => child(dr, right.nested[nested_value::X])?,
            At::W => inverter.add(dr, stages.lift(challenges::W))?,
            At::X => inverter.add(dr, stages.lift(challenges::X))?,
            At::Y => inverter.add(dr, stages.lift(challenges::Y))?,
            At::Xz => {
                let xz = stages
                    .lift(challenges::X)
                    .mul(dr, stages.lift(challenges::Z))?;
                inverter.add(dr, &xz)?
            }
            At::Internal(j) => inverter.add_circuit(dr, internal[j].circuit_index::<P>())?,
        };
        points.push(at);
    }
    let inverted = inverter.invert(dr)?;
    let quotients = openings
        .iter()
        .map(|&(evaluated, value, at)| {
            let inverse = points
                .iter()
                .position(|&point| point == at)
                .expect("every opening's denominator was inverted");
            evaluated.sub(dr, value).mul(dr, &inverted[inverse])
        })
        .collect::<Result<Vec<_>>>()?;

    let alpha = stages.lift(challenges::ALPHA);
    let before = match page.checked_sub(1) {
        Some(before) => memory.load_element(dr, cells.quotients[before])?,
        None => Element::zero(dr),
    };
    let mut fu = paging::fold(dr, &ElementHorner::new(alpha), before, &quotients)?;
    if last && !P::NESTED_ONLINE.is_empty() {
        let online = memory.advise_element(
            dr,
            cells.online_fold[0],
            inputs.online_fold.as_ref().map(|fold| fold[0]),
        )?;
        fu = mul_pow(dr, &fu, alpha, P::NESTED_ONLINE.openings.len())?.add(dr, &online);
    }
    memory.store_element(dr, cells.quotients[page], &fu)
}

/// Step [`Evaluations`](super::Step::Evaluations): the part of $v_n$ that
/// page `page` of the evaluations holds.
///
/// $v_n$ is the Horner fold under $\beta_n$, the challenge stage's lift of
/// `pre_beta`, of $f_n(u_n)$ and then the `eval` stage's nested
/// evaluations in the order the stage writes them. A page takes the fold
/// of the pages before from its cell, folds its own evaluations onto it
/// and stores the result.
///
/// The last page shifts the fold below the online batch's terms and adds
/// the online helper's evaluation sum, which the prover supplies; its
/// cell holds $v_n$, which the [instance circuit](super::instance)
/// provides as the instance's.
///
/// The first page also stores the commitments the `eval` stage holds.
pub fn evaluations<'dr, D, C, P>(
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
    let eval = stages.eval()?;
    let cells = cells::<P>();
    let memory = &inputs.memory;

    let fu = memory.load_element(dr, *cells.quotients.last().expect("f has a page"))?;
    let mut evaluations: Vec<Element<'dr, D>> = Vec::new();
    fu.write(dr, &mut evaluations)?;
    eval.nested.write(dr, &mut evaluations)?;
    assert_eq!(
        evaluations.len(),
        Sizes::of::<P>().evaluations,
        "the pages are cut over every evaluation"
    );
    let range = paging::range(EVALUATIONS, page, evaluations.len());
    let last = range.end == evaluations.len();

    let beta = &stages.challenges.beta.lift;
    let before = match page.checked_sub(1) {
        Some(before) => memory.load_element(dr, cells.evaluations[before])?,
        None => Element::zero(dr),
    };
    let mut v = paging::fold(dr, &ElementHorner::new(beta), before, &evaluations[range])?;
    if last && !P::NESTED_ONLINE.is_empty() {
        let online = memory.advise_element(
            dr,
            cells.online_fold[1],
            inputs.online_fold.as_ref().map(|fold| fold[1]),
        )?;
        v = mul_pow(dr, &v, beta, P::NESTED_ONLINE.polynomials.len())?.add(dr, &online);
    }
    memory.store_element(dr, cells.evaluations[page], &v)?;

    if page == 0 {
        memory.store_point(dr, cells.native_eval, &eval.native_eval)?;
        for (cell, point) in cells.eval_online_stage.iter().zip(&*eval.online_stage) {
            memory.store_point(dr, *cell, point)?;
        }
    }
    Ok(())
}

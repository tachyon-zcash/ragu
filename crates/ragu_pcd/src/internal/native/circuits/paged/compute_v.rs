//! The steps that recompute the batch evaluation $v$: the parts of the
//! [`compute_v`](super::super::compute_v) circuit.

use alloc::vec::Vec;

use ragu_circuits::polynomials::{Rank, txz::Evaluate};
use ragu_core::{Error, Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::{Element, GadgetExt as _};

use super::{Challenges, EVALUATIONS, FOLD_GROUPS, Inputs, QUOTIENTS, Sizes, cells, grid};
use crate::{
    internal::{
        inverter::Inverter,
        native::{
            InternalCircuitIndex, RevdotParameters,
            circuits::compute_v::{At, EvaluationProcessor, EvaluationSource, poly_queries},
            claims::{self, Processor},
        },
        paging::{self, ElementHorner},
        revdot::EvaluationFolder,
    },
    profile::{Profile, ProfiledCycle, online::circuit::mul_pow},
};

/// Step [`Challenges`](super::Step::Challenges): the challenges the other
/// steps compute with, from the unified instance into the memory.
///
/// The step runs where the unified instance is at hand, in the
/// [export circuit](super::export), which reads each challenge off the
/// instance and derives $\beta$ from `pre_beta` as the compute-v circuit
/// does. Each cell is held to the wire the circuit read.
pub fn challenges<'dr, D, C, const HEADER_SIZE: usize>(
    dr: &mut D,
    inputs: &Inputs<'_, 'dr, D, C, HEADER_SIZE>,
) -> Result<()>
where
    D: Driver<'dr, F = C::CircuitField>,
    C: ProfiledCycle,
{
    let challenges = inputs.challenges.ok_or_else(|| {
        Error::Initialization("the challenges are stored where the unified instance is".into())
    })?;
    let cells = cells::<C::Profile>().challenges;
    for (cell, challenge) in cells.each().into_iter().zip(challenges.each()) {
        inputs.memory.store_element(dr, *cell, challenge)?;
    }
    Ok(())
}

/// The challenges, as [`Challenges`](super::Step::Challenges) stored them.
fn load_challenges<'dr, D, C, const HEADER_SIZE: usize>(
    dr: &mut D,
    inputs: &Inputs<'_, 'dr, D, C, HEADER_SIZE>,
) -> Result<Challenges<Element<'dr, D>>>
where
    D: Driver<'dr, F = C::CircuitField>,
    C: ProfiledCycle,
{
    let cells = cells::<C::Profile>().challenges;
    let each = cells.each();
    Challenges::from_each(|i| inputs.memory.load_element(dr, *each[i]))
}

/// Collects the mask claims' folds under $z$, in claim order, and passes
/// over every other claim.
struct MaskFolds<'a, 'dr, D: Driver<'dr>> {
    dr: &'a mut D,
    z: &'a Element<'dr, D>,
    folds: Vec<Element<'dr, D>>,
}

impl<'a, 'dr, D: Driver<'dr>, P: Profile> Processor<P, &'a Element<'dr, D>, &'a Element<'dr, D>>
    for MaskFolds<'a, 'dr, D>
{
    fn raw_claim(&mut self, _: &'a Element<'dr, D>, _: &'a Element<'dr, D>) {}

    fn circuit_claim(
        &mut self,
        _: &'a Element<'dr, D>,
        _: impl Iterator<Item = &'a Element<'dr, D>>,
    ) {
    }

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

/// The claims' evaluations, as the `query` stage holds them.
fn source<'a, 'dr, D: Driver<'dr>, P: Profile>(
    query: &'a crate::internal::native::stages::query::Output<'dr, D, P>,
) -> EvaluationSource<'a, 'dr, D, P> {
    EvaluationSource {
        left: &query.left,
        right: &query.right,
        application: (
            &query.registry_xy_at_circuit_id,
            [&query.application_at_xz, &query.application_stage_at_xz],
        ),
    }
}

/// Step [`Masks`](super::Step::Masks): each mask claim's $a$ side at $xz$,
/// the fold under $z$ of the evaluations of the polynomials the mask
/// covers, into the memory for the pages of [`Fold`](super::Step::Fold).
///
/// A mask claim's fold costs a gate for each polynomial the mask covers,
/// against none for a circuit claim's sum, so the folds are apart from the
/// pages that fold the grid.
pub fn masks<'dr, D, C, const HEADER_SIZE: usize>(
    dr: &mut D,
    inputs: &Inputs<'_, 'dr, D, C, HEADER_SIZE>,
) -> Result<()>
where
    D: Driver<'dr, F = C::CircuitField>,
    C: ProfiledCycle,
{
    let query = inputs.stages.query()?;
    let challenges = load_challenges(dr, inputs)?;
    let folds = {
        let mut folds = MaskFolds {
            dr: &mut *dr,
            z: &challenges.z,
            folds: Vec::new(),
        };
        claims::build::<C::Profile, _, _>(&source(query), &mut folds)?;
        folds.folds
    };
    let cells = cells::<C::Profile>();
    assert_eq!(
        folds.len(),
        cells.masks.len(),
        "a cell for every mask claim"
    );
    for (cell, fold) in cells.masks.iter().zip(&folds) {
        inputs.memory.store_element(dr, *cell, fold)?;
    }
    Ok(())
}

/// Step [`Fold`](super::Step::Fold): the part of $a(xz)$ and of $b(x)$
/// that page `page` of the grid's groups holds, added to the part of the
/// pages before.
///
/// The two values are the two-layer fold of the claims' evaluations
/// ([`EvaluationFolder`]), a sum over the grid's groups. A page adds its
/// groups' terms ([`EvaluationFolder::fold_groups`]) to the sums the page
/// before stored, and stores the new sums. The last page adds the last
/// group's term, which holds the fold randomizer's alone, and its two
/// cells hold $a(xz)$ and $b(x)$.
///
/// The page builds the entries of its own groups' claims as the compute-v
/// circuit does, and takes each mask claim's fold from the memory.
pub fn fold<'dr, D, C, R, const HEADER_SIZE: usize>(
    dr: &mut D,
    inputs: &Inputs<'_, 'dr, D, C, HEADER_SIZE>,
    page: usize,
) -> Result<()>
where
    D: Driver<'dr, F = C::CircuitField>,
    C: ProfiledCycle,
    R: Rank,
{
    let query = inputs.stages.query()?;
    let cells = cells::<C::Profile>();
    let memory = &inputs.memory;
    let challenges = load_challenges(dr, inputs)?;
    let (groups, size) = grid::<C::Profile>();
    // Every group but the last holds claims.
    let page_groups = paging::range(FOLD_GROUPS, page, groups - 1);
    let last = page_groups.end == groups - 1;

    // t(xz), the vanishing polynomial evaluated at xz.
    let x = challenges.x.enforce_invertible(dr)?;
    let z = challenges.z.enforce_invertible(dr)?;
    let txz = dr.routine(Evaluate::<R>::new(), (x.clone(), z.clone()))?;

    let masks = cells
        .masks
        .iter()
        .map(|&cell| memory.load_element(dr, cell))
        .collect::<Result<Vec<_>>>()?;
    let source = source(query);
    let (ax, bx) = {
        let claims = page_groups.start * (size - 1)..page_groups.end * (size - 1);
        let mut processor =
            EvaluationProcessor::over(dr, z.element(), &txz, &query.fixed_registry, claims, &masks);
        claims::build::<C::Profile, _, _>(&source, &mut processor)?;
        processor.build()
    };

    let folder = EvaluationFolder::<_, RevdotParameters<C::Profile>>::new(
        dr,
        &challenges.mu,
        &challenges.mu_prime,
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

/// Step [`Quotients`](super::Step::Quotients): the part of $f(u)$ that
/// page `page` of the openings holds.
///
/// $f(u)$ is the Horner fold under $\alpha$ of the quotients
/// $(p_i(u) - v_i) / (u - x_i)$ of every opening, in the order of
/// [`poly_queries`]. A page takes the fold of the pages before from its
/// cell, folds its own openings' quotients onto it ([`ElementHorner`]) and
/// stores the result. It inverts the denominators of its own openings
/// alone.
///
/// The last page shifts the fold below the online batch's terms and adds
/// the online helper's quotient sum, which the prover supplies, as the
/// compute-v circuit does; its cell holds $f(u)$.
pub fn quotients<'dr, D, C, const HEADER_SIZE: usize>(
    dr: &mut D,
    inputs: &Inputs<'_, 'dr, D, C, HEADER_SIZE>,
    page: usize,
) -> Result<()>
where
    D: Driver<'dr, F = C::CircuitField>,
    C: ProfiledCycle,
{
    let stages = inputs.stages;
    let (query, eval) = (stages.query()?, &stages.eval()?.evaluations);
    let preamble = &stages.preamble;
    let cells = cells::<C::Profile>();
    let memory = &inputs.memory;
    let challenges = load_challenges(dr, inputs)?;

    let [a_cell, b_cell] = *cells.fold.last().expect("the fold has a page");
    let computed_ax = memory.load_element(dr, a_cell)?;
    let computed_bx = memory.load_element(dr, b_cell)?;
    let openings: Vec<_> =
        poly_queries::<_, C, HEADER_SIZE>(eval, query, preamble, &computed_ax, &computed_bx)
            .collect();
    assert_eq!(
        openings.len(),
        Sizes::of::<C::Profile>().openings,
        "the pages are cut over every opening"
    );
    let range = paging::range(QUOTIENTS, page, openings.len());
    let last = range.end == openings.len();
    let openings = &openings[range];

    // The inverted denominators the page's openings take, each once.
    let mut inverter = Inverter::with_base(challenges.u.clone());
    let mut points: Vec<At> = Vec::new();
    for &(_, _, at) in openings {
        if points.contains(&at) {
            continue;
        }
        match at {
            At::LeftU => inverter.add(dr, &preamble.left.unified.u)?,
            At::LeftY => inverter.add(dr, &preamble.left.unified.y)?,
            At::LeftX => inverter.add(dr, &preamble.left.unified.x)?,
            At::RightU => inverter.add(dr, &preamble.right.unified.u)?,
            At::RightY => inverter.add(dr, &preamble.right.unified.y)?,
            At::RightX => inverter.add(dr, &preamble.right.unified.x)?,
            At::W => inverter.add(dr, &challenges.w)?,
            At::X => inverter.add(dr, &challenges.x)?,
            At::Y => inverter.add(dr, &challenges.y)?,
            At::Xz => {
                let xz = challenges.x.mul(dr, &challenges.z)?;
                inverter.add(dr, &xz)?
            }
            At::CircuitId => inverter.add(dr, &preamble.own.circuit_id)?,
            At::Internal(id) => inverter.add_circuit(dr, id.circuit_index::<C::Profile>())?,
            At::Online(i) => inverter.add(dr, &preamble.own.online[i].x)?,
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

    let alpha = &challenges.alpha;
    let before = match page.checked_sub(1) {
        Some(before) => memory.load_element(dr, cells.quotients[before])?,
        None => Element::zero(dr),
    };
    let mut fu = paging::fold(dr, &ElementHorner::new(alpha), before, &quotients)?;
    if last && !C::Profile::NATIVE_ONLINE.is_empty() {
        let online = memory.advise_element(
            dr,
            cells.online_fold[0],
            inputs.online_fold.as_ref().map(|fold| fold[0]),
        )?;
        fu = mul_pow(dr, &fu, alpha, C::Profile::NATIVE_ONLINE.openings.len())?.add(dr, &online);
    }
    memory.store_element(dr, cells.quotients[page], &fu)
}

/// Step [`Evaluations`](super::Step::Evaluations): the part of $v$ that
/// page `page` of the evaluations holds.
///
/// $v$ is the Horner fold under $\beta$ of $f(u)$ and then the `eval`
/// stage's evaluations in the order the stage writes them. A page takes
/// the fold of the pages before from its cell, folds its own evaluations
/// onto it and stores the result.
///
/// The last page shifts the fold below the online batch's terms and adds
/// the online helper's evaluation sum, which the prover supplies; its
/// cell holds $v$, which the [export circuit](super::export) provides as
/// the instance's.
pub fn evaluations<'dr, D, C, const HEADER_SIZE: usize>(
    dr: &mut D,
    inputs: &Inputs<'_, 'dr, D, C, HEADER_SIZE>,
    page: usize,
) -> Result<()>
where
    D: Driver<'dr, F = C::CircuitField>,
    C: ProfiledCycle,
{
    let eval = &inputs.stages.eval()?.evaluations;
    let cells = cells::<C::Profile>();
    let memory = &inputs.memory;
    let challenges = load_challenges(dr, inputs)?;

    let fu = memory.load_element(dr, *cells.quotients.last().expect("f has a page"))?;
    let mut evaluations: Vec<Element<'dr, D>> = Vec::new();
    fu.write(dr, &mut evaluations)?;
    eval.write(dr, &mut evaluations)?;
    assert_eq!(
        evaluations.len(),
        Sizes::of::<C::Profile>().evaluations,
        "the pages are cut over every evaluation"
    );
    let range = paging::range(EVALUATIONS, page, evaluations.len());
    let last = range.end == evaluations.len();

    let beta = &challenges.beta;
    let before = match page.checked_sub(1) {
        Some(before) => memory.load_element(dr, cells.evaluations[before])?,
        None => Element::zero(dr),
    };
    let mut v = paging::fold(dr, &ElementHorner::new(beta), before, &evaluations[range])?;
    if last && !C::Profile::NATIVE_ONLINE.is_empty() {
        let online = memory.advise_element(
            dr,
            cells.online_fold[1],
            inputs.online_fold.as_ref().map(|fold| fold[1]),
        )?;
        v = mul_pow(dr, &v, beta, C::Profile::NATIVE_ONLINE.polynomials.len())?.add(dr, &online);
    }
    memory.store_element(dr, cells.evaluations[page], &v)
}

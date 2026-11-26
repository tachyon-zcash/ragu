//! The nested instance circuits of a profile that lays its stages side by
//! side, as a program of step circuits.
//!
//! The standard profile's [`collapse`](super::collapse) and
//! [`compute_v`](super::compute_v) circuits each load every nested stage.
//! A profile with a large extension has stages that do not fit one trace
//! together ([`layout`](crate::internal::nested::layout)), and work that
//! does not fit one circuit. Such a profile checks the same statement with
//! the circuits of this module:
//!
//! - A [`program`] of [`Step`]s, each a circuit
//!   that loads the trunk and one branch of the layout and exposes nothing.
//!   What a step computes for another step it stores in the program's
//!   memory, a stage of the trunk.
//! - [`instance::Circuit`], in the collapse circuit's place: it exposes the
//!   nested unified instance and holds every slot of it, to a stage it
//!   loads or to a memory cell a step stored.
//! - [`export::Circuit`], in the compute-v circuit's place: it exposes the
//!   unified instance again, and after it the online values that the
//!   compute-v circuit exposes.
//!
//! # The steps
//!
//! [`schedule`] lists the steps of a profile in order. Each kind of step
//! is one part of a standard circuit, and the list below names the part.
//!
//! | Step | Branch | Part |
//! |---|---|---|
//! | [`Step::Child`] | `preamble` | collapse: a child's $k(y_n)$ values; compute-v: the mesh tie |
//! | [`Step::Errors`] | `inner_error`, `outer_error` | collapse: layer one for a page of groups; the last page also folds layer two |
//! | [`Step::Masks`] | `query` | compute-v: the mask claims' folds under $z_n$ |
//! | [`Step::Fold`] | `query` | compute-v: $a_n(x_n z_n)$ and $b_n(x_n)$ for a page of groups |
//! | [`Step::Quotients`] | `query`, `eval` | compute-v: $f_n(u_n)$ for a page of openings |
//! | [`Step::Evaluations`] | `query`, `eval` | compute-v: $v_n$ for a page of evaluations |
//! | [`Step::Walk`] | `preamble` and a points group | collapse: a group of the walk's points |
//!
//! The pages are cut with [`paging::range`] at the capacities this module
//! pins. A page whose state crosses to the next page keeps it in a memory
//! cell: the next page loads the cell of the page before, continues, and
//! stores its own.
//!
//! # What holds the cut statement together
//!
//! The steps are sound as one statement under the conditions of a
//! [program](crate::internal::program#soundness): every step is a
//! registered circuit whose claim the parent folds
//! ([`InternalCircuitIndex::Step`]), every step and both instance circuits
//! read one memory polynomial, and each cell is defined once. The memory's
//! tests pin, from a run's [`Report`](program::Report), which step defines
//! each cell and which cells the prover supplies.
//!
//! [`InternalCircuitIndex::Step`]: crate::internal::nested::InternalCircuitIndex::Step

use alloc::{vec, vec::Vec};
use core::{cell::RefCell, marker::PhantomData};

use ragu_circuits::{
    WithAux,
    polynomials::Rank,
    staging::{MultiStageCircuit, StageBuilder, StageGuard},
};
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue, emulator::Emulator},
    gadgets::{Bound, Kind},
    maybe::{Always, Maybe},
};
use ragu_primitives::{
    Element, HoistedEndoscalar,
    vec::{FixedVec, Len},
};
use udon::curve::EndomorphismAffine as Affine;

use super::common;
use crate::{
    internal::{
        endoscalar::EndoscalarStage,
        nested::{
            self, FOLD_GROUP_SIZE, InternalCircuitIndex, Links, LinksStage, MemoryStage,
            NumFoldGroups, Points, PointsStage, stages, walk_grouping,
        },
        paging,
        program::{self, ElementCell, Layout, Log, Memory, PointCell, Program, Values},
    },
    profile::{
        Profile,
        online::stages::{Native, Nested, PhaseLen, Present},
    },
};

pub mod collapse;
pub mod compute_v;
pub mod export;
pub mod instance;
pub mod walk;

/// The groups of the claims' grid a page of [`Step::Errors`] folds in
/// layer one.
///
/// The capacities below are the page sizes at which every step fits a
/// trace of the wallet rank with as many polynomials as the aggregator's
/// extension adds. The room a step has is what the trunk and its branch
/// leave, which shrinks as a profile's polynomials grow, so a capacity is
/// a property of the largest paged profile and not of the unit it counts.
/// Setup refuses a step that outgrows the rank, and the internal census
/// holds every step to the rank at that size.
///
/// A group of layer one takes about seventeen gates. The last page also
/// folds layer two, which takes about five gates for each group of the
/// grid.
pub const ERROR_GROUPS: usize = 60;

/// The groups of the claims' grid a page of [`Step::Fold`] folds, at about
/// twenty gates a group beside the two bases the page builds.
pub const FOLD_GROUPS: usize = 36;

/// The openings a page of [`Step::Quotients`] folds into $f_n(u_n)$: two
/// gates an opening, and a third for an opening whose denominator no
/// other opening of the page shares, as every opening at an internal
/// circuit's $\omega^j$ is.
pub const QUOTIENTS: usize = 215;

/// The evaluations a page of [`Step::Evaluations`] folds into $v_n$, a
/// gate each.
pub const EVALUATIONS: usize = 650;

/// One step of the program: one circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// The $k(y_n)$ values of child `child` (zero for the left one, one for
    /// the right) and the child's nested values, from the `preamble`
    /// stage. See [`collapse::child`].
    Child { child: usize },
    /// Layer one of the fold of the children's claims for page `page` of
    /// the grid's groups, and layer two on the last page. See
    /// [`collapse::errors`].
    Errors { page: usize },
    /// The mask claims' folds under $z_n$. See [`compute_v::masks`].
    Masks,
    /// The part of $a_n(x_n z_n)$ and $b_n(x_n)$ that page `page` of the
    /// grid's groups holds. See [`compute_v::fold`].
    Fold { page: usize },
    /// The part of $f_n(u_n)$ that page `page` of the openings holds. See
    /// [`compute_v::quotients`].
    Quotients { page: usize },
    /// The part of $v_n$ that page `page` of the evaluations holds. See
    /// [`compute_v::evaluations`].
    Evaluations { page: usize },
    /// The points of group `group` of the walk. See [`walk::group`].
    Walk { group: usize },
}

/// The branch of the layout a circuit loads after the trunk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Branch {
    /// The `preamble` stage.
    Preamble,
    /// The `inner_error` and `outer_error` stages.
    Errors,
    /// The `query` stage.
    Query,
    /// The `query` and `eval` stages.
    Eval,
}

impl Step {
    /// The branch the step's circuit loads.
    pub fn branch(self) -> Branch {
        match self {
            Step::Child { .. } | Step::Walk { .. } => Branch::Preamble,
            Step::Errors { .. } => Branch::Errors,
            Step::Masks | Step::Fold { .. } => Branch::Query,
            Step::Quotients { .. } | Step::Evaluations { .. } => Branch::Eval,
        }
    }

    /// The group of the walk whose points stage the step's circuit loads.
    pub fn group(self) -> Option<usize> {
        match self {
            Step::Walk { group } => Some(group),
            _ => None,
        }
    }
}

/// The sizes the page counts of profile `P` follow from.
pub struct Sizes {
    /// The groups of the claims' grid, the last of which holds no claim.
    pub groups: usize,
    /// The mask claims, which are the last of the claims.
    pub masks: usize,
    /// The openings $f_n$ covers.
    pub openings: usize,
    /// The evaluations $v_n$ sums, $f_n(u_n)$ first.
    pub evaluations: usize,
    /// The groups of the walk.
    pub walk_groups: usize,
}

impl Sizes {
    /// The sizes of profile `P`.
    pub fn of<P: Profile>() -> Self {
        let internal = InternalCircuitIndex::all::<P>();
        Sizes {
            groups: NumFoldGroups::<P>::len(),
            masks: internal.iter().filter(|id| id.is_mask()).count(),
            openings: nested::pcs::STATIC_F_QUERIES.len()
                + 2 * nested::RxIndex::num::<P>()
                + internal.len(),
            // f_n(u_n), then each child's rx polynomials, a, b, registry_xy
            // and p, then the step's own nine.
            evaluations: 1 + 2 * (nested::pcs::OwnRxLen::<P>::len() + 4) + 9,
            walk_groups: walk_grouping::<P>().groups(),
        }
    }

    /// The pages of [`Step::Errors`]: the grid's groups at
    /// [`ERROR_GROUPS`] a page.
    pub fn error_pages(&self) -> usize {
        paging::num_pages(ERROR_GROUPS, self.groups)
    }

    /// The pages of [`Step::Fold`]: the grid's groups but the last at
    /// [`FOLD_GROUPS`] a page.
    pub fn fold_pages(&self) -> usize {
        paging::num_pages(FOLD_GROUPS, self.groups - 1)
    }

    /// The pages of [`Step::Quotients`].
    pub fn quotient_pages(&self) -> usize {
        paging::num_pages(QUOTIENTS, self.openings)
    }

    /// The pages of [`Step::Evaluations`].
    pub fn evaluation_pages(&self) -> usize {
        paging::num_pages(EVALUATIONS, self.evaluations)
    }
}

/// The steps of the program of profile `P`, in order.
///
/// The order is the order of the prover's run: a step loads only cells
/// that an earlier step defined.
pub fn schedule<P: Profile>() -> Vec<Step> {
    let sizes = Sizes::of::<P>();
    let mut steps = vec![Step::Child { child: 0 }, Step::Child { child: 1 }];
    steps.extend((0..sizes.error_pages()).map(|page| Step::Errors { page }));
    steps.push(Step::Masks);
    steps.extend((0..sizes.fold_pages()).map(|page| Step::Fold { page }));
    steps.extend((0..sizes.quotient_pages()).map(|page| Step::Quotients { page }));
    steps.extend((0..sizes.evaluation_pages()).map(|page| Step::Evaluations { page }));
    steps.extend((0..sizes.walk_groups).map(|group| Step::Walk { group }));
    steps
}

/// The steps of the program that are not a group of the walk: what
/// [`Profile::NESTED_STEPS`] pins.
pub fn num_fixed_steps<P: Profile>() -> usize {
    schedule::<P>()
        .iter()
        .filter(|step| !matches!(step, Step::Walk { .. }))
        .count()
}

/// The memory of the program of profile `P`: the [`program::Shape`] of
/// [`MemoryStage`].
pub struct Cells<P>(PhantomData<fn() -> P>);

impl<P: Profile> program::Shape for Cells<P> {
    const NAME: &'static str = "nested fuse";

    fn points() -> usize {
        layout::<P>().1.num_points()
    }

    fn elements() -> usize {
        layout::<P>().1.num_elements()
    }
}

/// The cells one [`Step::Child`] stores.
pub struct ChildCells {
    /// The child's nested $c$, $v$, $x$, $y$ and $u$, in that order.
    pub nested: [ElementCell; 5],
    /// The $k(y_n)$ of the child's nested unified instance.
    pub unified: ElementCell,
    /// The $k(y_n)$ of the child's compute-v claim.
    pub compute_v: ElementCell,
    /// The $k(y_n)$ of the child's online helper claim, for a profile with
    /// a nested online batch.
    pub online_helper: Option<ElementCell>,
    /// The $k(y_n)$ of the child's binding claim, for a profile whose
    /// nested extension has a binding circuit.
    pub binding: Option<ElementCell>,
}

/// The position of a value among [`ChildCells::nested`].
pub mod nested_value {
    pub const C: usize = 0;
    pub const V: usize = 1;
    pub const X: usize = 2;
    pub const Y: usize = 3;
    pub const U: usize = 4;
}

/// The cells of the memory, by what they hold.
pub struct MemoryCells {
    /// What each [`Step::Child`] stores, the left child's first.
    pub children: [ChildCells; 2],
    /// The folded $c_n$, from the last page of [`Step::Errors`].
    pub c: ElementCell,
    /// The `inner_error` stage's `registry_wy` and `native_inner_error`,
    /// and the `outer_error` stage's `native_outer_error`, from the last
    /// page of [`Step::Errors`].
    pub registry_wy: PointCell,
    pub native_inner_error: PointCell,
    pub native_outer_error: PointCell,
    /// Each mask claim's fold under $z_n$, in claim order, from
    /// [`Step::Masks`].
    pub masks: Vec<ElementCell>,
    /// The `query` stage's points, from [`Step::Masks`].
    pub native_query: PointCell,
    pub registry_xy: PointCell,
    pub query_online_points: Vec<PointCell>,
    pub query_online_stage: Vec<PointCell>,
    /// The parts of $a_n(x_n z_n)$ and of $b_n(x_n)$ up to each page of
    /// [`Step::Fold`]. The last page's are the two values.
    pub fold: Vec<[ElementCell; 2]>,
    /// The part of $f_n(u_n)$ up to each page of [`Step::Quotients`]. The
    /// last page's is $f_n(u_n)$.
    pub quotients: Vec<ElementCell>,
    /// The part of $v_n$ up to each page of [`Step::Evaluations`]. The
    /// last page's is $v_n$.
    pub evaluations: Vec<ElementCell>,
    /// The `eval` stage's points, from the first page of
    /// [`Step::Evaluations`].
    pub native_eval: PointCell,
    pub eval_online_stage: Vec<PointCell>,
    /// The online helper's two sums, which the prover supplies: the first
    /// to the last page of [`Step::Quotients`] and the second to the last
    /// page of [`Step::Evaluations`]. The export circuit exposes both, and
    /// the parent holds them to the helper circuit's.
    pub online_fold: Vec<ElementCell>,
}

/// Whether a child's online helper claim has a $k(y_n)$ in profile `P`.
pub fn has_online_helper<P: Profile>() -> bool {
    !P::NESTED_ONLINE.is_empty()
}

/// Whether a child's binding claim has a $k(y_n)$ in profile `P`.
pub fn has_binding<P: Profile>() -> bool {
    !crate::internal::ky::nested_bound::<P, ()>(|_| (), |_| (), |_| ()).is_empty()
}

/// Assigns the cells of the memory of profile `P`.
fn layout<P: Profile>() -> (MemoryCells, Layout<Cells<P>>) {
    let sizes = Sizes::of::<P>();
    let mut layout = Layout::new();
    let child = |layout: &mut Layout<Cells<P>>| ChildCells {
        nested: core::array::from_fn(|_| layout.element()),
        unified: layout.element(),
        compute_v: layout.element(),
        online_helper: has_online_helper::<P>().then(|| layout.element()),
        binding: has_binding::<P>().then(|| layout.element()),
    };
    let children = [child(&mut layout), child(&mut layout)];
    let cells = MemoryCells {
        children,
        c: layout.element(),
        registry_wy: layout.point(),
        native_inner_error: layout.point(),
        native_outer_error: layout.point(),
        masks: layout.elements(sizes.masks),
        native_query: layout.point(),
        registry_xy: layout.point(),
        query_online_points: layout.points(PhaseLen::<P, Native, 3>::len()),
        query_online_stage: layout.points(Present::<P, Native, 1>::len()),
        fold: (0..sizes.fold_pages())
            .map(|_| [layout.element(), layout.element()])
            .collect(),
        quotients: layout.elements(sizes.quotient_pages()),
        evaluations: layout.elements(sizes.evaluation_pages()),
        native_eval: layout.point(),
        eval_online_stage: layout.points(Present::<P, Native, 1>::len()),
        online_fold: layout.elements(Present::<P, Nested, 2>::len()),
    };
    (cells, layout)
}

/// The cells of the memory of profile `P`.
pub fn cells<P: Profile>() -> MemoryCells {
    layout::<P>().0
}

/// The stage outputs a circuit of the layout loaded. Every circuit loads
/// the trunk; the stages of the branches are present in the circuits that
/// load them.
pub struct Stages<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, P: Profile> {
    pub endoscalar: HoistedEndoscalar<'dr, D>,
    pub bridge_hash: stages::bridge_hash::Output<'dr, D, C>,
    pub links: Links<'dr, D, C, P>,
    pub s_prime: stages::s_prime::Output<'dr, D, C, P>,
    pub ab: stages::ab::Output<'dr, D, C, P>,
    pub f: stages::f::Output<'dr, D, C>,
    pub challenges: stages::challenges::Output<'dr, D>,
    points: Vec<(usize, Points<'dr, D, C, P>)>,
    preamble: Option<stages::preamble::Output<'dr, D, C, P>>,
    inner_error: Option<stages::inner_error::Output<'dr, D, C, P>>,
    outer_error: Option<stages::outer_error::Output<'dr, D, C, P>>,
    query: Option<stages::query::Output<'dr, D, C, P>>,
    eval: Option<stages::eval::Output<'dr, D, C, P>>,
}

/// The error of a step that reads a stage its circuit does not load.
fn absent(stage: &'static str) -> Error {
    Error::Initialization(
        alloc::format!("a step reads the {stage} stage, which its circuit does not load").into(),
    )
}

impl<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, P: Profile> Stages<'dr, D, C, P> {
    /// The points stage of group `group` of the walk.
    ///
    /// # Errors
    ///
    /// Fails if the circuit did not load that group's points stage.
    pub fn points(&self, group: usize) -> Result<&Points<'dr, D, C, P>> {
        self.points
            .iter()
            .find(|(loaded, _)| *loaded == group)
            .map(|(_, points)| points)
            .ok_or_else(|| absent("points"))
    }

    /// The `preamble` stage.
    ///
    /// # Errors
    ///
    /// Fails if the circuit did not load it, as the accessors below do
    /// for their stages.
    pub fn preamble(&self) -> Result<&stages::preamble::Output<'dr, D, C, P>> {
        self.preamble.as_ref().ok_or_else(|| absent("preamble"))
    }

    /// The `inner_error` stage.
    pub fn inner_error(&self) -> Result<&stages::inner_error::Output<'dr, D, C, P>> {
        self.inner_error
            .as_ref()
            .ok_or_else(|| absent("inner_error"))
    }

    /// The `outer_error` stage.
    pub fn outer_error(&self) -> Result<&stages::outer_error::Output<'dr, D, C, P>> {
        self.outer_error
            .as_ref()
            .ok_or_else(|| absent("outer_error"))
    }

    /// The `query` stage.
    pub fn query(&self) -> Result<&stages::query::Output<'dr, D, C, P>> {
        self.query.as_ref().ok_or_else(|| absent("query"))
    }

    /// The `eval` stage.
    pub fn eval(&self) -> Result<&stages::eval::Output<'dr, D, C, P>> {
        self.eval.as_ref().ok_or_else(|| absent("eval"))
    }

    /// The lift of the challenge at `index` of the challenge stage.
    pub fn lift(&self, index: usize) -> &Element<'dr, D> {
        &self.challenges.pairs[index].lift
    }
}

/// The witness of a circuit of the layout: every stage's, and the
/// memory's values.
pub struct Witness<'a, C: Affine, P: Profile> {
    pub stages: common::Witness<'a, C, P>,
    pub memory: &'a Values<C>,
}

/// The reserved stages of the trunk, before the circuit's driver is free
/// to load them.
struct Trunk<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, R: Rank, P: Profile> {
    endoscalar: StageGuard<'dr, D, R, EndoscalarStage>,
    bridge_hash: StageGuard<'dr, D, R, stages::bridge_hash::Stage<C>>,
    points: Option<(usize, StageGuard<'dr, D, R, PointsStage<C, P>>)>,
    links: StageGuard<'dr, D, R, LinksStage<C, P>>,
    s_prime: StageGuard<'dr, D, R, stages::s_prime::Stage<C, R, P>>,
    ab: StageGuard<'dr, D, R, stages::ab::Stage<C, R, P>>,
    f: StageGuard<'dr, D, R, stages::f::Stage<C, R, P>>,
    challenges: StageGuard<'dr, D, R, stages::challenges::Stage<C, R, P>>,
    memory: StageGuard<'dr, D, R, MemoryStage<C, R, P>>,
}

/// The builder after the trunk, for a circuit whose last stage is `T`.
type AfterTrunk<'a, 'dr, D, C, R, P, T> = StageBuilder<'a, 'dr, D, R, MemoryStage<C, R, P>, T>;

impl<'dr, D, C, R, P> Trunk<'dr, D, C, R, P>
where
    D: Driver<'dr, F = C::Base>,
    C: Affine,
    R: Rank,
    P: Profile,
{
    /// Reserves the trunk's stages in gate order: the endoscalar stage,
    /// the bridge-hash stage, the points stage, the links stage, `s_prime`,
    /// `ab`, `f`, the challenge stage and the memory stage. The points
    /// stage is loaded with the polynomial of group `group` of the walk, or
    /// reserved and not loaded for `None`.
    fn reserve<'a, T: ragu_circuits::staging::Stage<C::Base, R>>(
        dr: StageBuilder<'a, 'dr, D, R, (), T>,
        group: Option<usize>,
    ) -> Result<(Self, AfterTrunk<'a, 'dr, D, C, R, P, T>)> {
        let (endoscalar, dr) = dr.add_stage::<EndoscalarStage>()?;
        let (bridge_hash, dr) = dr.add_stage::<stages::bridge_hash::Stage<C>>()?;
        let (points, dr) = match group {
            Some(group) => {
                let (points, dr) = dr.add_stage::<PointsStage<C, P>>()?;
                (Some((group, points)), dr)
            }
            None => (None, dr.skip_stage::<PointsStage<C, P>>()?),
        };
        let (links, dr) = dr.add_stage::<LinksStage<C, P>>()?;
        let (s_prime, dr) = dr.add_stage_beside::<stages::s_prime::Stage<C, R, P>>()?;
        let (ab, dr) = dr.add_stage_beside::<stages::ab::Stage<C, R, P>>()?;
        let (f, dr) = dr.add_stage_beside::<stages::f::Stage<C, R, P>>()?;
        let (challenges, dr) = dr.add_stage_beside::<stages::challenges::Stage<C, R, P>>()?;
        let (memory, dr) = dr.add_stage::<MemoryStage<C, R, P>>()?;
        Ok((
            Trunk {
                endoscalar,
                bridge_hash,
                points,
                links,
                s_prime,
                ab,
                f,
                challenges,
                memory,
            },
            dr,
        ))
    }

    /// Loads the trunk's stages, unenforced, with no stage of a branch.
    fn load<'source: 'dr>(
        self,
        dr: &mut D,
        witness: &DriverValue<D, Witness<'source, C, P>>,
    ) -> Result<(Stages<'dr, D, C, P>, program::Loaded<'dr, D, C, Cells<P>>)> {
        let stage = witness.as_ref().map(|w| &w.stages);
        let stages = Stages {
            endoscalar: self
                .endoscalar
                .unenforced(dr, stage.as_ref().map(|w| w.endoscalar))?,
            bridge_hash: self
                .bridge_hash
                .unenforced(dr, stage.as_ref().map(|w| w.bridge_hash))?,
            points: match self.points {
                Some((group, points)) => vec![(
                    group,
                    points.unenforced(dr, stage.as_ref().map(|w| &w.walk.groups[group]))?,
                )],
                None => Vec::new(),
            },
            links: self
                .links
                .unenforced(dr, stage.as_ref().map(|w| &w.walk.links))?,
            s_prime: self
                .s_prime
                .unenforced(dr, stage.as_ref().map(|w| w.s_prime))?,
            ab: self.ab.unenforced(dr, stage.as_ref().map(|w| w.ab))?,
            f: self.f.unenforced(dr, stage.as_ref().map(|w| w.f))?,
            challenges: self
                .challenges
                .unenforced(dr, stage.as_ref().map(|w| w.challenges))?,
            preamble: None,
            inner_error: None,
            outer_error: None,
            query: None,
            eval: None,
        };
        let memory = self
            .memory
            .unenforced(dr, witness.as_ref().map(|w| w.memory))?;
        Ok((stages, memory))
    }
}

/// What a circuit of the layout loaded: its driver, the stages and the
/// memory.
pub type Loaded<'a, 'dr, D, C, P> = (
    &'a mut D,
    Stages<'dr, D, C, P>,
    program::Loaded<'dr, D, C, Cells<P>>,
);

/// A branch of the layout as a type: the last stage of the circuits that
/// load it, and the loading of the trunk and the branch.
pub trait Loads<C: Affine, R: Rank, P: Profile>: Send + Sync + 'static {
    /// The branch.
    const BRANCH: Branch;

    /// The last stage of a circuit that loads the branch.
    type Last: ragu_circuits::staging::Stage<C::Base, R>;

    /// Reserves and loads the trunk and the branch, every stage
    /// unenforced, with the points stage of group `group` of the walk or
    /// none.
    fn load<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: &DriverValue<D, Witness<'source, C, P>>,
        group: Option<usize>,
    ) -> Result<Loaded<'a, 'dr, D, C, P>>;
}

/// The `preamble` branch.
pub struct OnPreamble;

/// The `inner_error` and `outer_error` branch.
pub struct OnErrors;

/// The `query` branch.
pub struct OnQuery;

/// The `query` and `eval` branch.
pub struct OnEval;

impl<C: Affine, R: Rank, P: Profile> Loads<C, R, P> for OnPreamble {
    const BRANCH: Branch = Branch::Preamble;
    type Last = stages::preamble::Stage<C, R, P>;

    fn load<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: &DriverValue<D, Witness<'source, C, P>>,
        group: Option<usize>,
    ) -> Result<Loaded<'a, 'dr, D, C, P>> {
        let (trunk, dr) = Trunk::reserve(dr, group)?;
        let (preamble, dr) = dr.add_stage_beside::<stages::preamble::Stage<C, R, P>>()?;
        let dr = dr.finish();
        let (mut stages, memory) = trunk.load(dr, witness)?;
        stages.preamble =
            Some(preamble.unenforced(dr, witness.as_ref().map(|w| w.stages.preamble))?);
        Ok((dr, stages, memory))
    }
}

impl<C: Affine, R: Rank, P: Profile> Loads<C, R, P> for OnErrors {
    const BRANCH: Branch = Branch::Errors;
    type Last = stages::outer_error::Stage<C, R, P>;

    fn load<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: &DriverValue<D, Witness<'source, C, P>>,
        group: Option<usize>,
    ) -> Result<Loaded<'a, 'dr, D, C, P>> {
        let (trunk, dr) = Trunk::reserve(dr, group)?;
        let (inner, dr) = dr.add_stage_beside::<stages::inner_error::Stage<C, R, P>>()?;
        let (outer, dr) = dr.add_stage::<stages::outer_error::Stage<C, R, P>>()?;
        let dr = dr.finish();
        let (mut stages, memory) = trunk.load(dr, witness)?;
        stages.inner_error =
            Some(inner.unenforced(dr, witness.as_ref().map(|w| w.stages.inner_error))?);
        stages.outer_error =
            Some(outer.unenforced(dr, witness.as_ref().map(|w| w.stages.outer_error))?);
        Ok((dr, stages, memory))
    }
}

impl<C: Affine, R: Rank, P: Profile> Loads<C, R, P> for OnQuery {
    const BRANCH: Branch = Branch::Query;
    type Last = stages::query::Stage<C, R, P>;

    fn load<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: &DriverValue<D, Witness<'source, C, P>>,
        group: Option<usize>,
    ) -> Result<Loaded<'a, 'dr, D, C, P>> {
        let (trunk, dr) = Trunk::reserve(dr, group)?;
        let (query, dr) = dr.add_stage_beside::<stages::query::Stage<C, R, P>>()?;
        let dr = dr.finish();
        let (mut stages, memory) = trunk.load(dr, witness)?;
        stages.query = Some(query.unenforced(dr, witness.as_ref().map(|w| w.stages.query))?);
        Ok((dr, stages, memory))
    }
}

impl<C: Affine, R: Rank, P: Profile> Loads<C, R, P> for OnEval {
    const BRANCH: Branch = Branch::Eval;
    type Last = stages::eval::Stage<C, R, P>;

    fn load<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: &DriverValue<D, Witness<'source, C, P>>,
        group: Option<usize>,
    ) -> Result<Loaded<'a, 'dr, D, C, P>> {
        let (trunk, dr) = Trunk::reserve(dr, group)?;
        let (query, dr) = dr.add_stage_beside::<stages::query::Stage<C, R, P>>()?;
        let (eval, dr) = dr.add_stage_beside::<stages::eval::Stage<C, R, P>>()?;
        let dr = dr.finish();
        let (mut stages, memory) = trunk.load(dr, witness)?;
        stages.query = Some(query.unenforced(dr, witness.as_ref().map(|w| w.stages.query))?);
        stages.eval = Some(eval.unenforced(dr, witness.as_ref().map(|w| w.stages.eval))?);
        Ok((dr, stages, memory))
    }
}

/// What a step runs over: the stages its circuit loaded, the memory and
/// the values the prover supplies.
pub struct Inputs<'a, 'dr, D: Driver<'dr>, C: Affine<Base = D::F>, P: Profile> {
    pub stages: &'a Stages<'dr, D, C, P>,
    pub memory: Memory<'a, 'dr, D, C, Cells<P>>,
    /// The online helper's two sums, for [`MemoryCells::online_fold`].
    pub online_fold: DriverValue<D, FixedVec<C::Base, Present<P, Nested, 2>>>,
}

/// The program of profile `P`: [`schedule`]'s steps.
pub struct Fuse<C, R, P>(PhantomData<fn() -> (C, R, P)>);

impl<C, R, P> Fuse<C, R, P> {
    /// The program.
    pub const fn new() -> Self {
        Fuse(PhantomData)
    }
}

impl<C: Affine, R: Rank, P: Profile> Program<C::Base> for Fuse<C, R, P> {
    type Inputs<'a, 'dr, D: Driver<'dr, F = C::Base>>
        = Inputs<'a, 'dr, D, C, P>
    where
        'dr: 'a,
        D: 'a;

    fn steps(&self) -> usize {
        schedule::<P>().len()
    }

    fn step<'a, 'dr: 'a, D: Driver<'dr, F = C::Base> + 'a>(
        &self,
        step: usize,
        dr: &mut D,
        inputs: &Self::Inputs<'a, 'dr, D>,
    ) -> Result<()> {
        match schedule::<P>()[step] {
            Step::Child { child } => collapse::child(dr, inputs, child),
            Step::Errors { page } => collapse::errors(dr, inputs, page),
            Step::Masks => compute_v::masks(dr, inputs),
            Step::Fold { page } => compute_v::fold::<_, _, R, _>(dr, inputs, page),
            Step::Quotients { page } => compute_v::quotients(dr, inputs, page),
            Step::Evaluations { page } => compute_v::evaluations(dr, inputs, page),
            Step::Walk { group } => walk::group(dr, inputs, group),
        }
    }
}

/// The circuit of step `step` of the program, which loads the branch `B`.
pub struct StepCircuit<C, R, P, B> {
    step: usize,
    _marker: PhantomData<fn() -> (C, R, P, B)>,
}

impl<C: Affine, R: Rank, P: Profile, B: Loads<C, R, P>> StepCircuit<C, R, P, B> {
    /// Creates the circuit of step `step`.
    ///
    /// # Panics
    ///
    /// Panics if the program has no such step or the step loads another
    /// branch.
    pub fn new(step: usize) -> Self {
        assert_eq!(
            schedule::<P>()[step].branch(),
            B::BRANCH,
            "the step's circuit loads the step's branch"
        );
        StepCircuit {
            step,
            _marker: PhantomData,
        }
    }
}

impl<C: Affine, R: Rank, P: Profile, B: Loads<C, R, P>> MultiStageCircuit<C::Base, R>
    for StepCircuit<C, R, P, B>
{
    type Last = B::Last;
    type Instance<'source> = ();
    type Witness<'source> = Witness<'source, C, P>;
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
        let group = schedule::<P>()[self.step].group();
        let (dr, stages, memory) = B::load(dr, &witness, group)?;
        let inputs = Inputs {
            stages: &stages,
            memory: Memory::loaded(&memory),
            online_fold: witness.as_ref().map(|w| w.stages.online_fold.clone()),
        };
        Fuse::<C, R, P>::new().step(self.step, dr, &inputs)?;
        Ok(WithAux::new((), D::unit()))
    }
}

/// The prover's run of the program over the stages' witnesses: the values
/// of the memory, which the memory stage then commits.
///
/// The run executes every step in order outside a circuit, with every
/// stage present. A stored cell takes the value the step computed, so no
/// second copy of the steps exists for the circuits to disagree with.
///
/// # Errors
///
/// Fails if a step fails over the witness, or if the run breaks a rule of
/// the program's [log](program::Log).
pub fn memory<C: Affine, R: Rank, P: Profile>(
    witness: &common::Witness<'_, C, P>,
) -> Result<Values<C>> {
    type Run<F> = Emulator<ragu_core::drivers::emulator::Wireless<Always<()>, F>>;

    let values = RefCell::new(Values::blank::<Cells<P>>(C::generator()));
    let log = Log::new();
    {
        let dr = &mut Run::<C::Base>::execute();
        let stages = every_stage::<_, C, R, P>(dr, &Run::<C::Base>::just(|| witness))?;
        let inputs = Inputs {
            stages: &stages,
            memory: Memory::tracing(&values, &log),
            online_fold: Run::<C::Base>::just(|| witness.online_fold.clone()),
        };
        program::run(&Fuse::<C, R, P>::new(), dr, &inputs, &log)?;
    }
    log.finish()?;
    Ok(values.into_inner())
}

/// Every stage's output over `witness`, allocated on `dr`: what a run of
/// the whole program reads.
pub fn every_stage<'dr, 'source: 'dr, D, C, R, P>(
    dr: &mut D,
    witness: &DriverValue<D, &common::Witness<'source, C, P>>,
) -> Result<Stages<'dr, D, C, P>>
where
    D: Driver<'dr, F = C::Base>,
    C: Affine,
    R: Rank,
    P: Profile,
{
    use ragu_circuits::staging::Stage;

    let groups = walk_grouping::<P>().groups();
    Ok(Stages {
        endoscalar: Stage::<C::Base, R>::witness(
            &EndoscalarStage,
            dr,
            witness.as_ref().map(|w| w.endoscalar),
        )?,
        bridge_hash: Stage::<C::Base, R>::witness(
            &stages::bridge_hash::Stage::<C>::default(),
            dr,
            witness.as_ref().map(|w| w.bridge_hash),
        )?,
        points: (0..groups)
            .map(|group| {
                Ok((
                    group,
                    Stage::<C::Base, R>::witness(
                        &PointsStage::<C, P>::default(),
                        dr,
                        witness.as_ref().map(|w| &w.walk.groups[group]),
                    )?,
                ))
            })
            .collect::<Result<_>>()?,
        links: Stage::<C::Base, R>::witness(
            &LinksStage::<C, P>::default(),
            dr,
            witness.as_ref().map(|w| &w.walk.links),
        )?,
        s_prime: stages::s_prime::Stage::<C, R, P>::default()
            .witness(dr, witness.as_ref().map(|w| w.s_prime))?,
        ab: stages::ab::Stage::<C, R, P>::default().witness(dr, witness.as_ref().map(|w| w.ab))?,
        f: stages::f::Stage::<C, R, P>::default().witness(dr, witness.as_ref().map(|w| w.f))?,
        challenges: stages::challenges::Stage::<C, R, P>::default()
            .witness(dr, witness.as_ref().map(|w| w.challenges))?,
        preamble: Some(
            stages::preamble::Stage::<C, R, P>::default()
                .witness(dr, witness.as_ref().map(|w| w.preamble))?,
        ),
        inner_error: Some(
            stages::inner_error::Stage::<C, R, P>::default()
                .witness(dr, witness.as_ref().map(|w| w.inner_error))?,
        ),
        outer_error: Some(
            stages::outer_error::Stage::<C, R, P>::default()
                .witness(dr, witness.as_ref().map(|w| w.outer_error))?,
        ),
        query: Some(
            stages::query::Stage::<C, R, P>::default()
                .witness(dr, witness.as_ref().map(|w| w.query))?,
        ),
        eval: Some(
            stages::eval::Stage::<C, R, P>::default()
                .witness(dr, witness.as_ref().map(|w| w.eval))?,
        ),
    })
}

/// The grid of the claims' fold in profile `P`: its groups and the nodes
/// of a group.
pub(super) fn grid<P: Profile>() -> (usize, usize) {
    (NumFoldGroups::<P>::len(), FOLD_GROUP_SIZE)
}

#[cfg(test)]
#[path = "../../../../../tests/nested_paged.rs"]
mod tests;

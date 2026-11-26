//! The native compute-v circuit of a profile whose batch outgrows one
//! circuit, as a program of step circuits.
//!
//! The standard profile's [`compute_v`](super::compute_v) circuit loads
//! the `preamble`, `query` and `eval` stages and recomputes the batch
//! evaluation $v$ in one trace. A profile with a large extension pins a
//! native program ([`Profile::NATIVE_STEPS`]) and checks the same statement
//! with the circuits of this module, the way its nested side does
//! ([`nested::circuits::paged`](crate::internal::nested::circuits::paged)):
//!
//! - A [`program`] of [`Step`]s over a memory
//!   stage that follows the `preamble` stage. A step loads the `preamble`
//!   stage, the memory and the `query` stage, or those and the `eval`
//!   stage, and exposes nothing.
//! - [`export::Circuit`], in the compute-v circuit's place. It exposes
//!   that circuit's public output. It reads the challenges from the unified
//!   instance and stores them in the memory, which is the program's first
//!   step; the other steps take the challenges from those cells. It
//!   provides the instance's $v$ from the cell the last step stored.
//!
//! # The steps
//!
//! | Step | Stages after the memory | Part of compute-v |
//! |---|---|---|
//! | [`Step::Challenges`] | (in the export circuit) | the challenges, and $\beta$ from `pre_beta` |
//! | [`Step::Masks`] | `query` | the mask claims' folds under $z$ |
//! | [`Step::Fold`] | `query` | $a(xz)$ and $b(x)$ for a page of groups |
//! | [`Step::Quotients`] | `query`, `eval` | $f(u)$ for a page of openings |
//! | [`Step::Evaluations`] | `query`, `eval` | $v$ for a page of evaluations |
//!
//! The steps share the compute-v circuit's list of the openings
//! ([`poly_queries`](super::compute_v::poly_queries)) and its evaluation
//! processor, so the two forms fold the same terms in the same order.
//!
//! # What holds the cut statement together
//!
//! The conditions of a [program](crate::internal::program#soundness):
//! every step is a registered circuit whose claim is folded
//! ([`InternalCircuitIndex::Step`]), all of them and the export circuit
//! read one memory polynomial, and each cell is defined once. A challenge
//! cell is held to the unified instance's wire by the export circuit, whose
//! claim's $k(y)$ the parent computes from the instance.

use alloc::{vec, vec::Vec};
use core::{cell::RefCell, marker::PhantomData};

use ragu_circuits::{
    WithAux,
    polynomials::Rank,
    staging::{MultiStage, MultiStageCircuit, Stage as _, StageBuilder},
};
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue, emulator::Emulator},
    gadgets::{Bound, Kind},
    maybe::{Always, Maybe},
};
use ragu_primitives::{
    Element, Endoscalar, EndoscalarChallenge, WithSuffix,
    allocator::Allocator,
    vec::{FixedVec, Len},
};

use crate::{
    internal::{
        native::{
            self, FOLD_GROUP_SIZE, InternalCircuitIndex, MemoryStage, NumFoldGroups, RxIndex,
            online::NUM_ONLINE_FP_QUERIES,
            pcs::STATIC_F_QUERIES,
            stages::{
                eval as native_eval, points::BindingStage, preamble as native_preamble,
                query as native_query,
            },
        },
        paging,
        program::{self, ElementCell, Layout, Log, Memory, Program, Values},
    },
    profile::{
        Profile, ProfiledCycle,
        online::stages::{Native, Present},
    },
};

pub mod compute_v;
pub mod export;

/// The groups of the claims' grid a page of [`Step::Fold`] folds.
///
/// The capacities are the page sizes at which every step fits a trace of
/// the wallet rank with as many polynomials as the aggregator's extension
/// adds. See the nested program's
/// [capacities](crate::internal::nested::circuits::paged::ERROR_GROUPS).
pub const FOLD_GROUPS: usize = 32;

/// The openings a page of [`Step::Quotients`] folds into $f(u)$.
pub const QUOTIENTS: usize = 235;

/// The evaluations a page of [`Step::Evaluations`] folds into $v$.
pub const EVALUATIONS: usize = 600;

/// One step of the program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// The challenges, from the unified instance into the memory. The
    /// export circuit runs it. See [`compute_v::challenges`].
    Challenges,
    /// The mask claims' folds under $z$. See [`compute_v::masks`].
    Masks,
    /// The part of $a(xz)$ and $b(x)$ that page `page` of the grid's
    /// groups holds. See [`compute_v::fold`].
    Fold { page: usize },
    /// The part of $f(u)$ that page `page` of the openings holds. See
    /// [`compute_v::quotients`].
    Quotients { page: usize },
    /// The part of $v$ that page `page` of the evaluations holds. See
    /// [`compute_v::evaluations`].
    Evaluations { page: usize },
}

/// The stages a step's circuit loads after the memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Branch {
    /// The `query` stage.
    Query,
    /// The `query` and `eval` stages.
    Eval,
}

impl Step {
    /// The stages the step's circuit loads after the memory.
    pub fn branch(self) -> Branch {
        match self {
            Step::Masks | Step::Fold { .. } => Branch::Query,
            Step::Challenges | Step::Quotients { .. } | Step::Evaluations { .. } => Branch::Eval,
        }
    }
}

/// The sizes the page counts of profile `P` follow from.
pub struct Sizes {
    /// The groups of the claims' grid, the last of which holds no claim.
    pub groups: usize,
    /// The mask claims.
    pub masks: usize,
    /// The openings $f$ covers.
    pub openings: usize,
    /// The evaluations $v$ sums, $f(u)$ first.
    pub evaluations: usize,
}

impl Sizes {
    /// The sizes of profile `P`.
    pub fn of<P: Profile>() -> Self {
        let internal = InternalCircuitIndex::all::<P>();
        let rx = RxIndex::num::<P>();
        Sizes {
            groups: NumFoldGroups::<P>::len(),
            masks: internal.iter().filter(|id| id.is_mask()).count(),
            openings: STATIC_F_QUERIES.len() + 2 * rx + internal.len() + NUM_ONLINE_FP_QUERIES,
            // f(u), then each child's rx polynomials, a, b, registry_xy and
            // p, then the step's own eleven and its online openings.
            evaluations: 1 + 2 * (rx + 4) + 11 + NUM_ONLINE_FP_QUERIES,
        }
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

/// The steps of the program of profile `P`, in order: a step loads only
/// cells that an earlier step defined. The first step is the export
/// circuit's, and each later step is a circuit of its own.
pub fn schedule<P: Profile>() -> Vec<Step> {
    let sizes = Sizes::of::<P>();
    let mut steps = vec![Step::Challenges, Step::Masks];
    steps.extend((0..sizes.fold_pages()).map(|page| Step::Fold { page }));
    steps.extend((0..sizes.quotient_pages()).map(|page| Step::Quotients { page }));
    steps.extend((0..sizes.evaluation_pages()).map(|page| Step::Evaluations { page }));
    steps
}

/// The step circuits of the program: its steps after the first. What
/// [`Profile::NATIVE_STEPS`] pins.
pub fn num_step_circuits<P: Profile>() -> usize {
    schedule::<P>().len() - 1
}

/// The memory of the program of profile `P`: the [`program::Shape`] of
/// [`MemoryStage`]. A profile without a program has no cell.
pub struct Cells<P>(PhantomData<fn() -> P>);

impl<P: Profile> program::Shape for Cells<P> {
    const NAME: &'static str = "native compute-v";

    fn points() -> usize {
        0
    }

    fn elements() -> usize {
        if native::paged::<P>() {
            layout::<P>().1.num_elements()
        } else {
            0
        }
    }
}

/// The challenges the steps compute with, as elements.
pub struct Challenges<T> {
    pub w: T,
    pub y: T,
    pub z: T,
    pub x: T,
    pub mu: T,
    pub mu_prime: T,
    pub alpha: T,
    pub u: T,
    /// The lift of the endoscalar extracted from `pre_beta`.
    pub beta: T,
}

impl<T> Challenges<T> {
    /// The challenges in the order of the memory's cells.
    pub fn each(&self) -> [&T; 9] {
        [
            &self.w,
            &self.y,
            &self.z,
            &self.x,
            &self.mu,
            &self.mu_prime,
            &self.alpha,
            &self.u,
            &self.beta,
        ]
    }

    /// The challenges built from `each`, called in the order of the
    /// memory's cells.
    pub fn from_each(mut each: impl FnMut(usize) -> Result<T>) -> Result<Self> {
        Ok(Challenges {
            w: each(0)?,
            y: each(1)?,
            z: each(2)?,
            x: each(3)?,
            mu: each(4)?,
            mu_prime: each(5)?,
            alpha: each(6)?,
            u: each(7)?,
            beta: each(8)?,
        })
    }
}

/// The cells of the memory, by what they hold.
pub struct MemoryCells {
    /// The challenges, from [`Step::Challenges`].
    pub challenges: Challenges<ElementCell>,
    /// Each mask claim's fold under $z$, in claim order, from
    /// [`Step::Masks`].
    pub masks: Vec<ElementCell>,
    /// The parts of $a(xz)$ and of $b(x)$ up to each page of
    /// [`Step::Fold`]. The last page's are the two values.
    pub fold: Vec<[ElementCell; 2]>,
    /// The part of $f(u)$ up to each page of [`Step::Quotients`].
    pub quotients: Vec<ElementCell>,
    /// The part of $v$ up to each page of [`Step::Evaluations`]. The last
    /// page's is $v$.
    pub evaluations: Vec<ElementCell>,
    /// The online helper's two sums, which the prover supplies: the first
    /// to the last page of [`Step::Quotients`] and the second to the last
    /// page of [`Step::Evaluations`]. The export circuit exposes both.
    pub online_fold: Vec<ElementCell>,
}

/// Assigns the cells of the memory of profile `P`.
fn layout<P: Profile>() -> (MemoryCells, Layout<Cells<P>>) {
    let sizes = Sizes::of::<P>();
    let mut layout = Layout::new();
    let cells = MemoryCells {
        challenges: Challenges::from_each(|_| Ok(layout.element())).expect("infallible"),
        masks: layout.elements(sizes.masks),
        fold: (0..sizes.fold_pages())
            .map(|_| [layout.element(), layout.element()])
            .collect(),
        quotients: layout.elements(sizes.quotient_pages()),
        evaluations: layout.elements(sizes.evaluation_pages()),
        online_fold: layout.elements(Present::<P, Native, 2>::len()),
    };
    (cells, layout)
}

/// The cells of the memory of profile `P`.
pub fn cells<P: Profile>() -> MemoryCells {
    layout::<P>().0
}

/// The stage outputs a circuit of the program loaded: the `preamble`
/// stage always, and the `query` and `eval` stages in the circuits that
/// load them.
pub struct Stages<
    'dr,
    D: Driver<'dr>,
    C: ProfiledCycle<CircuitField = D::F>,
    const HEADER_SIZE: usize,
> {
    pub preamble: native_preamble::Output<'dr, D, C, HEADER_SIZE>,
    pub(super) query: Option<native_query::Output<'dr, D, C::Profile>>,
    pub(super) eval: Option<native_eval::Output<'dr, D, C>>,
}

/// The error of a step that reads a stage its circuit does not load.
fn absent(stage: &'static str) -> Error {
    Error::Initialization(
        alloc::format!("a step reads the {stage} stage, which its circuit does not load").into(),
    )
}

impl<'dr, D: Driver<'dr>, C: ProfiledCycle<CircuitField = D::F>, const HEADER_SIZE: usize>
    Stages<'dr, D, C, HEADER_SIZE>
{
    /// The `query` stage.
    ///
    /// # Errors
    ///
    /// Fails if the circuit did not load it.
    pub fn query(&self) -> Result<&native_query::Output<'dr, D, C::Profile>> {
        self.query.as_ref().ok_or_else(|| absent("query"))
    }

    /// The `eval` stage.
    ///
    /// # Errors
    ///
    /// Fails if the circuit did not load it.
    pub fn eval(&self) -> Result<&native_eval::Output<'dr, D, C>> {
        self.eval.as_ref().ok_or_else(|| absent("eval"))
    }
}

/// The witness of a step circuit: the stages' and the memory's values.
pub struct Witness<'a, C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize> {
    pub online_fold: &'a FixedVec<C::CircuitField, Present<C::Profile, Native, 2>>,
    pub preamble_witness: &'a native_preamble::Witness<'a, C, R, HEADER_SIZE>,
    pub query_witness: &'a native_query::Witness<C>,
    pub eval_witness: &'a native_eval::Witness<C>,
    pub memory: &'a Values<C::NestedCurve>,
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize> Clone for Witness<'_, C, R, HEADER_SIZE> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize> Copy for Witness<'_, C, R, HEADER_SIZE> {}

/// What a step runs over: the stages its circuit loaded, the memory, the
/// challenges where the unified instance is at hand, and the values the
/// prover supplies.
pub struct Inputs<
    'a,
    'dr,
    D: Driver<'dr>,
    C: ProfiledCycle<CircuitField = D::F>,
    const HEADER_SIZE: usize,
> {
    pub stages: &'a Stages<'dr, D, C, HEADER_SIZE>,
    pub memory: Memory<'a, 'dr, D, C::NestedCurve, Cells<C::Profile>>,
    /// The challenges as the unified instance holds them, in the export
    /// circuit and in the prover's run. A step circuit has none: it takes
    /// them from the memory.
    pub challenges: Option<&'a Challenges<Element<'dr, D>>>,
    /// The online helper's two sums, for [`MemoryCells::online_fold`].
    pub online_fold: DriverValue<D, &'a FixedVec<C::CircuitField, Present<C::Profile, Native, 2>>>,
}

/// The lift of the endoscalar extracted from `pre_beta`, as the compute-v
/// circuit derives $\beta$.
pub fn effective_beta<'dr, D: Driver<'dr>, A: Allocator<'dr, D>>(
    dr: &mut D,
    allocator: &mut A,
    pre_beta: Element<'dr, D>,
) -> Result<Element<'dr, D>> {
    let pre_beta = EndoscalarChallenge::from_element(dr, allocator, pre_beta)?;
    Endoscalar::extract(pre_beta).lift(dr)
}

/// The program of profile `C::Profile`: [`schedule`]'s steps.
pub struct Batch<C, R, const HEADER_SIZE: usize>(PhantomData<fn() -> (C, R)>);

impl<C, R, const HEADER_SIZE: usize> Batch<C, R, HEADER_SIZE> {
    /// The program.
    pub const fn new() -> Self {
        Batch(PhantomData)
    }
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize> Program<C::CircuitField>
    for Batch<C, R, HEADER_SIZE>
{
    type Inputs<'a, 'dr, D: Driver<'dr, F = C::CircuitField>>
        = Inputs<'a, 'dr, D, C, HEADER_SIZE>
    where
        'dr: 'a,
        D: 'a;

    fn steps(&self) -> usize {
        schedule::<C::Profile>().len()
    }

    fn step<'a, 'dr: 'a, D: Driver<'dr, F = C::CircuitField> + 'a>(
        &self,
        step: usize,
        dr: &mut D,
        inputs: &Self::Inputs<'a, 'dr, D>,
    ) -> Result<()> {
        match schedule::<C::Profile>()[step] {
            Step::Challenges => compute_v::challenges(dr, inputs),
            Step::Masks => compute_v::masks(dr, inputs),
            Step::Fold { page } => compute_v::fold::<_, _, R, HEADER_SIZE>(dr, inputs, page),
            Step::Quotients { page } => compute_v::quotients(dr, inputs, page),
            Step::Evaluations { page } => compute_v::evaluations(dr, inputs, page),
        }
    }
}

/// The circuit of step `step` of the program, a step after the first.
pub struct StepCircuit<C, R, const HEADER_SIZE: usize, const EVAL: bool> {
    step: usize,
    _marker: PhantomData<fn() -> (C, R)>,
}

/// A step circuit whose last stage is the `query` stage.
pub type OnQuery<C, R, const HEADER_SIZE: usize> = StepCircuit<C, R, HEADER_SIZE, false>;

/// A step circuit whose last stage is the `eval` stage.
pub type OnEval<C, R, const HEADER_SIZE: usize> = StepCircuit<C, R, HEADER_SIZE, true>;

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, const EVAL: bool>
    StepCircuit<C, R, HEADER_SIZE, EVAL>
where
    Self: MultiStageCircuit<C::CircuitField, R>,
{
    /// Creates the circuit of step `step` of [`schedule`], a step after
    /// the first.
    ///
    /// # Panics
    ///
    /// Panics if `step` is the program's first step or not a step of it, or
    /// if the step loads other stages than this circuit does.
    pub fn new(step: usize) -> MultiStage<C::CircuitField, R, Self> {
        assert!(
            step != 0,
            "the export circuit runs the program's first step"
        );
        let branch = if EVAL { Branch::Eval } else { Branch::Query };
        assert_eq!(
            schedule::<C::Profile>()[step].branch(),
            branch,
            "the step's circuit loads the step's stages"
        );
        MultiStage::new(StepCircuit {
            step,
            _marker: PhantomData,
        })
    }
}

/// Reserves the binding stage and loads the `preamble` stage and the
/// memory, unenforced: the stages every circuit of the program starts
/// with. The export circuit enforces the `preamble` stage's contracts.
#[allow(clippy::type_complexity)]
fn load_trunk<'a, 'dr, 'source: 'dr, D, C, R, T, const HEADER_SIZE: usize>(
    builder: StageBuilder<'a, 'dr, D, R, (), T>,
) -> Result<(
    ragu_circuits::staging::StageGuard<'dr, D, R, native_preamble::Stage<C, R, HEADER_SIZE>>,
    ragu_circuits::staging::StageGuard<'dr, D, R, MemoryStage<C, R, HEADER_SIZE>>,
    StageBuilder<'a, 'dr, D, R, MemoryStage<C, R, HEADER_SIZE>, T>,
)>
where
    D: Driver<'dr, F = C::CircuitField>,
    C: ProfiledCycle,
    R: Rank,
    T: ragu_circuits::staging::Stage<C::CircuitField, R>,
{
    let builder = builder.skip_stage::<BindingStage<C::NestedCurve, C::Profile>>()?;
    let (preamble, builder) = builder.add_stage::<native_preamble::Stage<C, R, HEADER_SIZE>>()?;
    let (memory, builder) = builder.add_stage::<MemoryStage<C, R, HEADER_SIZE>>()?;
    Ok((preamble, memory, builder))
}

macro_rules! step_circuit {
    ($eval:literal, $last:ty, |$builder:ident, $dr:ident, $witness:ident| $load:block) => {
        impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize>
            MultiStageCircuit<C::CircuitField, R> for StepCircuit<C, R, HEADER_SIZE, $eval>
        {
            type Last = $last;
            type Instance<'source> = ();
            type Witness<'source> = Witness<'source, C, R, HEADER_SIZE>;
            type Output = Kind![C::CircuitField; WithSuffix<'_, _, ()>];
            type Aux<'source> = ();

            fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
                &self,
                dr: &mut D,
                _: DriverValue<D, ()>,
            ) -> Result<Bound<'dr, D, Self::Output>> {
                Ok(WithSuffix::new((), Element::zero(dr)))
            }

            fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
                &self,
                $builder: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
                $witness: DriverValue<D, Self::Witness<'source>>,
            ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
            {
                let ($dr, stages, memory) = $load;
                let inputs = Inputs {
                    stages: &stages,
                    memory: Memory::loaded(&memory),
                    challenges: None,
                    online_fold: $witness.as_ref().map(|w| w.online_fold),
                };
                Batch::<C, R, HEADER_SIZE>::new().step(self.step, $dr, &inputs)?;
                Ok(WithAux::new(
                    WithSuffix::new((), Element::zero($dr)),
                    D::unit(),
                ))
            }
        }
    };
}

step_circuit!(false, native_query::Stage<C, R, HEADER_SIZE>, |builder, dr, witness| {
    let (preamble, memory, builder) = load_trunk::<_, C, R, _, HEADER_SIZE>(builder)?;
    let (query, builder) = builder.add_stage::<native_query::Stage<C, R, HEADER_SIZE>>()?;
    let dr = builder.finish();
    let stages = Stages {
        preamble: preamble.unenforced(dr, witness.as_ref().map(|w| w.preamble_witness))?,
        query: Some(query.unenforced(dr, witness.as_ref().map(|w| w.query_witness))?),
        eval: None,
    };
    let memory = memory.unenforced(dr, witness.as_ref().map(|w| w.memory))?;
    (dr, stages, memory)
});

step_circuit!(true, native_eval::Stage<C, R, HEADER_SIZE>, |builder, dr, witness| {
    let (preamble, memory, builder) = load_trunk::<_, C, R, _, HEADER_SIZE>(builder)?;
    let (query, builder) = builder.add_stage::<native_query::Stage<C, R, HEADER_SIZE>>()?;
    let (eval, builder) = builder.add_stage::<native_eval::Stage<C, R, HEADER_SIZE>>()?;
    let dr = builder.finish();
    let stages = Stages {
        preamble: preamble.unenforced(dr, witness.as_ref().map(|w| w.preamble_witness))?,
        query: Some(query.unenforced(dr, witness.as_ref().map(|w| w.query_witness))?),
        eval: Some(eval.unenforced(dr, witness.as_ref().map(|w| w.eval_witness))?),
    };
    let memory = memory.unenforced(dr, witness.as_ref().map(|w| w.memory))?;
    (dr, stages, memory)
});

/// The prover's run of the program over the stages' witnesses: the values
/// of the memory, which the memory stage then commits.
///
/// The run executes every step in order outside a circuit, with every
/// stage present and the challenges as `challenges` gives them, `beta`
/// being `pre_beta`. A stored cell takes the value the step computed.
///
/// # Errors
///
/// Fails if a step fails over the witness, or if the run breaks a rule of
/// the program's [log](program::Log).
pub fn memory<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize>(
    witness: &Witness<'_, C, R, HEADER_SIZE>,
    challenges: &Challenges<C::CircuitField>,
) -> Result<Values<C::NestedCurve>> {
    type Run<F> = Emulator<ragu_core::drivers::emulator::Wireless<Always<()>, F>>;

    let values = RefCell::new(Values::blank::<Cells<C::Profile>>(
        <C::NestedCurve as udon::curve::Affine>::generator(),
    ));
    let log = Log::new();
    {
        let dr = &mut Run::<C::CircuitField>::execute();
        let stages =
            every_stage::<_, C, R, HEADER_SIZE>(dr, &Run::<C::CircuitField>::just(|| *witness))?;
        let each = challenges.each();
        let mut elements = Challenges::from_each(|i| {
            Element::alloc(dr, &mut (), Run::<C::CircuitField>::just(|| *each[i]))
        })?;
        elements.beta = effective_beta(dr, &mut (), elements.beta)?;
        let inputs = Inputs {
            stages: &stages,
            memory: Memory::tracing(&values, &log),
            challenges: Some(&elements),
            online_fold: Run::<C::CircuitField>::just(|| witness.online_fold),
        };
        program::run(&Batch::<C, R, HEADER_SIZE>::new(), dr, &inputs, &log)?;
    }
    log.finish()?;
    Ok(values.into_inner())
}

/// Every stage's output over `witness`, allocated on `dr`: what a run of
/// the whole program reads.
pub fn every_stage<'dr, 'source: 'dr, D, C, R, const HEADER_SIZE: usize>(
    dr: &mut D,
    witness: &DriverValue<D, Witness<'source, C, R, HEADER_SIZE>>,
) -> Result<Stages<'dr, D, C, HEADER_SIZE>>
where
    D: Driver<'dr, F = C::CircuitField>,
    C: ProfiledCycle,
    R: Rank,
{
    Ok(Stages {
        preamble: native_preamble::Stage::<C, R, HEADER_SIZE>::default()
            .witness(dr, witness.as_ref().map(|w| w.preamble_witness))?,
        query: Some(
            native_query::Stage::<C, R, HEADER_SIZE>::default()
                .witness(dr, witness.as_ref().map(|w| w.query_witness))?,
        ),
        eval: Some(
            native_eval::Stage::<C, R, HEADER_SIZE>::default()
                .witness(dr, witness.as_ref().map(|w| w.eval_witness))?,
        ),
    })
}

/// The grid of the claims' fold in profile `P`: its groups and the nodes
/// of a group.
pub(super) fn grid<P: Profile>() -> (usize, usize) {
    (NumFoldGroups::<P>::len(), FOLD_GROUP_SIZE)
}

#[cfg(test)]
#[path = "../../../../../tests/native_paged.rs"]
mod tests;

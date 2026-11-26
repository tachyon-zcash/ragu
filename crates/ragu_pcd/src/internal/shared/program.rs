//! Programs: one computation cut by hand into step circuits that share a
//! memory.
//!
//! Some statements are too large for one circuit and have no single
//! operation to page (see [`paging`](super::paging)): a transcript, then
//! some field arithmetic, then a Horner chain. A program writes such a
//! statement as a list of steps. Each step is one circuit. The author of
//! the program decides which part of the statement each step checks.
//!
//! Steps share no wires. A value one step computes and a later step needs
//! lives in a cell of the program's [`Memory`], which is a stage every
//! step loads ([`MemoryStage`]):
//!
//! ```text
//!            ┌──────────────── memory stage ────────────────┐
//!            │  cell a      cell b      cell c      cell d  │
//!            └────▲───────────│▲──────────│▲──────────│─────┘
//!           store │      load ││ store    ││ store    │ load
//!              step 0       step 1      step 2      step 3
//! ```
//!
//! # Cells
//!
//! A [`Layout`] assigns the cells: an [`ElementCell`] holds one field
//! element and a [`PointCell`] one curve point. Every cell has exactly one
//! definition, in exactly one step:
//!
//! - [`store`](Memory::store_element): the step computes the value and the
//!   cell is held to it. In the step's circuit this is an equality between
//!   the computed value and the cell's stage wires.
//! - [`advise`](Memory::advise_element): the prover supplies the value and
//!   nothing holds it. An advised point is held to the curve by the step
//!   that advises it. What an advised value means is fixed only by the
//!   steps that compute with it: the steps that load it, and the step
//!   that advises it, which gets the value back.
//!
//! Any step after the definition can [`load`](Memory::load_element) the
//! cell, which costs no gate: the step reads the stage's wires.
//!
//! The calls to `advise` are the complete list of the free values of a
//! memory. A review of a program reads them first.
//!
//! # One body, three uses
//!
//! A step is written once, generic over the driver, against the [`Memory`]
//! handle. The same body serves three callers.
//!
//! - **The step's circuit** loads the memory stage and runs the step over
//!   [`Memory::loaded`]. Stores are equalities and loads are wires.
//! - **The prover** runs every step in order outside a circuit over
//!   [`Memory::tracing`] ([`run`]). Stores fill the [`Values`] the stage
//!   then commits. No second, native copy of the statement exists that
//!   could disagree with the circuits.
//! - **The program's tests** run the same pass over [`Memory::checking`]
//!   on a driver without a witness and read the [`Report`] of the
//!   [`Log`]: which step defines each cell and which steps load it.
//!
//! # Rules the log holds
//!
//! The [`Log`] refuses, at the access that breaks the rule:
//!
//! - a second definition of a cell;
//! - a load of a cell before its definition, in step order and then in the
//!   order of the accesses of one step.
//!
//! [`Log::finish`] refuses a cell without a definition. A cell that no step
//! loads is not an error, because a circuit outside the program can read
//! it: the report lists these cells ([`Report::unread`]) for the program's
//! tests to pin.
//!
//! # Soundness
//!
//! A program rests on the same conditions as a paged walk.
//!
//! 1. Every step is a registered circuit whose claim is folded: steps
//!    `0..steps`. A step that is not checked leaves the cells it stores
//!    free.
//! 2. All steps read the same stage polynomial for the memory, which the
//!    stage's mask and the steps' claims give.
//! 3. The wire contracts of what the steps read from other stages hold.
//!    The memory needs none beyond what the steps give it: a stored value
//!    equals a value a step computed, and an advised point is held to the
//!    curve by the step that advises it.
//!
//! Under these conditions, order the cells by their definitions. Loads
//! follow definitions, so each stored cell is a function of the steps'
//! other inputs, the advised cells and cells earlier in that order. By
//! induction every stored cell holds the value the program defines for it.
//! The order of the steps matters to the prover's run and to a reader. It
//! does not matter to the argument: all steps are checked over one
//! assignment of the stage.
//!
//! # Paging inside a program
//!
//! A step can run a page of a walk whose interstitials are cells: it loads
//! the cell of the page before, calls [`paging::fold`](super::paging::fold)
//! over the page's inputs and stores the result in the page's cell. The
//! cells then follow the rules above, and the walk's pages are steps of
//! the program.

use alloc::{string::String, vec, vec::Vec};
use core::{cell::RefCell, marker::PhantomData};

use ragu_circuits::{polynomials::Rank, staging::Stage};
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::{Always, Maybe},
};
use ragu_primitives::{
    Element, GadgetExt, Point,
    consistent::Consistent,
    vec::{FixedVec, Len},
};
use udon::{curve::EndomorphismAffine as Affine, field::Field};

/// A cell of a memory that holds one field element.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ElementCell {
    memory: &'static str,
    index: usize,
}

/// A cell of a memory that holds one curve point.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PointCell {
    memory: &'static str,
    index: usize,
}

impl ElementCell {
    /// Returns the cell's position among the memory's elements.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "only the tests of a program read its report")
    )]
    pub fn index(&self) -> usize {
        self.index
    }
}

impl PointCell {
    /// Returns the cell's position among the memory's points.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "only the tests of a program read its report")
    )]
    pub fn index(&self) -> usize {
        self.index
    }
}

/// A cell of either kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Cell {
    /// A cell that holds a point.
    Point(PointCell),
    /// A cell that holds an element.
    Element(ElementCell),
}

/// The size of a memory and its name: what [`MemoryStage`] takes its
/// length from.
///
/// The name tells the memories of one program apart. A cell carries the
/// name of the memory its [`Layout`] assigned it in, and an access to
/// another memory through it panics.
pub trait Shape: Send + Sync + 'static {
    /// The name of the memory.
    const NAME: &'static str;

    /// Returns the number of point cells.
    fn points() -> usize;

    /// Returns the number of element cells.
    fn elements() -> usize;
}

/// Assigns the cells of the memory of shape `S`, in order.
///
/// A program assigns its cells once, in a function that returns them as a
/// struct of named cells, and [`Shape`] reports the counts the layout
/// reached.
pub struct Layout<S> {
    points: usize,
    elements: usize,
    _marker: PhantomData<fn() -> S>,
}

impl<S: Shape> Default for Layout<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Shape> Layout<S> {
    /// Creates a layout with no cells.
    pub fn new() -> Self {
        Layout {
            points: 0,
            elements: 0,
            _marker: PhantomData,
        }
    }

    /// Assigns the next element cell.
    pub fn element(&mut self) -> ElementCell {
        self.elements += 1;
        ElementCell {
            memory: S::NAME,
            index: self.elements - 1,
        }
    }

    /// Assigns the next `count` element cells.
    pub fn elements(&mut self, count: usize) -> Vec<ElementCell> {
        (0..count).map(|_| self.element()).collect()
    }

    /// Assigns the next point cell.
    pub fn point(&mut self) -> PointCell {
        self.points += 1;
        PointCell {
            memory: S::NAME,
            index: self.points - 1,
        }
    }

    /// Assigns the next `count` point cells.
    pub fn points(&mut self, count: usize) -> Vec<PointCell> {
        (0..count).map(|_| self.point()).collect()
    }

    /// Returns the number of point cells assigned.
    pub fn num_points(&self) -> usize {
        self.points
    }

    /// Returns the number of element cells assigned.
    pub fn num_elements(&self) -> usize {
        self.elements
    }
}

/// Length type for the point cells of the memory of shape `S`.
pub struct Points<S>(PhantomData<fn() -> S>);

impl<S: Shape> Len for Points<S> {
    fn len() -> usize {
        S::points()
    }
}

/// Length type for the element cells of the memory of shape `S`.
pub struct Elements<S>(PhantomData<fn() -> S>);

impl<S: Shape> Len for Elements<S> {
    fn len() -> usize {
        S::elements()
    }
}

/// The values of a memory: what the prover's run fills and the memory
/// stage commits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Values<C: Affine> {
    /// The point cells' values.
    pub points: Vec<C>,
    /// The element cells' values.
    pub elements: Vec<C::Base>,
}

impl<C: Affine> Values<C> {
    /// Creates the values of a memory of shape `S` before any step ran:
    /// every element zero and every point `placeholder`.
    ///
    /// A point cell cannot hold the identity, which has no coordinates, so
    /// `placeholder` must be another point of the curve.
    pub fn blank<S: Shape>(placeholder: C) -> Self {
        Values {
            points: vec![placeholder; S::points()],
            elements: vec![C::Base::ZERO; S::elements()],
        }
    }
}

/// The wires of a memory stage, as a step circuit loaded them.
#[derive(Gadget)]
pub struct Loaded<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, S: Shape> {
    /// The point cells' wires.
    #[ragu(gadget)]
    pub points: FixedVec<Point<'dr, D, C>, Points<S>>,
    /// The element cells' wires.
    #[ragu(gadget)]
    pub elements: FixedVec<Element<'dr, D>, Elements<S>>,
}

impl<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, S: Shape> Loaded<'dr, D, C, S> {
    /// Allocates the memory's cells for `values`: the points' coordinates
    /// first, then the elements, one wire each.
    ///
    /// # Errors
    ///
    /// Returns a witness-generation error if a point is the identity.
    pub fn alloc(dr: &mut D, values: DriverValue<D, &Values<C>>) -> Result<Self> {
        Ok(Loaded {
            points: FixedVec::try_from_fn(|i| {
                Point::alloc(dr, values.as_ref().map(|v| v.points[i]))
            })?,
            elements: FixedVec::try_from_fn(|i| {
                Element::alloc(dr, &mut (), values.as_ref().map(|v| v.elements[i]))
            })?,
        })
    }
}

/// The stage that holds the memory of shape `S`, with points of the curve
/// `C`, after the stage `Parent`.
///
/// Every step circuit of the program loads it unenforced: the steps give
/// the cells their contracts (see [the module's soundness
/// conditions](self#soundness)).
pub struct MemoryStage<S, C, Parent>(PhantomData<fn() -> (S, C, Parent)>);

impl<S, C, Parent> Default for MemoryStage<S, C, Parent> {
    fn default() -> Self {
        MemoryStage(PhantomData)
    }
}

impl<S, C, R, Parent> Stage<C::Base, R> for MemoryStage<S, C, Parent>
where
    S: Shape,
    C: Affine,
    R: Rank,
    Parent: Stage<C::Base, R>,
{
    type Parent = Parent;
    type Witness<'source> = &'source Values<C>;
    type OutputKind = Kind![C::Base; Loaded<'_, _, C, S>];

    fn values() -> usize {
        2 * S::points() + S::elements()
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        Loaded::alloc(dr, witness)
    }
}

/// How a cell got its value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Definition {
    /// A step computed the value and the cell is held to it.
    Stored,
    /// The prover supplied the value.
    Advised,
}

/// What the log keeps for one cell.
#[derive(Clone, Debug, Default)]
struct CellLog {
    /// The step that defined the cell, and how.
    defined: Option<(usize, Definition)>,
    /// The steps that loaded the cell, one entry per load.
    loads: Vec<usize>,
}

/// What the log keeps for one memory.
struct MemoryLog {
    name: &'static str,
    points: Vec<CellLog>,
    elements: Vec<CellLog>,
}

/// Records the accesses of a run of a program over [`Memory::tracing`]
/// or [`Memory::checking`] memories, and holds them to the rules of
/// [the module](self#rules-the-log-holds).
#[derive(Default)]
pub struct Log {
    step: RefCell<Option<usize>>,
    memories: RefCell<Vec<MemoryLog>>,
}

impl Log {
    /// Creates an empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Marks the accesses that follow as those of step `step`.
    ///
    /// # Panics
    ///
    /// Panics if `step` is before the step the log is at: a run goes
    /// through the steps in order.
    pub fn begin(&self, step: usize) {
        let mut current = self.step.borrow_mut();
        assert!(
            current.is_none_or(|current| current <= step),
            "a run goes through the steps in order"
        );
        *current = Some(step);
    }

    /// Adds a memory of shape `S` to the log.
    fn register<S: Shape>(&self) {
        let mut memories = self.memories.borrow_mut();
        assert!(
            memories.iter().all(|memory| memory.name != S::NAME),
            "the memory {:?} is recorded once",
            S::NAME
        );
        memories.push(MemoryLog {
            name: S::NAME,
            points: vec![CellLog::default(); S::points()],
            elements: vec![CellLog::default(); S::elements()],
        });
    }

    /// The step the log is at.
    fn current(&self) -> Result<usize> {
        self.step
            .borrow()
            .ok_or_else(|| refuse("a memory access outside a step".into()))
    }

    /// Runs `f` over the log of `cell`.
    fn with<T>(&self, cell: Cell, f: impl FnOnce(&mut CellLog) -> T) -> T {
        let mut memories = self.memories.borrow_mut();
        let (name, index) = match cell {
            Cell::Point(cell) => (cell.memory, cell.index),
            Cell::Element(cell) => (cell.memory, cell.index),
        };
        let memory = memories
            .iter_mut()
            .find(|memory| memory.name == name)
            .expect("an accessed memory is registered");
        f(match cell {
            Cell::Point(_) => &mut memory.points[index],
            Cell::Element(_) => &mut memory.elements[index],
        })
    }

    /// Records the definition of `cell` in the current step.
    fn define(&self, cell: Cell, how: Definition) -> Result<()> {
        let step = self.current()?;
        self.with(cell, |log| match log.defined {
            Some((first, _)) => Err(refuse(alloc::format!(
                "step {step} defines {cell:?}, which step {first} defined"
            ))),
            None => {
                log.defined = Some((step, how));
                Ok(())
            }
        })
    }

    /// Records a load of `cell` in the current step.
    fn load(&self, cell: Cell) -> Result<()> {
        let step = self.current()?;
        self.with(cell, |log| match log.defined {
            Some(_) => {
                log.loads.push(step);
                Ok(())
            }
            None => Err(refuse(alloc::format!(
                "step {step} loads {cell:?} before its definition"
            ))),
        })
    }

    /// Ends the run and returns its report.
    ///
    /// # Errors
    ///
    /// Fails if a cell of a recorded memory has no definition.
    pub fn finish(self) -> Result<Report> {
        let mut cells = Vec::new();
        for memory in self.memories.into_inner() {
            let name = memory.name;
            let points = memory.points.into_iter().enumerate().map(|(index, log)| {
                (
                    Cell::Point(PointCell {
                        memory: name,
                        index,
                    }),
                    log,
                )
            });
            let elements = memory.elements.into_iter().enumerate().map(|(index, log)| {
                (
                    Cell::Element(ElementCell {
                        memory: name,
                        index,
                    }),
                    log,
                )
            });
            for (cell, log) in points.chain(elements) {
                let Some((step, how)) = log.defined else {
                    return Err(refuse(alloc::format!("no step defines {cell:?}")));
                };
                cells.push(Usage {
                    cell,
                    step,
                    how,
                    loads: log.loads,
                });
            }
        }
        Ok(Report { cells })
    }
}

/// A broken rule of the log.
fn refuse(what: String) -> Error {
    Error::Initialization(what.into())
}

/// How a run used one cell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Usage {
    /// The cell.
    pub cell: Cell,
    /// The step that defined it.
    pub step: usize,
    /// How that step defined it.
    pub how: Definition,
    /// The steps that loaded it, one entry per load, in order.
    pub loads: Vec<usize>,
}

/// What a run did with every cell of its memories.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// Every cell, by memory in the order the memories were recorded, points
    /// before elements.
    pub cells: Vec<Usage>,
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "only the tests of a program read its report")
)]
impl Report {
    /// Returns how the run used `cell`.
    ///
    /// # Panics
    ///
    /// Panics if `cell` is not a cell of a recorded memory.
    pub fn usage(&self, cell: Cell) -> &Usage {
        self.cells
            .iter()
            .find(|usage| usage.cell == cell)
            .expect("a cell of a recorded memory")
    }

    /// Returns the advised cells: the free values of the memories.
    pub fn advised(&self) -> Vec<Cell> {
        self.cells
            .iter()
            .filter(|usage| usage.how == Definition::Advised)
            .map(|usage| usage.cell)
            .collect()
    }

    /// Returns the cells no step loads. A program's tests hold this to the
    /// cells that circuits outside the program read.
    pub fn unread(&self) -> Vec<Cell> {
        self.cells
            .iter()
            .filter(|usage| usage.loads.is_empty())
            .map(|usage| usage.cell)
            .collect()
    }

    /// Returns the cells step `step` defines.
    pub fn defined_by(&self, step: usize) -> Vec<Cell> {
        self.cells
            .iter()
            .filter(|usage| usage.step == step)
            .map(|usage| usage.cell)
            .collect()
    }
}

/// How a filling run takes values out of gadgets and advice. A run fills
/// values only on a driver that has a witness, where every value exists,
/// so these are plain functions and no witness closure writes to the
/// values.
struct Take<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> {
    element: fn(&Element<'dr, D>) -> D::F,
    point: fn(&Point<'dr, D, C>) -> C,
    advised_element: fn(&DriverValue<D, D::F>) -> D::F,
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "no program advises a point yet")
    )]
    advised_point: fn(&DriverValue<D, C>) -> C,
}

impl<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> Clone for Take<'dr, D, C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> Copy for Take<'dr, D, C> {}

/// What backs a memory handle.
enum Backing<'a, 'dr, D: Driver<'dr>, C: Affine<Base = D::F>, S: Shape> {
    /// The stage's wires, in a step circuit.
    Stage(&'a Loaded<'dr, D, C, S>),
    /// The values a run fills, outside a circuit.
    Fill(&'a RefCell<Values<C>>, &'a Log, Take<'dr, D, C>),
    /// A run that records its accesses and fills nothing. A loaded point
    /// is the placeholder.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "only the tests of a program run a checking pass")
    )]
    Check(&'a Log, C),
}

/// A program's memory as a step uses it.
///
/// See [the module](self) for what `load`, `store` and `advise` mean.
pub struct Memory<'a, 'dr, D: Driver<'dr>, C: Affine<Base = D::F>, S: Shape> {
    backing: Backing<'a, 'dr, D, C, S>,
}

impl<'a, 'dr, D, C, S> Memory<'a, 'dr, D, C, S>
where
    D: Driver<'dr, MaybeKind = Always<()>>,
    C: Affine<Base = D::F>,
    S: Shape,
{
    /// Creates the handle of the prover's run outside a circuit, which
    /// fills `values` and records its accesses in `log`. The driver has a
    /// witness.
    ///
    /// # Panics
    ///
    /// Panics if `values` is not the size of `S`, or if `log` already
    /// records a memory of this name.
    pub fn tracing(values: &'a RefCell<Values<C>>, log: &'a Log) -> Self {
        {
            let values = values.borrow();
            assert_eq!(values.points.len(), S::points(), "one value per point cell");
            assert_eq!(
                values.elements.len(),
                S::elements(),
                "one value per element cell"
            );
        }
        log.register::<S>();
        Memory {
            backing: Backing::Fill(
                values,
                log,
                Take {
                    element: |element| *element.value().take(),
                    point: |point| point.value().take(),
                    advised_element: |value| *value.snag(),
                    advised_point: |value| *value.snag(),
                },
            ),
        }
    }
}

impl<'a, 'dr, D: Driver<'dr>, C: Affine<Base = D::F>, S: Shape> Memory<'a, 'dr, D, C, S> {
    /// Creates the handle of a step circuit over the memory stage it
    /// loaded.
    pub fn loaded(stage: &'a Loaded<'dr, D, C, S>) -> Self {
        Memory {
            backing: Backing::Stage(stage),
        }
    }

    /// Creates the handle of a run that records its accesses in `log` and
    /// fills nothing, on any driver. A run for a [`Report`] uses it on a
    /// driver without a witness. A loaded element is zero and a loaded
    /// point is `placeholder`, which must not be the identity.
    ///
    /// # Panics
    ///
    /// Panics if `log` already records a memory of this name.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "only the tests of a program run a checking pass")
    )]
    pub fn checking(log: &'a Log, placeholder: C) -> Self {
        log.register::<S>();
        Memory {
            backing: Backing::Check(log, placeholder),
        }
    }

    /// Checks that a cell of the memory named `memory` is one of this
    /// memory's.
    fn own(memory: &'static str) {
        assert_eq!(
            memory,
            S::NAME,
            "a cell of the memory {memory:?} used on the memory {:?}",
            S::NAME
        );
    }

    /// Loads an element cell.
    ///
    /// # Errors
    ///
    /// Fails in a run if no earlier access defined the cell.
    pub fn load_element(&self, dr: &mut D, cell: ElementCell) -> Result<Element<'dr, D>> {
        Self::own(cell.memory);
        match self.backing {
            Backing::Stage(stage) => Ok(stage.elements[cell.index].clone()),
            Backing::Fill(values, log, _) => {
                log.load(Cell::Element(cell))?;
                Element::alloc(
                    dr,
                    &mut (),
                    D::just(|| values.borrow().elements[cell.index]),
                )
            }
            Backing::Check(log, _) => {
                log.load(Cell::Element(cell))?;
                Element::alloc(dr, &mut (), D::just(|| D::F::ZERO))
            }
        }
    }

    /// Stores `value` in an element cell: defines the cell as the value
    /// this step computed.
    ///
    /// # Errors
    ///
    /// Fails in a run if the cell has a definition already.
    pub fn store_element(
        &self,
        dr: &mut D,
        cell: ElementCell,
        value: &Element<'dr, D>,
    ) -> Result<()> {
        Self::own(cell.memory);
        match self.backing {
            Backing::Stage(stage) => value.enforce_equal(dr, &stage.elements[cell.index]),
            Backing::Fill(values, log, take) => {
                log.define(Cell::Element(cell), Definition::Stored)?;
                values.borrow_mut().elements[cell.index] = (take.element)(value);
                Ok(())
            }
            Backing::Check(log, _) => log.define(Cell::Element(cell), Definition::Stored),
        }
    }

    /// Defines an element cell as `value`, which the prover supplies, and
    /// returns it. Nothing holds the cell to `value`.
    ///
    /// # Errors
    ///
    /// Fails in a run if the cell has a definition already.
    pub fn advise_element(
        &self,
        dr: &mut D,
        cell: ElementCell,
        value: DriverValue<D, D::F>,
    ) -> Result<Element<'dr, D>> {
        Self::own(cell.memory);
        match self.backing {
            Backing::Stage(stage) => Ok(stage.elements[cell.index].clone()),
            Backing::Fill(values, log, take) => {
                log.define(Cell::Element(cell), Definition::Advised)?;
                values.borrow_mut().elements[cell.index] = (take.advised_element)(&value);
                Element::alloc(dr, &mut (), value)
            }
            Backing::Check(log, _) => {
                log.define(Cell::Element(cell), Definition::Advised)?;
                Element::alloc(dr, &mut (), value)
            }
        }
    }

    /// Loads a point cell.
    ///
    /// # Errors
    ///
    /// Fails in a run if no earlier access defined the cell.
    pub fn load_point(&self, dr: &mut D, cell: PointCell) -> Result<Point<'dr, D, C>> {
        Self::own(cell.memory);
        match self.backing {
            Backing::Stage(stage) => Ok(stage.points[cell.index].clone()),
            Backing::Fill(values, log, _) => {
                log.load(Cell::Point(cell))?;
                Point::alloc(dr, D::just(|| values.borrow().points[cell.index]))
            }
            Backing::Check(log, placeholder) => {
                log.load(Cell::Point(cell))?;
                Point::alloc(dr, D::just(|| placeholder))
            }
        }
    }

    /// Stores `value` in a point cell: defines the cell as the point this
    /// step computed.
    ///
    /// # Errors
    ///
    /// Fails in a run if the cell has a definition already.
    pub fn store_point(&self, dr: &mut D, cell: PointCell, value: &Point<'dr, D, C>) -> Result<()> {
        Self::own(cell.memory);
        match self.backing {
            Backing::Stage(stage) => value.enforce_equal(dr, &stage.points[cell.index]),
            Backing::Fill(values, log, take) => {
                log.define(Cell::Point(cell), Definition::Stored)?;
                values.borrow_mut().points[cell.index] = (take.point)(value);
                Ok(())
            }
            Backing::Check(log, _) => log.define(Cell::Point(cell), Definition::Stored),
        }
    }

    /// Defines a point cell as `value`, which the prover supplies, and
    /// returns it, held to the curve. Nothing else holds the cell to
    /// `value`.
    ///
    /// # Errors
    ///
    /// Fails in a run if the cell has a definition already, and returns a
    /// witness-generation error if `value` is the identity.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "no program advises a point yet")
    )]
    pub fn advise_point(
        &self,
        dr: &mut D,
        cell: PointCell,
        value: DriverValue<D, C>,
    ) -> Result<Point<'dr, D, C>> {
        Self::own(cell.memory);
        match self.backing {
            Backing::Stage(stage) => {
                // The stage is loaded unenforced, so the cell's wires are
                // held to the curve here, in the one step that defines it.
                let point = stage.points[cell.index].clone();
                point.enforce_consistent(dr)?;
                Ok(point)
            }
            Backing::Fill(values, log, take) => {
                log.define(Cell::Point(cell), Definition::Advised)?;
                values.borrow_mut().points[cell.index] = (take.advised_point)(&value);
                Point::alloc(dr, value)
            }
            Backing::Check(log, _) => {
                log.define(Cell::Point(cell), Definition::Advised)?;
                Point::alloc(dr, value)
            }
        }
    }
}

/// A computation as a list of steps over shared memories.
///
/// The step circuits are the implementor's: circuit `step` loads the
/// stages, builds [`Inputs`](Self::Inputs) over [`Memory::loaded`] handles
/// and calls [`step`](Self::step). The trait gives the prover's run and
/// the tests one way to go through the same steps ([`run`]).
pub trait Program<F: Field> {
    /// What a step reads: the outputs of the stages it loads, the
    /// witnesses it allocates, and the program's [`Memory`] handles.
    type Inputs<'a, 'dr, D: Driver<'dr, F = F>>
    where
        'dr: 'a,
        D: 'a;

    /// Returns the number of steps.
    fn steps(&self) -> usize;

    /// Runs step `step`.
    ///
    /// # Errors
    ///
    /// Returns the error of the step's gadgets, of the driver, or of the
    /// memories' log.
    fn step<'a, 'dr: 'a, D: Driver<'dr, F = F> + 'a>(
        &self,
        step: usize,
        dr: &mut D,
        inputs: &Self::Inputs<'a, 'dr, D>,
    ) -> Result<()>;
}

/// Runs every step of `program` in order on `dr`, outside a circuit.
///
/// `inputs` holds handles over `log`: [`Memory::tracing`] handles for the
/// prover, whose run fills the memories' [`Values`], or
/// [`Memory::checking`] handles, whose run records the accesses alone, for
/// the [`Report`].
///
/// # Errors
///
/// Returns the first error of a step.
pub fn run<'a, 'dr: 'a, D: Driver<'dr> + 'a, P: Program<D::F>>(
    program: &P,
    dr: &mut D,
    inputs: &P::Inputs<'a, 'dr, D>,
    log: &Log,
) -> Result<()> {
    for step in 0..program.steps() {
        log.begin(step);
        program.step(step, dr, inputs)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/program.rs"]
mod tests;

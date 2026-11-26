//! Paging: one walk of a unit operation, cut into circuits.
//!
//! A walk applies one operation, its [`Unit`], many times in a row. Each
//! application takes the state the application before it left and one
//! input, and leaves a new state. Horner's rule is the example this crate
//! uses: the state is the accumulator, and one application is
//! `state * x + input`.
//!
//! A walk can be longer than one circuit's gate budget. Paging cuts it into
//! pages. Every page applies the unit [`Walk::capacity`] times, except the
//! last, which applies it to the inputs that remain. Pages share no wires.
//! They share a stage, which holds one state per page: the page's
//! interstitial, the state after the page's last application.
//!
//! ```text
//! initial ──▶ page 0 ──▶ i[0] ──▶ page 1 ──▶ i[1] ──▶ ⋯ ──▶ page n-1 ──▶ i[n-1]
//!             inputs              inputs                    inputs
//!             0..c                c..2c                     (n-1)c..len
//! ```
//!
//! Page `k` starts from interstitial `k - 1`, or from the walk's initial
//! state when `k` is zero. It applies the unit to its inputs in order and
//! enforces that the result equals interstitial `k`. The last interstitial
//! is the walk's result.
//!
//! # What a walk declares
//!
//! A walk has two parts.
//!
//! - A [`Unit`]: the operation, its state and its input. This is the only
//!   place where the arithmetic of the walk is written.
//! - A [`Walk`]: where a page finds the initial state, each input and each
//!   interstitial among the stages it loaded, and the walk's capacity.
//!
//! [`page`] is the only code that runs a page. It is the same for every
//! walk, so a review of a paged computation reads the unit, the walk's
//! three accessors and the stage that holds the interstitials.
//!
//! [`page`] is a function over a driver and not a circuit. A circuit that
//! is one page calls it once after it loads its stages, as the endoscaling
//! steps do. A circuit that does other work can call it for the pages it
//! has room for. A step of a [`program`](super::program) runs a page as
//! [`fold`] between a load and a store of its memory.
//!
//! # Capacity
//!
//! The capacity is a constant of the walk. It is the largest number of
//! applications for which a full page fits the gate budget of the rank
//! beside the stages the page loads. No estimate sets it: a test
//! synthesizes a full page, measures one application, and holds the
//! constant to the largest count that fits (`assert_capacity` in this
//! module's tests). The page boundaries follow from the capacity alone
//! ([`num_pages`] and [`range`]).
//!
//! # Soundness
//!
//! Paging rests on three conditions, and the walk's owner must hold all
//! three.
//!
//! 1. Every page of the walk is a registered circuit whose claim is
//!    folded: pages `0..num_pages`. A page that is not checked leaves its
//!    interstitial free, and with it every later state.
//! 2. All pages read the same stage polynomials. The stages' masks and the
//!    claims that sum each page's trace with the stages it loads give this.
//! 3. The wire contracts of the states and inputs hold. A page reads them
//!    from stages as loaded, and [`page`] adds no contract of its own. For
//!    points this is curve membership, which one circuit of the walk's
//!    owner enforces for the whole stage.
//!
//! Under these conditions the pages chain by induction. Interstitial `k`
//! equals the unit applied to inputs `0..(k + 1) * capacity` from the
//! initial state, clamped to the walk's length, because page `k` holds it
//! to the unit applied to its own inputs from interstitial `k - 1`. The
//! last interstitial is therefore the result of the whole walk.
//!
//! A walk with no inputs has one page. That page applies nothing and
//! enforces that the initial state equals interstitial zero.
//!
//! # Groups
//!
//! A page loads the stage that holds its walk's values. When one stage
//! holds the whole walk, the gates a page reserves grow with the walk, and
//! a long walk leaves a page no room for its applications. A [`Grouping`]
//! cuts the pages into groups so that a page loads one group alone.
//!
//! A group is a walk of its own. It has an entry state, its inputs and one
//! interstitial per page, in its own stage polynomial. Every group uses
//! the same stage type, so all groups sit at the same gates and share one
//! stage mask. A page loads the polynomial of its group and runs [`page`]
//! with its index within the group. Nothing else about a page changes.
//!
//! ```text
//!   links:   l[0] ────────────── l[1] ────────────── l[2] ─ ⋯ ─ l[G]
//!             ║                   ║ ║                 ║
//!   group 0: entry ▶ pages ▶ exit   ║                 ║
//!   group 1:                      entry ▶ pages ▶ exit
//! ```
//!
//! The groups chain through a links stage. It holds one state per group
//! boundary: link 0 is the walk's initial state, and link `g + 1` is the
//! state after group `g`. The last link is the walk's result. No page
//! loads the links. One circuit per group, the group's check circuit,
//! loads the links and the group and calls [`link`], which enforces that
//! the group's entry equals link `g` and its exit equals link `g + 1`.
//!
//! The soundness conditions then hold per group, with one more: every
//! group's check circuit is registered and its claim folded. By induction
//! over the groups, link `g + 1` equals the unit applied to the inputs of
//! groups `0..=g` from link 0.
//!
//! A grouping of zero pages per group is the whole walk in one stage,
//! with no links: the layout a short walk uses.

use alloc::vec::Vec;
use core::ops::Range;

use ragu_core::{Result, drivers::Driver, gadgets::Gadget};
use ragu_primitives::{
    Element, GadgetExt, HoistedEndoscalar, NonzeroBank, Point, comparison::GadgetEquals,
};
use udon::curve::EndomorphismAffine as Affine;

/// The operation a walk repeats.
///
/// An implementation is the arithmetic of one application and nothing else.
/// It must be the same for every application of the walk: what differs
/// between applications is the input alone.
pub trait Unit<'dr, D: Driver<'dr>> {
    /// The value an application updates. The interstitials have this type.
    type State: Gadget<'dr, D, Kind: GadgetEquals<D::F>>;

    /// What one application takes beside the state.
    type Input;

    /// What the applications of one page share. Use `()` when they share
    /// nothing.
    type Scope;

    /// Opens the scope of one page, runs `body` in it and closes it.
    ///
    /// [`page`] calls this once per page, and calls [`apply`](Self::apply)
    /// only inside `body`.
    ///
    /// # Errors
    ///
    /// Returns the error of `body`, or the error of opening or closing the
    /// scope.
    fn scope<T>(
        &self,
        dr: &mut D,
        body: impl FnOnce(&mut D, &mut Self::Scope) -> Result<T>,
    ) -> Result<T>;

    /// Applies the operation once: returns the state that follows `state`
    /// for `input`.
    ///
    /// # Errors
    ///
    /// Returns a witness-generation error if the witness is an exceptional
    /// case of the operation, or a driver error.
    fn apply(
        &self,
        dr: &mut D,
        scope: &mut Self::Scope,
        state: Self::State,
        input: &Self::Input,
    ) -> Result<Self::State>;
}

/// The state type of walk `W`.
pub type State<'dr, D, W> = <<W as Walk<'dr, D>>::Unit as Unit<'dr, D>>::State;

/// The input type of walk `W`.
pub type Input<'dr, D, W> = <<W as Walk<'dr, D>>::Unit as Unit<'dr, D>>::Input;

/// A walk as one page sees it: the unit, and where the page finds the
/// walk's values among the stages it loaded.
///
/// The accessors take walk-wide indices. A page calls
/// [`input`](Self::input) only for the inputs in its [`range`], and
/// [`interstitial`](Self::interstitial) only for its own page and the page
/// before it, so an implementation needs only those values loaded.
pub trait Walk<'dr, D: Driver<'dr>> {
    /// The operation the walk repeats.
    type Unit: Unit<'dr, D>;

    /// Returns the operation.
    fn unit(&self) -> &Self::Unit;

    /// Returns the number of applications a full page performs.
    fn capacity(&self) -> usize;

    /// Returns the number of inputs, which is the number of applications
    /// of the whole walk.
    fn num_inputs(&self) -> usize;

    /// Returns the state before the first application.
    fn initial(&self) -> &State<'dr, D, Self>;

    /// Returns input `index` of the walk.
    fn input(&self, index: usize) -> &Input<'dr, D, Self>;

    /// Returns the state after the last application of page `page`.
    fn interstitial(&self, page: usize) -> &State<'dr, D, Self>;
}

/// Returns the number of pages of a walk over `len` inputs at `capacity`
/// applications per page.
///
/// A walk with no inputs has one page.
///
/// # Panics
///
/// Panics if `capacity` is zero.
pub const fn num_pages(capacity: usize, len: usize) -> usize {
    assert!(capacity > 0, "a page applies its unit at least once");
    let pages = len.div_ceil(capacity);
    if pages > 1 { pages } else { 1 }
}

/// Returns the inputs page `page` applies the unit to, out of `len`, at
/// `capacity` applications per page.
///
/// The ranges of pages `0..num_pages(capacity, len)` are adjacent, do not
/// overlap and cover `0..len`. The range is empty for a later page.
pub fn range(capacity: usize, page: usize, len: usize) -> Range<usize> {
    let start = page.saturating_mul(capacity).min(len);
    let end = start.saturating_add(capacity).min(len);
    start..end
}

/// Applies `unit` to `inputs` in order, from `start`, inside one scope, and
/// returns the state after the last application.
///
/// This is the work of one page without the two ends: [`page`] takes
/// `start` from a stage and holds the result to a stage. A caller that
/// keeps its interstitials elsewhere, as a [`program`](super::program)
/// keeps them in its memory, calls this and stores the result itself.
///
/// # Errors
///
/// Returns the error of the unit or of the driver.
pub fn fold<'dr, 'i, D: Driver<'dr>, U: Unit<'dr, D>>(
    dr: &mut D,
    unit: &U,
    start: U::State,
    inputs: impl IntoIterator<Item = &'i U::Input>,
) -> Result<U::State>
where
    U::Input: 'i,
{
    unit.scope(dr, |dr, scope| {
        let mut state = start;
        for input in inputs {
            state = unit.apply(dr, scope, state, input)?;
        }
        Ok(state)
    })
}

/// Runs page `page` of `walk`.
///
/// Starts from the interstitial of the page before, or from the initial
/// state for page zero. Applies the unit to the inputs of the page in
/// order, inside one scope ([`fold`]). Enforces that the result equals the
/// interstitial of `page`.
///
/// # Errors
///
/// Returns the error of the unit or of the driver.
///
/// # Panics
///
/// Panics if `page` is not a page of the walk.
pub fn page<'dr, D: Driver<'dr>, W: Walk<'dr, D>>(dr: &mut D, walk: &W, page: usize) -> Result<()> {
    let (capacity, len) = (walk.capacity(), walk.num_inputs());
    let pages = num_pages(capacity, len);
    assert!(
        page < pages,
        "page {page} is not a page of the walk ({pages} pages)"
    );

    let start = match page.checked_sub(1) {
        Some(before) => walk.interstitial(before),
        None => walk.initial(),
    }
    .clone();

    let inputs = range(capacity, page, len).map(|index| walk.input(index));
    let end = fold(dr, walk.unit(), start, inputs)?;

    end.enforce_equal(dr, walk.interstitial(page))
}

/// Computes the interstitials of a walk outside a circuit: the state after
/// each page, for a prover to fill the stage that holds them.
///
/// `apply` is the unit's operation on the values the prover computes with.
/// It must agree with the [`Unit`] the pages run, which the walk's tests
/// check. The result has [`num_pages`] states, and the last is the result
/// of the whole walk.
///
/// # Panics
///
/// Panics if `capacity` is zero.
pub fn interstitials<S: Clone, I>(
    capacity: usize,
    initial: S,
    inputs: &[I],
    mut apply: impl FnMut(&mut S, &I),
) -> Vec<S> {
    let pages = num_pages(capacity, inputs.len());
    let mut state = initial;
    let mut interstitials = Vec::with_capacity(pages);
    for page in 0..pages {
        for input in &inputs[range(capacity, page, inputs.len())] {
            apply(&mut state, input);
        }
        interstitials.push(state.clone());
    }
    interstitials
}

/// How the pages of a walk are cut into groups, and what each group's
/// stage and the links stage hold. See [the module's section on
/// groups](self#groups).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grouping {
    capacity: usize,
    num_inputs: usize,
    per_group: usize,
}

impl Grouping {
    /// Creates the grouping of a walk over `num_inputs` inputs at
    /// `capacity` applications per page into groups of `per_group` pages.
    /// A `per_group` of zero keeps the whole walk in one stage.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is zero.
    pub const fn new(capacity: usize, num_inputs: usize, per_group: usize) -> Self {
        assert!(capacity > 0, "a page applies its unit at least once");
        Grouping {
            capacity,
            num_inputs,
            per_group,
        }
    }

    /// Returns whether the walk is cut into groups that chain through
    /// links.
    pub const fn is_grouped(&self) -> bool {
        self.per_group > 0
    }

    /// Returns the number of pages of the whole walk.
    pub const fn pages(&self) -> usize {
        num_pages(self.capacity, self.num_inputs)
    }

    /// Returns the number of groups. A walk in one stage is one group.
    pub const fn groups(&self) -> usize {
        if self.is_grouped() {
            self.pages().div_ceil(self.per_group)
        } else {
            1
        }
    }

    /// Returns the interstitials a group's stage holds: one per page of a
    /// full group.
    pub const fn group_pages(&self) -> usize {
        if self.is_grouped() {
            self.per_group
        } else {
            self.pages()
        }
    }

    /// Returns the inputs a group's stage holds: the inputs of a full
    /// group.
    pub const fn group_inputs(&self) -> usize {
        if self.is_grouped() {
            self.per_group * self.capacity
        } else {
            self.num_inputs
        }
    }

    /// Returns the number of states the links stage holds: one per group
    /// boundary, or none for a walk in one stage.
    pub const fn links(&self) -> usize {
        if self.is_grouped() {
            self.groups() + 1
        } else {
            0
        }
    }

    /// Returns the group of page `page` of the walk and the page's index
    /// within that group.
    pub const fn locate(&self, page: usize) -> (usize, usize) {
        if self.is_grouped() {
            (page / self.per_group, page % self.per_group)
        } else {
            (0, page)
        }
    }

    /// Returns the inputs of the walk that group `group` holds. The last
    /// group can hold fewer than [`group_inputs`](Self::group_inputs).
    pub fn inputs_of(&self, group: usize) -> Range<usize> {
        range(self.group_inputs().max(1), group, self.num_inputs)
    }

    /// Returns the number of pages of group `group`. The last group can
    /// have fewer than [`group_pages`](Self::group_pages).
    ///
    /// # Panics
    ///
    /// Panics if `group` is not a group of the walk.
    pub fn pages_of(&self, group: usize) -> usize {
        assert!(
            group < self.groups(),
            "group {group} is not a group of the walk"
        );
        num_pages(self.capacity, self.inputs_of(group).len())
    }

    /// Computes the values of every group and of the links outside a
    /// circuit, for a prover to fill the stages.
    ///
    /// `apply` is the unit's operation, as for [`interstitials`]. A group
    /// shorter than a full one is padded: its unused inputs with `padding`
    /// and its unused interstitials with its exit state. No page reads the
    /// padding.
    pub fn arrange<S: Clone, I: Clone>(
        &self,
        initial: S,
        inputs: &[I],
        padding: I,
        mut apply: impl FnMut(&mut S, &I),
    ) -> Arranged<S, I> {
        assert_eq!(inputs.len(), self.num_inputs, "one value per input");
        let mut links = Vec::with_capacity(self.links());
        let mut groups = Vec::with_capacity(self.groups());
        let mut state = initial;
        if self.is_grouped() {
            links.push(state.clone());
        }
        for group in 0..self.groups() {
            let own = &inputs[self.inputs_of(group)];
            let mut interstitials = interstitials(self.capacity, state.clone(), own, &mut apply);
            let exit = interstitials.last().expect("a group has a page").clone();
            interstitials.resize(self.group_pages(), exit.clone());
            let mut padded = own.to_vec();
            padded.resize(self.group_inputs(), padding.clone());
            groups.push(Group {
                entry: state,
                inputs: padded,
                interstitials,
            });
            state = exit;
            if self.is_grouped() {
                links.push(state.clone());
            }
        }
        Arranged { links, groups }
    }
}

/// The values of one group: what its stage holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group<S, I> {
    /// The state before the group's first application.
    pub entry: S,
    /// The group's inputs, padded to a full group's.
    pub inputs: Vec<I>,
    /// The state after each of the group's pages, padded to a full
    /// group's.
    pub interstitials: Vec<S>,
}

/// The values of a grouped walk: what [`Grouping::arrange`] computes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Arranged<S, I> {
    /// The links: the walk's initial state, then the state after each
    /// group. Empty for a walk in one stage.
    pub links: Vec<S>,
    /// Each group's values.
    pub groups: Vec<Group<S, I>>,
}

/// Holds group `group` to the links: enforces that its `entry` state
/// equals link `group` and its `exit` state, the interstitial of its last
/// page, equals link `group + 1`.
///
/// The check circuit of each group calls this once. See [the module's
/// section on groups](self#groups).
///
/// # Errors
///
/// Returns the error of the driver.
///
/// # Panics
///
/// Panics if `links` has no link `group + 1`.
pub fn link<'dr, D: Driver<'dr>, T: Gadget<'dr, D, Kind: GadgetEquals<D::F>>>(
    dr: &mut D,
    links: &[T],
    group: usize,
    entry: &T,
    exit: &T,
) -> Result<()> {
    entry.enforce_equal(dr, &links[group])?;
    exit.enforce_equal(dr, &links[group + 1])
}

/// Horner's rule over curve points under an endoscalar: one application is
/// `[e] state + input`.
///
/// The applications of a page share a [`NonzeroBank`], which holds the
/// incomplete additions' exceptional cases to one check per page.
///
/// The unit does not enforce the wire contracts of the endoscalar or of the
/// points. See [the module's soundness conditions](self#soundness).
pub struct PointHorner<'a, 'dr, D: Driver<'dr>, C: Affine<Base = D::F>> {
    endoscalar: &'a HoistedEndoscalar<'dr, D>,
    _marker: core::marker::PhantomData<C>,
}

impl<'a, 'dr, D: Driver<'dr>, C: Affine<Base = D::F>> PointHorner<'a, 'dr, D, C> {
    /// Creates the unit that scales by `endoscalar`.
    pub fn new(endoscalar: &'a HoistedEndoscalar<'dr, D>) -> Self {
        PointHorner {
            endoscalar,
            _marker: core::marker::PhantomData,
        }
    }
}

impl<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> Unit<'dr, D> for PointHorner<'_, 'dr, D, C> {
    type State = Point<'dr, D, C>;
    type Input = Point<'dr, D, C>;
    type Scope = NonzeroBank<'dr, D>;

    fn scope<T>(
        &self,
        dr: &mut D,
        body: impl FnOnce(&mut D, &mut Self::Scope) -> Result<T>,
    ) -> Result<T> {
        NonzeroBank::scope(dr, body)
    }

    fn apply(
        &self,
        dr: &mut D,
        bank: &mut Self::Scope,
        state: Self::State,
        input: &Self::Input,
    ) -> Result<Self::State> {
        self.endoscalar
            .group_scale(dr, &state)?
            .add_incomplete(dr, input, bank)
    }
}

/// Horner's rule over field elements at a point: one application is
/// `state * x + input`.
///
/// An application costs one gate. The applications of a page share
/// nothing.
pub struct ElementHorner<'a, 'dr, D: Driver<'dr>> {
    point: &'a Element<'dr, D>,
}

impl<'a, 'dr, D: Driver<'dr>> ElementHorner<'a, 'dr, D> {
    /// Creates the unit that evaluates at `point`.
    pub fn new(point: &'a Element<'dr, D>) -> Self {
        ElementHorner { point }
    }
}

impl<'dr, D: Driver<'dr>> Unit<'dr, D> for ElementHorner<'_, 'dr, D> {
    type State = Element<'dr, D>;
    type Input = Element<'dr, D>;
    type Scope = ();

    fn scope<T>(
        &self,
        dr: &mut D,
        body: impl FnOnce(&mut D, &mut Self::Scope) -> Result<T>,
    ) -> Result<T> {
        body(dr, &mut ())
    }

    fn apply(
        &self,
        dr: &mut D,
        (): &mut Self::Scope,
        state: Self::State,
        input: &Self::Input,
    ) -> Result<Self::State> {
        Ok(state.mul(dr, self.point)?.add(dr, input))
    }
}

#[cfg(test)]
#[path = "../../../tests/paging.rs"]
mod tests;

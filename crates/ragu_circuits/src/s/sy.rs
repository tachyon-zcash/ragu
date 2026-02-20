//! Evaluates $s(X, y)$ at fixed $y$.
//!
//! This module provides [`eval`], which computes $s(X, y)$: the wiring
//! polynomial evaluated at a concrete $y$, yielding a univariate polynomial in
//! $X$. See the [parent module][`super`] for background on $s(X, Y)$.
//!
//! # Design
//!
//! Unlike [`sx`] which can build coefficients incrementally, $s(X, y)$
//! coefficients cannot be computed in a strictly streaming order during
//! synthesis.
//!
//! ### Why Deferred Computation?
//!
//! Consider the coefficient of $X^j$ in $s(X, y)$: it equals $\sum\_{q=0}^{Q-1}
//! \mathbf{U}\_{j,q} \cdot y^q$, where $\mathbf{U}\_{j,q}$ is determined by
//! which wires appear in constraint $q$ and $Q$ is the total constraint count.
//! During synthesis, constraints arrive one at a time—we learn $U\_{j,0}$ from
//! the first constraint, $U\_{j,1}$ from the second, and so on. The complete
//! coefficient of $X^j$ remains unknown until all $q$ constraints have been
//! processed.
//!
//! This contrasts with [`sx`], where each constraint produces a complete
//! coefficient $c\_j$ that can be stored immediately (because the $Y$ powers
//! are symbolic, not evaluated).
//!
//! ### Virtual Wire Algorithm
//!
//! We use **virtual wires** to defer coefficient computation until all
//! constraints are known:
//!
//! 1. **Allocate virtual wires** — When [`Driver::add`] creates a linear
//!    combination, allocate a virtual wire from [`VirtualTable`] to represent
//!    it.
//!
//! 2. **Track references** — Each virtual wire maintains a refcount. Storing a
//!    reference (e.g., in another virtual wire's term list) increments it;
//!    dropping a [`Wire`] handle decrements it.
//!
//! 3. **Resolve on zero refcount** — When a virtual wire's refcount reaches
//!    zero, it *resolves*: distribute its accumulated $y$-power value to all
//!    constituent terms, then recursively free those terms.
//!
//! 4. **Cascading to allocated wires** — Resolution cascades through the
//!    virtual wire graph until reaching allocated wires ($a$, $b$, $c$), where
//!    values are written directly to the backward view of the polynomial.
//!
//! ### Backward View
//!
//! The wiring constraint $\langle\langle r(X), s(X, y) \rangle\rangle = k(y)$
//! uses a "revdot" inner product: coefficients of $r(X)$ are matched against
//! coefficients of $s(X, y)$ in a specific order based on wire type. Rather
//! than building a flat coefficient vector and reinterpreting it, the backward
//! view provides direct access to the $a$, $b$, and $c$ coefficient regions.
//! See [`structured::View`] for details.
//!
//! ### Coefficient Order
//!
//! The output polynomial $s(X, y)$ has its coefficients stored in structured
//! form via [`structured::View`]. Each wire type ($a$, $b$, $c$) occupies a
//! separate coefficient region with its appropriate exponent range.
//!
//! [`common`]: super::common
//! [`sx`]: super::sx
//! [`sxy`]: super::sxy
//! [`Driver::add`]: ragu_core::drivers::Driver::add
//! [`structured::View`]: crate::polynomials::structured::View

use ff::Field;
use ragu_arithmetic::Coeff;
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverTypes, LinearExpression, emulator::Emulator},
    gadgets::{Bound, GadgetKind},
    maybe::Empty,
    routines::Routine,
};
use ragu_primitives::GadgetExt;

use alloc::{vec, vec::Vec};
use core::cell::RefCell;

use super::DriverExt;
use crate::{
    Circuit, DriverScope,
    floor_planner::RoutineSlot,
    polynomials::{Rank, structured},
    registry,
};

/// An index identifying a wire in the evaluator.
///
/// During $s(X, y)$ evaluation, wires are either *allocated* (from
/// multiplication gates) or *virtual* (from linear combinations via
/// [`Driver::add`]).
///
/// # Variants
///
/// - `A(i)`, `B(i)`, `C(i)` — Allocated wires from gate $i$, corresponding to
///   the $a$, $b$, $c$ wires respectively. Values are written directly to the
///   backward view when resolved.
///
/// - `Virtual(i)` — A virtual wire (linear combination) at index $i$ in the
///   [`VirtualTable`]. Uses reference counting for deferred resolution.
///
/// [`Driver::add`]: ragu_core::drivers::Driver::add
#[derive(Copy, Clone)]
enum WireIndex {
    A(usize),
    B(usize),
    C(usize),
    Virtual(usize),
}

/// A handle to a wire in the $s(X, y)$ evaluator.
///
/// Wires represent either allocated wires (from multiplication gates) or
/// virtual wires (from linear combinations). The handle tracks a reference to
/// the [`VirtualTable`] for managing reference counts.
///
/// # Reference Counting
///
/// For virtual wires, the reference count tracks both owned `Wire` handles and
/// stored references in other virtual wires' term lists. Cloning a `Wire`
/// increments the refcount; dropping decrements it. When a virtual wire's
/// refcount reaches zero, it resolves (see [`VirtualTable::free`]).
///
/// For allocated wires (`A`, `B`, `C`), reference counting is a no-op since
/// these wires write directly to the backward view upon resolution.
///
/// # The `ONE` Wire
///
/// The constant [`Driver::ONE`] is the $c$ wire from gate 0. Since `const`
/// items cannot hold references, `ONE` uses `table: None`. This is safe because
/// the ONE wire is allocated (not virtual) and needs no reference counting.
///
/// [`Driver::ONE`]: ragu_core::drivers::Driver::ONE
struct Wire<'table, 'sy, F: Field, R: Rank> {
    /// Index identifying this wire as allocated (A/B/C) or virtual.
    index: WireIndex,
    /// Reference to the virtual table for refcount management.
    ///
    /// `None` only for the [`Driver::ONE`]
    /// constant, which is an allocated wire that needs no refcounting.
    table: Option<&'table RefCell<VirtualTable<'sy, F, R>>>,
}

impl<'table, 'sy, F: Field, R: Rank> Wire<'table, 'sy, F, R> {
    fn new(index: WireIndex, table: &'table RefCell<VirtualTable<'sy, F, R>>) -> Self {
        Wire {
            index,
            table: Some(table),
        }
    }

    /// Increments the refcount for this wire to register storing a reference.
    ///
    /// This is used when storing a wire reference in a term vector (e.g., in a
    /// virtual wire's linear combination). The refcount will be decremented when
    /// the virtual wire is freed and its terms are resolved.
    ///
    /// For non-virtual wires (A, B, C), this is a no-op.
    fn increment_refcount(&self) {
        if let WireIndex::Virtual(index) = self.index {
            self.table.unwrap().borrow_mut().wires[index].refcount += 1;
        }
    }
}

impl<F: Field, R: Rank> Clone for Wire<'_, '_, F, R> {
    fn clone(&self) -> Self {
        if let WireIndex::Virtual(index) = self.index {
            self.table.unwrap().borrow_mut().wires[index].refcount += 1;
        }

        Wire {
            index: self.index,
            table: self.table,
        }
    }
}

impl<F: Field, R: Rank> Drop for Wire<'_, '_, F, R> {
    fn drop(&mut self) {
        if let WireIndex::Virtual(_) = self.index {
            self.table.as_ref().unwrap().borrow_mut().free(self.index);
        }
    }
}

/// A virtual wire representing a linear combination of other wires.
///
/// Virtual wires accumulate references to other wires (virtual or allocated)
/// in their `terms` vector. The reference count tracks:
/// 1. Owned [`Wire`] handles that reference this virtual wire
/// 2. References stored in other virtual wires' `terms` vectors
///
/// When the refcount reaches zero, the virtual wire is **resolved**—see
/// [`VirtualTable::free`].
///
/// # Lifecycle
///
/// Virtual wires transition through these states:
///
/// 1. **Allocated** — Freshly allocated from [`VirtualTable::alloc`]. The wire
///    has `refcount = 1`, `terms = []`, and `value = Zero`.
///
/// 2. **Active** — In use with `refcount >= 1`. Terms may be populated via
///    [`VirtualTable::update`], and `value` accumulates contributions from
///    [`Driver::enforce_zero`] calls.
///
/// 3. **Freed** — Refcount reached zero, triggering resolution. The `value` is
///    distributed to all terms, `terms` is drained, `value` is cleared, and the
///    index is pushed to the free list for reuse.
///
/// [`Driver::enforce_zero`]: ragu_core::drivers::Driver::enforce_zero
struct VirtualWire<F: Field> {
    /// Reference count: number of owned [`Wire`] handles + stored term
    /// references pointing to this virtual wire.
    refcount: usize,

    /// Terms in this virtual wire's linear combination.
    ///
    /// Each entry `(wire_index, coeff)` represents a term `coeff * wire`. When
    /// this virtual wire is stored in another's term list, we increment the
    /// target's refcount; when resolved, we decrement and propagate values.
    terms: Vec<(WireIndex, Coeff<F>)>,

    /// Accumulated $y^j$ coefficient value for this virtual wire.
    ///
    /// Each [`Driver::enforce_zero`] call that references this wire adds its
    /// $y^j$ contribution here (where $j$ is the constraint index). Upon
    /// resolution, this value is distributed to all terms.
    ///
    /// [`Driver::enforce_zero`]: ragu_core::drivers::Driver::enforce_zero
    value: Coeff<F>,
}

/// Manages virtual wires and the backward view into $s(X, y)$.
///
/// The virtual table maintains:
/// - A vector of [`VirtualWire`]s representing deferred linear combinations
/// - A free list for reusing virtual wire slots after resolution
/// - A backward view into the structured polynomial for direct coefficient access
///
/// See [`Self::free`] for the resolution algorithm and reference counting details.
struct VirtualTable<'sy, F: Field, R: Rank> {
    /// All virtual wires, indexed by [`WireIndex::Virtual`] values.
    ///
    /// Wires may be active (refcount > 0) or freed (refcount = 0, index in
    /// `free` list). Freed slots are reused by [`Self::alloc`].
    wires: Vec<VirtualWire<F>>,

    /// Indices of freed virtual wires available for reuse.
    ///
    /// When a virtual wire's refcount reaches zero in [`Self::free`], its index
    /// is pushed here. [`Self::alloc`] pops from this list before growing
    /// `wires`.
    free: Vec<usize>,

    /// Backward view into the structured polynomial $s(X, y)$.
    ///
    /// Provides direct mutable access to the $a$, $b$, $c$ coefficient vectors.
    /// When allocated wires (A/B/C) receive values during resolution, they are
    /// written here. See the [module documentation](self) for the backward view
    /// concept.
    sy: structured::View<'sy, F, R, structured::Backward>,
}

impl<F: Field, R: Rank> VirtualTable<'_, F, R> {
    fn add(&mut self, index: WireIndex, value: Coeff<F>) {
        *match index {
            WireIndex::A(i) => &mut self.sy.a[i],
            WireIndex::B(i) => &mut self.sy.b[i],
            WireIndex::C(i) => &mut self.sy.c[i],
            WireIndex::Virtual(i) => {
                self.wires[i].value = self.wires[i].value + value;
                return;
            }
        } += value.value();
    }

    /// Decrements the refcount of a virtual wire and **resolves** it (by adding
    /// to the `self.free` vector) if the count reaches zero.
    ///
    /// Resolved virtual wires distribute their accumulated value to all
    /// constituent terms, which are then recursively freed. This cascading
    /// resolution eventually reaches allocated wires (A, B, C) where the values
    /// are written to the polynomial.
    fn free(&mut self, index: WireIndex) {
        if let WireIndex::Virtual(index) = index {
            // Invariant: refcount must be positive before decrementing.
            assert!(self.wires[index].refcount > 0);
            self.wires[index].refcount -= 1;

            if self.wires[index].refcount == 0 {
                let mut terms = vec![];
                core::mem::swap(&mut terms, &mut self.wires[index].terms);
                let value = self.wires[index].value;
                for (wire, coeff) in terms.drain(..) {
                    self.add(wire, value * coeff);
                    self.free(wire);
                }
                self.wires[index].value = Coeff::Zero;
                self.free.push(index);
            }
        }
    }

    /// Updates the terms of a virtual wire.
    fn update(&mut self, index: WireIndex, terms: Vec<(WireIndex, Coeff<F>)>) {
        match index {
            WireIndex::Virtual(index) => {
                self.wires[index].terms = terms;
            }
            _ => unreachable!(),
        }
    }

    /// Allocates a new virtual wire.
    fn alloc(&mut self) -> WireIndex {
        match self.free.pop() {
            Some(index) => {
                // Invariant: freed wires must have been fully resolved—refcount
                // zero, value cleared, and terms drained.
                assert_eq!(self.wires[index].refcount, 0);
                assert!(self.wires[index].value.is_zero());
                assert!(self.wires[index].terms.is_empty());

                self.wires[index].refcount = 1;
                WireIndex::Virtual(index)
            }
            None => {
                let index = self.wires.len();
                self.wires.push(VirtualWire {
                    refcount: 1,
                    terms: vec![],
                    value: Coeff::Zero,
                });
                WireIndex::Virtual(index)
            }
        }
    }
}

/// Per-routine state saved and restored across routine boundaries.
struct SyScope<'table, 'sy, F: Field, R: Rank> {
    /// Stashed $b$ wire from paired allocation.
    available_b: Option<Wire<'table, 'sy, F, R>>,
    /// Current $y$ power being applied to constraints in this routine.
    current_y: F,
    /// Number of multiplication gates consumed so far in this routine.
    multiplication_constraints: usize,
    /// Number of linear constraints processed so far in this routine.
    linear_constraints: usize,
}

/// A [`Driver`] that computes $s(X, y)$ at a fixed $y$.
///
/// Given a fixed evaluation point $y \in \mathbb{F}$, this driver interprets
/// circuit synthesis operations to produce the structured polynomial $s(X, y)$.
/// Unlike [`sx`] and [`sxy`] which use immediate evaluation, this driver uses
/// deferred computation through virtual wires (see [module documentation](self)).
///
/// [`Driver`]: ragu_core::drivers::Driver
/// [`sx`]: super::sx
/// [`sxy`]: super::sxy
struct Evaluator<'table, 'sy, 'fp, F: Field, R: Rank> {
    /// Per-routine scoped state.
    scope: SyScope<'table, 'sy, F, R>,

    /// The evaluation point $y$.
    y: F,

    /// Cached inverse $y^{-1}$, used to step through decreasing powers of $y$.
    y_inv: F,

    /// Reference to the virtual table for wire management.
    ///
    /// Shared via [`RefCell`] to allow mutable access during synthesis while
    /// maintaining multiple [`Wire`] handles.
    virtual_table: &'table RefCell<VirtualTable<'sy, F, R>>,

    /// Floor plan mapping DFS routine index to absolute offsets.
    floor_plan: &'fp [RoutineSlot],

    /// Global monotonic DFS counter for routine entries.
    current_routine: usize,

    /// Marker for the rank type parameter.
    _marker: core::marker::PhantomData<R>,
}

/// Collects wire references when building a linear combination via [`Driver::add`].
///
/// This accumulator builds a term list for a virtual wire. Each wire reference
/// added increments that wire's refcount (for virtual wires), establishing the
/// reference graph used during deferred resolution.
///
/// # Contrast with [`sxy`]
///
/// In [`sx`] and [`sxy`], [`WireEvalSum`] immediately evaluates linear
/// combinations to field elements. Here, `TermCollector` builds a symbolic
/// term list for later resolution, since coefficients of $s(X, y)$ cannot be
/// computed until all constraints are known.
///
/// [`Driver::add`]: ragu_core::drivers::Driver::add
/// [`sx`]: super::sx
/// [`sxy`]: super::sxy
/// [`WireEvalSum`]: super::common::WireEvalSum
struct TermCollector<F: Field> {
    /// Accumulated terms: pairs of (wire index, coefficient).
    terms: Vec<(WireIndex, Coeff<F>)>,

    /// Coefficient multiplier for subsequently added terms.
    gain: Coeff<F>,
}

impl<F: Field> TermCollector<F> {
    fn new() -> Self {
        TermCollector {
            terms: vec![],
            gain: Coeff::One,
        }
    }
}

impl<'table, 'sy, F: Field, R: Rank> LinearExpression<Wire<'table, 'sy, F, R>, F>
    for TermCollector<F>
{
    fn add_term(mut self, wire: &Wire<'table, 'sy, F, R>, coeff: Coeff<F>) -> Self {
        wire.increment_refcount();
        self.terms.push((wire.index, coeff * self.gain));
        self
    }

    fn gain(mut self, coeff: Coeff<F>) -> Self {
        self.gain = self.gain * coeff;
        self
    }
}

/// Directly enforces a linear constraint by distributing $y^j$ values.
///
/// Used by [`Driver::enforce_zero`] to add weighted contributions to wires.
/// Unlike [`TermCollector`] which builds a term list for deferred resolution,
/// `TermEnforcer` immediately adds `current_y * coeff` to each wire's
/// accumulated value in the virtual table.
///
/// # Tuple Fields
///
/// - `.0` — Reference to the [`VirtualTable`] for value distribution.
/// - `.1` — The $y^j$ coefficient for this constraint (from `current_y`).
///
/// [`Driver::enforce_zero`]: ragu_core::drivers::Driver::enforce_zero
struct TermEnforcer<'table, 'sy, F: Field, R: Rank>(
    &'table RefCell<VirtualTable<'sy, F, R>>,
    Coeff<F>,
);
impl<'table, 'sy, F: Field, R: Rank> LinearExpression<Wire<'table, 'sy, F, R>, F>
    for TermEnforcer<'table, 'sy, F, R>
{
    fn add_term(self, wire: &Wire<'table, 'sy, F, R>, coeff: Coeff<F>) -> Self {
        self.0.borrow_mut().add(wire.index, coeff * self.1);
        self
    }

    fn gain(mut self, coeff: Coeff<F>) -> Self {
        self.1 = self.1 * coeff;
        self
    }
}

impl<'table, 'sy, F: Field, R: Rank> DriverScope<SyScope<'table, 'sy, F, R>>
    for Evaluator<'table, 'sy, '_, F, R>
{
    fn scope(&mut self) -> &mut SyScope<'table, 'sy, F, R> {
        &mut self.scope
    }
}

/// Configures associated types for the [`Evaluator`] driver.
///
/// - `MaybeKind = Empty`: No witness values are needed; we only compute
///   polynomial structure.
/// - `LCadd`: Uses [`TermCollector`] to build deferred term lists for virtual
///   wires.
/// - `LCenforce`: Uses [`TermEnforcer`] to immediately distribute $y^j$
///   contributions.
/// - `ImplWire`: [`Wire`] handles with reference counting for virtual wires.
impl<'table, 'sy, F: Field, R: Rank> DriverTypes for Evaluator<'table, 'sy, '_, F, R> {
    type MaybeKind = Empty;
    type LCadd = TermCollector<F>;
    type LCenforce = TermEnforcer<'table, 'sy, F, R>;
    type ImplField = F;
    type ImplWire = Wire<'table, 'sy, F, R>;
}

impl<'table, 'sy, F: Field, R: Rank> Driver<'table> for Evaluator<'table, 'sy, '_, F, R> {
    type F = F;
    type Wire = Wire<'table, 'sy, F, R>;

    const ONE: Self::Wire = Wire {
        index: WireIndex::C(0),
        table: None,
    };

    /// Allocates a wire using paired allocation.
    ///
    /// Returns either a stashed $b$ wire from a previous gate, or allocates a
    /// new gate and stashes its $b$ wire for the next call.
    fn alloc(&mut self, _: impl Fn() -> Result<Coeff<Self::F>>) -> Result<Self::Wire> {
        if let Some(wire) = self.scope.available_b.take() {
            Ok(wire)
        } else {
            let (a, b, _) = self.mul(|| unreachable!())?;
            self.scope.available_b = Some(b);

            Ok(a)
        }
    }

    /// Consumes a multiplication gate, returning wire handles for $(a, b, c)$.
    ///
    /// The gate index comes from the absolute floor-plan position tracked in
    /// `scope.multiplication_constraints`. Backward view slots are
    /// pre-allocated, so no push is needed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MultiplicationBoundExceeded`] if the gate count reaches
    /// [`Rank::n()`].
    fn mul(
        &mut self,
        _: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(Self::Wire, Self::Wire, Self::Wire)> {
        let index = self.scope.multiplication_constraints;
        if index == R::n() {
            return Err(Error::MultiplicationBoundExceeded(R::n()));
        }
        self.scope.multiplication_constraints += 1;

        let a = Wire::new(WireIndex::A(index), self.virtual_table);
        let b = Wire::new(WireIndex::B(index), self.virtual_table);
        let c = Wire::new(WireIndex::C(index), self.virtual_table);

        Ok((a, b, c))
    }

    /// Creates a virtual wire representing a linear combination.
    ///
    /// Allocates a new virtual wire from [`VirtualTable`], collects terms via
    /// [`TermCollector`], and stores them in the virtual wire. The returned
    /// [`Wire`] handle owns one reference to the virtual wire.
    fn add(&mut self, lc: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {
        let wire = self.virtual_table.borrow_mut().alloc();
        let terms = lc(TermCollector::new()).terms;
        self.virtual_table.borrow_mut().update(wire, terms);

        Wire {
            index: wire,
            table: Some(self.virtual_table),
        }
    }

    /// Applies a linear constraint weighted by the current $y$ power.
    ///
    /// Distributes `current_y * coeff` to each wire in the linear combination
    /// via [`TermEnforcer`], then advances `current_y` by multiplying with
    /// `y_inv` (implementing reverse Horner iteration).
    ///
    /// # Errors
    ///
    /// Returns [`Error::LinearBoundExceeded`] if the constraint count reaches
    /// [`Rank::num_coeffs()`].
    fn enforce_zero(&mut self, lc: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        let q = self.scope.linear_constraints;
        if q == R::num_coeffs() {
            return Err(Error::LinearBoundExceeded(R::num_coeffs()));
        }
        self.scope.linear_constraints += 1;

        lc(TermEnforcer(
            self.virtual_table,
            Coeff::Arbitrary(self.scope.current_y),
        ));

        self.scope.current_y *= self.y_inv;

        Ok(())
    }

    fn routine<Ro: Routine<Self::F> + 'table>(
        &mut self,
        routine: Ro,
        input: Bound<'table, Self, Ro::Input>,
    ) -> Result<Bound<'table, Self, Ro::Output>> {
        self.current_routine += 1;
        let slot = &self.floor_plan[self.current_routine];
        // Routine's y-power starts at y^{linear_start + num_linear_constraints - 1}
        // and decrements through the routine's linear constraint range.
        let init_scope = SyScope {
            available_b: None,
            // When num_linear_constraints == 0 the routine emits no
            // enforce_zero calls, so current_y is never read; use
            // F::ZERO as an inert sentinel.
            current_y: if slot.num_linear_constraints == 0 {
                F::ZERO
            } else {
                self.y
                    .pow_vartime([(slot.linear_start + slot.num_linear_constraints - 1) as u64])
            },
            multiplication_constraints: slot.multiplication_start,
            linear_constraints: slot.linear_start,
        };

        self.with_scope(init_scope, |this| {
            let mut dummy = Emulator::wireless();
            let dummy_input = Ro::Input::map_gadget(&input, &mut dummy)?;
            let aux = routine.predict(&mut dummy, &dummy_input)?.into_aux();
            let result = routine.execute(this, input, aux)?;

            // Verify this routine consumed exactly the expected constraints.
            assert_eq!(
                this.scope.multiplication_constraints,
                slot.multiplication_start + slot.num_multiplication_constraints,
                "routine multiplication constraint count must match floor plan"
            );
            assert_eq!(
                this.scope.linear_constraints,
                slot.linear_start + slot.num_linear_constraints,
                "routine linear constraint count must match floor plan"
            );

            Ok(result)
        })
    }
}

/// Evaluates the wiring polynomial $s(X, y)$ at a fixed $y$.
///
/// Returns a structured polynomial in $X$ with coefficients computed via
/// deferred evaluation through virtual wires. See the [module
/// documentation](self) for the algorithm overview.
///
/// # Arguments
///
/// - `circuit`: The circuit whose wiring polynomial to evaluate.
/// - `y`: The evaluation point for the $Y$ variable.
/// - `key`: The registry key that binds this evaluation to a [`Registry`] context by
///   enforcing `key_wire - key = 0` as a constraint. This randomizes
///   evaluations of $s(X, y)$, preventing trivial forgeries across registry
///   contexts.
/// - `floor_plan`: Per-routine absolute offsets, computed by
///   [`floor_plan()`](crate::floor_planner::floor_plan). The root routine's
///   `num_linear_constraints` determines the initial `current_y = y^{q-1}` for
///   reverse Horner iteration.
///
/// [`Registry`]: crate::registry::Registry
pub fn eval<F: Field, C: Circuit<F>, R: Rank>(
    circuit: &C,
    y: F,
    key: &registry::Key<F>,
    floor_plan: &[RoutineSlot],
) -> Result<structured::Polynomial<F, R>> {
    let mut sy = structured::Polynomial::<F, R>::new();

    if y == F::ZERO {
        // If y is zero, all terms y^j for j > 0 vanish, leaving only the ONE
        // wire coefficient.
        sy.backward().c.push(F::ONE);
        return Ok(sy);
    }

    let total_multiplications: usize = floor_plan
        .iter()
        .map(|s| s.num_multiplication_constraints)
        .sum();

    // Root routine's linear constraint count (for initial current_y).
    // The root always has at least the registry key and ONE constraints.
    let root_linear_constraints = floor_plan[0].num_linear_constraints;
    assert!(
        root_linear_constraints > 0,
        "root routine must have at least one linear constraint"
    );

    {
        let virtual_table = RefCell::new(VirtualTable::<F, R> {
            wires: vec![],
            free: vec![],
            sy: sy.backward(),
        });

        // Pre-allocate backward view slots for all multiplication gates.
        {
            let mut table = virtual_table.borrow_mut();
            table.sy.a.resize(total_multiplications, F::ZERO);
            table.sy.b.resize(total_multiplications, F::ZERO);
            table.sy.c.resize(total_multiplications, F::ZERO);
        }

        {
            let mut evaluator = Evaluator::<'_, '_, '_, F, R> {
                scope: SyScope {
                    available_b: None,
                    // Assertion above prevents this from underflowing.
                    current_y: y.pow_vartime([(root_linear_constraints - 1) as u64]),
                    multiplication_constraints: 0,
                    linear_constraints: 0,
                },
                y,
                y_inv: y.invert().expect("y is not zero"),
                virtual_table: &virtual_table,
                floor_plan,
                current_routine: 0,
                _marker: core::marker::PhantomData,
            };

            // Allocate the key_wire and ONE wires
            let (key_wire, _, _one) = evaluator.mul(|| unreachable!())?;

            // Registry key constraint
            evaluator.enforce_registry_key(&key_wire, key)?;

            let mut outputs = vec![];
            let (io, _) = circuit.witness(&mut evaluator, Empty)?;
            io.write(&mut evaluator, &mut outputs)?;

            // Enforcing public inputs
            evaluator.enforce_public_outputs(outputs.iter().map(|output| output.wire()))?;
            evaluator.enforce_one()?;

            // Verify all floor plan slots were consumed and counts match.
            assert_eq!(
                evaluator.current_routine + 1,
                evaluator.floor_plan.len(),
                "floor plan routine count must match synthesis"
            );
            assert_eq!(
                evaluator.scope.multiplication_constraints,
                evaluator.floor_plan[0].num_multiplication_constraints,
                "root multiplication constraint count must match floor plan"
            );
            assert_eq!(
                evaluator.scope.linear_constraints, evaluator.floor_plan[0].num_linear_constraints,
                "root linear constraint count must match floor plan"
            );
        }

        // Invariant: all virtual wires must have been freed during synthesis,
        // indicating proper reference counting and no leaked wires.
        let virtual_table = virtual_table.into_inner();
        assert_eq!(virtual_table.free.len(), virtual_table.wires.len());
    }

    Ok(sy)
}

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
//! constraint emission.
//!
//! ### Why Deferred Computation?
//!
//! Consider the coefficient of $X^j$ in $s(X, y)$: it equals $\sum\_{q=0}^{Q-1}
//! \mathbf{U}\_{j,q} \cdot y^q$, where $\mathbf{U}\_{j,q}$ is determined by
//! which wires appear in constraint $q$ and $Q$ is the total constraint count.
//! During constraint emission, constraints arrive one at a time—we learn
//! $U\_{j,0}$ from the first constraint, $U\_{j,1}$ from the second, and so on.
//! The complete coefficient of $X^j$ remains unknown until all $q$ constraints
//! have been processed.
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
//!    virtual wire graph until reaching allocated wires ($a$, $b$, $c$, $d$), where
//!    values are written directly to the wiring view of the polynomial.
//!
//! ### Wiring View
//!
//! The wiring constraint $\langle\langle r(X), s(X, y) \rangle\rangle = k(y)$
//! uses a "revdot" inner product: coefficients of $r(X)$ are matched against
//! coefficients of $s(X, y)$ in a specific order based on wire type. Rather
//! than building a flat coefficient vector and reinterpreting it, the wiring
//! view provides direct access to the $a$, $b$, $c$, and $d$ coefficient regions.
//! See [`sparse::View`] for details.
//!
//! [`sx`]: super::sx
//! [`sxy`]: super::sxy
//! [`Driver::add`]: ragu_core::drivers::Driver::add
//! [`sparse::View`]: crate::polynomials::sparse::View

use alloc::{vec, vec::Vec};
use core::cell::{RefCell, RefMut};

use ragu_core::{
    Coeff, Error, Result,
    convert::{StripWires, WireMap},
    drivers::{
        Driver, DriverTypes, LinearExpression,
        emulator::{Emulator, Wireless},
    },
    gadgets::{Bound, GadgetKind as _},
    maybe::Empty,
    routines::Routine,
};
use udon::field::Field;

use super::{
    memo::{MemoCache, Placement, WireInjector},
    record::{self, Recorded, Term, WireRef},
};
use crate::{
    DeepFingerprint, DriverScope, RoutineIdentity, SegmentRecord,
    floor_planner::ConstraintSegment,
    polynomials::{Rank, sparse},
    raw::RawCircuit,
};

/// An index identifying a wire in the evaluator.
///
/// During $s(X, y)$ evaluation, wires are either *allocated* (from
/// multiplication gates) or *virtual* (from linear combinations via
/// [`Driver::add`]).
///
/// # Variants
///
/// - `A(i)`, `B(i)`, `C(i)`, `D(i)` — Allocated wires from gate $i$, corresponding
///   to the $a$, $b$, $c$, $d$ wires respectively. Values are written directly to the
///   wiring view when resolved.
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
    D(usize),
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
/// For allocated wires (`A`, `B`, `C`, `D`), reference counting is a no-op since
/// these wires write directly to the wiring view upon resolution.
///
/// # The `ONE` Wire
///
/// The constant [`Driver::ONE`] is the $d$ wire of the SYSTEM gate. Since `const`
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

/// Manages virtual wires and the coefficient buffers for the wiring view of $s(X, y)$.
///
/// The virtual table maintains:
/// - A vector of [`VirtualWire`]s representing deferred linear combinations
/// - A free list for reusing virtual wire slots after resolution
/// - Mutable references to the wiring view's $a$, $b$, $c$ coefficient vectors
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

    /// Wiring-view wire buffers for the polynomial $s(X, y)$.
    ///
    /// Provides direct mutable access to the $a$, $b$, $c$, $d$ coefficient
    /// vectors. When allocated wires (A/B/C/D) receive values during
    /// resolution, they are written here. See the [module documentation](self)
    /// for the wiring view concept.
    a: &'sy mut Vec<F>,
    b: &'sy mut Vec<F>,
    c: &'sy mut Vec<F>,
    d: &'sy mut Vec<F>,

    _marker: core::marker::PhantomData<R>,
}

impl<F: Field, R: Rank> VirtualTable<'_, F, R> {
    fn add(&mut self, index: WireIndex, value: Coeff<F>) {
        *match index {
            WireIndex::A(i) => &mut self.a[i],
            WireIndex::B(i) => &mut self.b[i],
            WireIndex::C(i) => &mut self.c[i],
            WireIndex::D(i) => &mut self.d[i],
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
    /// resolution eventually reaches allocated wires (A, B, C, D) where the values
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
struct SyScope<F: Field> {
    /// Current $y$ power being applied to constraints in this routine.
    current_y: F,
    /// Absolute index of the next gate to be written.
    /// Initialized to `segment.gate_start` on routine entry.
    gates: usize,
    /// Absolute index of the next constraint to be written.
    /// Initialized to `segment.constraint_start` on routine entry.
    constraints: usize,
}

/// A [`Driver`] that computes $s(X, y)$ at a fixed $y$.
///
/// Given a fixed evaluation point $y \in \mathbb{F}$, this driver interprets
/// circuit operations to produce the polynomial $s(X, y)$. Unlike [`sx`] and
/// [`sxy`] which use immediate evaluation, this driver uses deferred
/// computation through virtual wires (see [module documentation](self)).
///
/// [`Driver`]: ragu_core::drivers::Driver
/// [`sx`]: super::sx
/// [`sxy`]: super::sxy
struct Evaluator<'table, 'sy, 'fp, F: Field, R: Rank> {
    /// Per-routine scoped state.
    scope: SyScope<F>,

    /// The evaluation point $y$.
    y: F,

    /// Cached inverse $y^{-1}$, used to step through decreasing powers of $y$.
    y_inv: F,

    /// Reference to the virtual table for wire management.
    ///
    /// Shared via [`RefCell`] to allow mutable access during constraint
    /// emission while maintaining multiple [`Wire`] handles.
    virtual_table: &'table RefCell<VirtualTable<'sy, F, R>>,

    /// Floor plan mapping DFS segment index to absolute offsets.
    floor_plan: &'fp [ConstraintSegment],

    /// Global monotonic DFS counter for routine entries.
    current_routine: usize,

    /// Per-segment constraint records (from metrics), used to extract fingerprints.
    segment_records: &'fp [SegmentRecord],

    /// Cache for memoized routine contributions (optional).
    memo_cache: Option<&'fp mut MemoCache<F>>,

    /// Routine nesting depth; memoization only applies at depth 0.
    routine_depth: usize,

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
/// In [`sx`] and [`sxy`], a [`DirectSum`] accumulator immediately evaluates
/// linear combinations to field elements. Here, `TermCollector` builds a
/// symbolic term list for later resolution, since coefficients of $s(X, y)$
/// cannot be computed until all constraints are known.
///
/// [`Driver::add`]: ragu_core::drivers::Driver::add
/// [`sx`]: super::sx
/// [`sxy`]: super::sxy
/// [`DirectSum`]: ragu_core::drivers::DirectSum
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

/// Directly enforces a constraint by distributing $y^j$ values.
///
/// Used by [`Driver::enforce_zero`] to add weighted contributions to wires.
/// Unlike [`TermCollector`] which builds a term list for deferred resolution,
/// `TermEnforcer` immediately adds `current_y * coeff` to each wire's
/// accumulated value in the virtual table.
///
/// # Tuple Fields
///
/// - `.0` — Mutable borrow of the [`VirtualTable`] for value distribution,
///   held for the duration of the linear combination to avoid repeated
///   [`RefCell::borrow_mut`] calls.
/// - `.1` — The $y^j$ coefficient for this constraint (from `current_y`).
///
/// [`Driver::enforce_zero`]: ragu_core::drivers::Driver::enforce_zero
struct TermEnforcer<'table, 'sy, F: Field, R: Rank>(
    RefMut<'table, VirtualTable<'sy, F, R>>,
    Coeff<F>,
);
impl<'table, 'sy, F: Field, R: Rank> LinearExpression<Wire<'table, 'sy, F, R>, F>
    for TermEnforcer<'table, 'sy, F, R>
{
    fn add_term(mut self, wire: &Wire<'table, 'sy, F, R>, coeff: Coeff<F>) -> Self {
        self.0.add(wire.index, coeff * self.1);
        self
    }

    fn gain(mut self, coeff: Coeff<F>) -> Self {
        self.1 = self.1 * coeff;
        self
    }
}

/// Collects a gadget's wire indices.
struct IndexExtractor<Src> {
    indices: Vec<WireIndex>,
    _marker: core::marker::PhantomData<Src>,
}

impl<'table, 'sy: 'table, F, R, Src> WireMap<F> for IndexExtractor<Src>
where
    F: Field,
    R: Rank,
    Src: DriverTypes<ImplField = F, ImplWire = Wire<'table, 'sy, F, R>>,
{
    type Src = Src;
    type Dst = Emulator<Wireless<Empty, F>>;

    fn convert_wire(&mut self, wire: &Wire<'table, 'sy, F, R>) -> Result<()> {
        self.indices.push(wire.index);
        Ok(())
    }
}

impl<'table, 'sy, F: Field, R: Rank> Evaluator<'table, 'sy, '_, F, R> {
    /// Fingerprint recorded for the routine segment at `index`.
    fn fingerprint_at(&self, index: usize) -> DeepFingerprint {
        match self.segment_records[index].identity() {
            RoutineIdentity::Routine(fp) => *fp,
            RoutineIdentity::Root => unreachable!("routine segments are never Root"),
        }
    }

    /// Evaluation-point data shared with the routine recorder. `s(X, y)`
    /// has no fixed `x`; the recorder's `x`-dependent views are unused here.
    fn record_params(&self) -> record::Params<F> {
        record::Params {
            x: F::ZERO,
            x_inv: F::ZERO,
            y: self.y,
            y_inv: self.y_inv,
            base_a_x: F::ZERO,
            base_b_x: F::ZERO,
            base_c_x: F::ZERO,
            a_to_d: F::ZERO,
        }
    }

    /// Builds the wire handle a replayed output form denotes at gate offset
    /// `m`, given the caller's input wire indices: a plain handle for a
    /// single wire, otherwise a virtual wire over the form's terms.
    fn materialize(
        &self,
        form: &record::Form<F>,
        m: usize,
        inputs: &[WireIndex],
    ) -> Wire<'table, 'sy, F, R> {
        let terms: Vec<(WireIndex, Coeff<F>)> = form
            .terms()
            .map(|(term, v)| {
                let index = match term {
                    Term::Wire(WireRef::A(i)) => WireIndex::A(m + i),
                    Term::Wire(WireRef::B(i)) => WireIndex::B(m + i),
                    Term::Wire(WireRef::C(i)) => WireIndex::C(m + i),
                    Term::Wire(WireRef::D(i)) => WireIndex::D(m + i),
                    Term::One => WireIndex::D(0),
                    Term::Input(j) => inputs[j],
                };
                (index, Coeff::Arbitrary(v))
            })
            .collect();

        if let [(index, Coeff::Arbitrary(v))] = terms.as_slice()
            && *v == F::ONE
        {
            let wire = Wire::new(*index, self.virtual_table);
            wire.increment_refcount();
            return wire;
        }

        let mut table = self.virtual_table.borrow_mut();
        let wire = table.alloc();
        for (index, _) in &terms {
            if let WireIndex::Virtual(i) = index {
                table.wires[*i].refcount += 1;
            }
        }
        table.update(wire, terms);
        drop(table);
        Wire {
            index: wire,
            table: Some(self.virtual_table),
        }
    }
}

impl<'table, 'sy, F: Field, R: Rank> DriverScope<SyScope<F>> for Evaluator<'table, 'sy, '_, F, R> {
    fn scope(&mut self) -> &mut SyScope<F> {
        &mut self.scope
    }
}

/// Configures associated types for the [`Evaluator`] driver.
///
/// - `MaybeKind = Empty`: No witness input is needed; we only compute
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
    type Extra = usize;

    /// Consumes a gate, returning wire handles for $(a, b, c)$ and the gate
    /// index as [`Extra`](DriverTypes::Extra).
    ///
    /// The gate index comes from the absolute floor-plan position tracked in
    /// `scope.gates`. Wiring view slots are
    /// pre-allocated, so no push is needed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::GateBoundExceeded`] if the gate count reaches
    /// [`Rank::n()`].
    fn gate(
        &mut self,
        _: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(
        Wire<'table, 'sy, F, R>,
        Wire<'table, 'sy, F, R>,
        Wire<'table, 'sy, F, R>,
        usize,
    )> {
        let index = self.scope.gates;
        if index == R::n() {
            return Err(Error::GateBoundExceeded { limit: R::n() });
        }
        self.scope.gates += 1;

        let a = Wire::new(WireIndex::A(index), self.virtual_table);
        let b = Wire::new(WireIndex::B(index), self.virtual_table);
        let c = Wire::new(WireIndex::C(index), self.virtual_table);

        Ok((a, b, c, index))
    }

    /// Constructs the $d$-wire handle for the gate at the given index.
    fn assign_extra(
        &mut self,
        index: Self::Extra,
        _: impl Fn() -> Result<Coeff<F>>,
    ) -> Result<Wire<'table, 'sy, F, R>> {
        Ok(Wire::new(WireIndex::D(index), self.virtual_table))
    }
}

impl<'table, 'sy, F: Field, R: Rank> Driver<'table> for Evaluator<'table, 'sy, '_, F, R> {
    type F = F;
    type Wire = Wire<'table, 'sy, F, R>;

    const ONE: Self::Wire = Wire {
        index: WireIndex::D(0),
        table: None,
    };

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

    /// Applies a constraint weighted by the current $y$ power.
    ///
    /// Distributes `current_y * coeff` to each wire in the linear combination
    /// via [`TermEnforcer`], then advances `current_y` by multiplying with
    /// `y_inv` (implementing reverse Horner iteration).
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConstraintBoundExceeded`] if the constraint count reaches
    /// `Rank::num_coeffs() - 1` (the last slot is reserved for the registry
    /// tag constraint).
    fn enforce_zero(&mut self, lc: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        let q = self.scope.constraints;
        if q >= R::num_coeffs() - 1 {
            return Err(Error::ConstraintBoundExceeded {
                limit: R::num_coeffs() - 1,
            });
        }
        self.scope.constraints += 1;

        lc(TermEnforcer(
            self.virtual_table.borrow_mut(),
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
        let index = self.current_routine;
        let seg = &self.floor_plan[index];

        // Only top-level routines are memoized; a recording covers the whole
        // subtree. On a miss the routine is recorded in a position-free frame
        // (see the `record` module); either way its per-wire coefficients and
        // output wires are replayed at this placement.
        let memo = (self.routine_depth == 0 && self.memo_cache.is_some())
            .then(|| self.fingerprint_at(index));

        if let Some(fingerprint) = memo {
            let cache = self.memo_cache.as_mut().expect("memo implies a cache");
            let inputs: Vec<WireIndex> = match cache.lookup(&fingerprint) {
                Some(_) => {
                    let mut extractor = IndexExtractor::<Self> {
                        indices: Vec::new(),
                        _marker: core::marker::PhantomData,
                    };
                    Ro::Input::map_gadget(&input, &mut extractor)?;
                    extractor.indices
                }
                None => {
                    let (recorded, inputs) = record::record(
                        &routine,
                        &input,
                        self.record_params(),
                        self.floor_plan,
                        index,
                        |w: &Wire<'table, 'sy, F, R>| w.index,
                    )?;
                    self.memo_cache
                        .as_mut()
                        .expect("memo implies a cache")
                        .insert(fingerprint, recorded);
                    inputs
                }
            };

            // Replay: every wire's coefficient, scaled to this block's
            // constraint offset, lands on the wire's absolute index.
            let m = seg.gate_start;
            let y_pow = self.y.pow_u64(seg.constraint_start as u64);
            let sharing = self
                .memo_cache
                .as_ref()
                .is_some_and(|cache| cache.is_sharing());
            let recorded = self
                .memo_cache
                .as_ref()
                .and_then(|cache| cache.get(&fingerprint))
                .expect("recording was just looked up or inserted");
            {
                let mut table = self.virtual_table.borrow_mut();
                // In sharing mode the registry adds the block's own wires and
                // `ONE` once for every circuit with this block here.
                if !sharing {
                    for &(wire, h) in &recorded.wires.own {
                        let index = match wire {
                            WireRef::A(i) => WireIndex::A(m + i),
                            WireRef::B(i) => WireIndex::B(m + i),
                            WireRef::C(i) => WireIndex::C(m + i),
                            WireRef::D(i) => WireIndex::D(m + i),
                        };
                        table.add(index, Coeff::Arbitrary(y_pow * h));
                    }
                    if recorded.wires.one != F::ZERO {
                        table.add(
                            WireIndex::D(0),
                            Coeff::Arbitrary(y_pow * recorded.wires.one),
                        );
                    }
                }
                for (j, h) in recorded.wires.inputs.iter().enumerate() {
                    if *h != F::ZERO {
                        table.add(inputs[j], Coeff::Arbitrary(y_pow * *h));
                    }
                }
            }
            let output_wires: Vec<Wire<'table, 'sy, F, R>> = recorded
                .outputs
                .iter()
                .map(|form| self.materialize(form, m, &inputs))
                .collect();
            let num_segments = recorded.num_segments;
            if sharing {
                let placement = Placement {
                    gate_start: seg.gate_start,
                    constraint_start: seg.constraint_start,
                };
                self.memo_cache
                    .as_mut()
                    .expect("memo implies a cache")
                    .note_shared(fingerprint, placement);
            }

            // Reconstruct the output gadget from the replayed wires:
            // 1. Execute on a wireless emulator to get a template with unit wires.
            // 2. Use WireInjector to replace the unit wires with the handles.
            type W<F> = Emulator<Wireless<Empty, F>>;

            let aux = Emulator::predict(&routine, &input)?.into_aux();
            let wireless_input = StripWires::<Self>::remap(&input)?;
            let template = routine.execute(&mut W::<F>::wireless(), wireless_input, aux)?;

            let mut injector = WireInjector::<_, W<F>, Self>::new(&output_wires);
            let output = Ro::Output::map_gadget(&template, &mut injector)?;
            debug_assert!(
                injector.is_exhausted(),
                "replayed wires should be fully consumed"
            );

            // The recording already includes the nested sub-routines, so
            // skip their segments.
            self.current_routine += num_segments - 1;

            return Ok(output);
        }

        // Jump to this routine's absolute position in the polynomial;
        // see "Polynomial Encoding and Scope Jumps" in the `s` module doc.
        let init_scope = SyScope {
            // When num_constraints == 0 the routine emits no
            // enforce_zero calls, so current_y is never read; use
            // F::ZERO as an inert sentinel.
            current_y: if seg.num_constraints == 0 {
                F::ZERO
            } else {
                self.y
                    .pow_u64((seg.constraint_start + seg.num_constraints - 1) as u64)
            },
            gates: seg.gate_start,
            constraints: seg.constraint_start,
        };

        self.routine_depth += 1;
        let result = self.with_scope(init_scope, |this| {
            let aux = Emulator::predict(&routine, &input)?.into_aux();
            let result = routine.execute(this, input, aux)?;

            // Verify this routine consumed exactly the expected constraints.
            assert_eq!(
                this.scope.gates,
                seg.gate_start + seg.num_gates,
                "routine gate count must match floor plan"
            );
            assert_eq!(
                this.scope.constraints,
                seg.constraint_start + seg.num_constraints,
                "routine constraint count must match floor plan"
            );

            Ok(result)
        });
        self.routine_depth -= 1;
        result
    }
}

/// Evaluates the wiring polynomial $s(X, y)$ at a fixed $y$.
///
/// Returns a sparse polynomial in $X$ with coefficients computed via
/// deferred evaluation through virtual wires. See the [module
/// documentation](self) for the algorithm overview.
///
/// # Arguments
///
/// - `circuit`: The circuit whose wiring polynomial to evaluate.
/// - `y`: The evaluation point for the $Y$ variable.
/// - `floor_plan`: Per-segment absolute offsets, computed by
///   [`floor_plan()`](crate::floor_planner::floor_plan). The root segment's
///   `num_constraints` determines the initial `current_y = y^{q-1}`
///   for reverse Horner iteration.
#[cfg_attr(not(test), allow(dead_code))]
pub fn eval<F: Field, RC: RawCircuit<F>, R: Rank>(
    circuit: &RC,
    y: F,
    floor_plan: &[ConstraintSegment],
    segment_records: &[SegmentRecord],
) -> Result<sparse::Polynomial<F, R>> {
    eval_inner::<F, RC, R>(circuit, y, floor_plan, segment_records, None)
}

/// Evaluates $s(X, y)$ with routine memoization.
///
/// Like [`eval`], but records each top-level routine's per-wire coefficients
/// in a position-free form and replays them for every later invocation with
/// the same fingerprint, within this circuit and across circuits that share
/// `cache`; see the [`memo`](super::memo) and [`record`] modules.
pub(crate) fn eval_with_cache<F: Field, RC: RawCircuit<F>, R: Rank>(
    circuit: &RC,
    y: F,
    floor_plan: &[ConstraintSegment],
    segment_records: &[SegmentRecord],
    cache: &mut MemoCache<F>,
) -> Result<sparse::Polynomial<F, R>> {
    eval_inner::<F, RC, R>(circuit, y, floor_plan, segment_records, Some(cache))
}

/// The position-independent part of a recorded block placed at `placement`,
/// as a polynomial in $X$ at this $y$, scaled by `scale`. This is what the
/// evaluators leave out in sharing mode; see [`MemoCache`].
pub(crate) fn shared_block<F: Field, R: Rank>(
    recorded: &Recorded<F>,
    placement: Placement,
    y: F,
    scale: F,
) -> sparse::Polynomial<F, R> {
    let m = placement.gate_start;
    let y_pow = y.pow_u64(placement.constraint_start as u64) * scale;

    let extent = recorded
        .wires
        .own
        .iter()
        .map(|(wire, _)| match wire {
            WireRef::A(i) | WireRef::B(i) | WireRef::C(i) | WireRef::D(i) => m + i + 1,
        })
        .max()
        .unwrap_or(0)
        .max(1);
    let mut view = sparse::View::<_, R, _>::wiring();
    view.a.resize(extent, F::ZERO);
    view.b.resize(extent, F::ZERO);
    view.c.resize(extent, F::ZERO);
    view.d.resize(extent, F::ZERO);
    for &(wire, h) in &recorded.wires.own {
        match wire {
            WireRef::A(i) => view.a[m + i] += y_pow * h,
            WireRef::B(i) => view.b[m + i] += y_pow * h,
            WireRef::C(i) => view.c[m + i] += y_pow * h,
            WireRef::D(i) => view.d[m + i] += y_pow * h,
        }
    }
    view.d[0] += y_pow * recorded.wires.one;
    view.build()
}

fn eval_inner<F: Field, RC: RawCircuit<F>, R: Rank>(
    circuit: &RC,
    y: F,
    floor_plan: &[ConstraintSegment],
    segment_records: &[SegmentRecord],
    memo_cache: Option<&mut MemoCache<F>>,
) -> Result<sparse::Polynomial<F, R>> {
    let mut view = sparse::View::wiring();

    if y == F::ZERO {
        // If y is zero, all terms y^j for j > 0 vanish, leaving only the ONE
        // wire coefficient (d[0] at monomial x^0).
        view.d.push(F::ONE);
        return Ok(view.build());
    }

    // Segments may be placed with gaps between them, so the view spans the
    // furthest gate any segment reaches.
    let total_gates: usize = floor_plan
        .iter()
        .map(|s| s.gate_start + s.num_gates)
        .max()
        .unwrap_or(0);

    // Circuit-scope segment's constraint count (for initial current_y).
    // This segment always has at least the ONE constraint.
    let root_constraints = floor_plan[0].num_constraints;
    assert!(
        root_constraints > 0,
        "root segment must have at least one constraint"
    );

    {
        let virtual_table = RefCell::new(VirtualTable::<F, R> {
            wires: vec![],
            free: vec![],
            a: &mut view.a,
            b: &mut view.b,
            c: &mut view.c,
            d: &mut view.d,
            _marker: core::marker::PhantomData,
        });

        // Pre-allocate wiring view slots for all gates.
        {
            let mut table = virtual_table.borrow_mut();
            table.a.resize(total_gates, F::ZERO);
            table.b.resize(total_gates, F::ZERO);
            table.c.resize(total_gates, F::ZERO);
            table.d.resize(total_gates, F::ZERO);
        }

        {
            let mut evaluator = Evaluator::<'_, '_, '_, F, R> {
                scope: SyScope {
                    // Assertion above prevents this from underflowing.
                    current_y: y.pow_u64((root_constraints - 1) as u64),
                    gates: 0,
                    constraints: 0,
                },
                y,
                y_inv: y.invert().expect("y is not zero"),
                virtual_table: &virtual_table,
                floor_plan,
                current_routine: 0,
                segment_records,
                memo_cache,
                routine_depth: 0,
                _marker: core::marker::PhantomData,
            };

            crate::raw::orchestrate(&mut evaluator, circuit, Empty)?;

            // Verify all floor plan segments were consumed and counts match.
            assert_eq!(
                evaluator.current_routine + 1,
                evaluator.floor_plan.len(),
                "floor plan routine count must match constraint emission"
            );
            assert_eq!(
                evaluator.scope.gates, evaluator.floor_plan[0].num_gates,
                "root gate count must match floor plan"
            );
            assert_eq!(
                evaluator.scope.constraints, evaluator.floor_plan[0].num_constraints,
                "root constraint count must match floor plan"
            );
        }

        // Invariant: all virtual wires must have been freed during constraint
        // emission, indicating proper reference counting and no leaked wires.
        let virtual_table = virtual_table.into_inner();
        assert_eq!(virtual_table.free.len(), virtual_table.wires.len());
    }

    Ok(view.build())
}

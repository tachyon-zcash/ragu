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

use arithmetic::Coeff;
use ff::Field;
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverTypes, LinearExpression, emulator::Emulator},
    gadgets::GadgetKind,
    maybe::Empty,
    routines::{Prediction, Routine},
};
use ragu_primitives::GadgetExt;

use alloc::{vec, vec::Vec};
use core::cell::RefCell;

use crate::{
    Circuit,
    polynomials::{Rank, structured},
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
struct Evaluator<'table, 'sy, F: Field, R: Rank> {
    /// Number of multiplication gates consumed so far.
    ///
    /// Incremented by [`mul()`](Driver::mul). Must not exceed [`Rank::n()`].
    multiplication_constraints: usize,

    /// Number of linear constraints processed so far.
    ///
    /// Incremented by [`enforce_zero`](Driver::enforce_zero). Must not exceed
    /// [`Rank::num_coeffs()`].
    linear_constraints: usize,

    /// Cached inverse $y^{-1}$, used to step through decreasing powers of $y$.
    ///
    /// Each [`enforce_zero`](Driver::enforce_zero) call multiplies `current_y`
    /// by this value to step through $y^{q-1}, y^{q-2}, \ldots, y^0$.
    y_inv: F,

    /// Current $y$ power being applied to constraints.
    ///
    /// Initialized to $y^{q-1}$ (where $q$ is the total linear constraint count)
    /// and multiplied by `y_inv` after each constraint, so that constraints are
    /// weighted by $y^{q-1}, y^{q-2}, \ldots, y^0$ in synthesis order.
    current_y: F,

    /// Reference to the virtual table for wire management.
    ///
    /// Shared via [`RefCell`] to allow mutable access during synthesis while
    /// maintaining multiple [`Wire`] handles.
    virtual_table: &'table RefCell<VirtualTable<'sy, F, R>>,

    /// Stashed $b$ wire from paired allocation (see [`Driver::alloc`]).
    ///
    /// [`Driver::alloc`]: ragu_core::drivers::Driver::alloc
    available_b: Option<Wire<'table, 'sy, F, R>>,

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

/// Configures associated types for the [`Evaluator`] driver.
///
/// - `MaybeKind = Empty`: No witness values are needed; we only compute
///   polynomial structure.
/// - `LCadd`: Uses [`TermCollector`] to build deferred term lists for virtual
///   wires.
/// - `LCenforce`: Uses [`TermEnforcer`] to immediately distribute $y^j$
///   contributions.
/// - `ImplWire`: [`Wire`] handles with reference counting for virtual wires.
impl<'table, 'sy, F: Field, R: Rank> DriverTypes for Evaluator<'table, 'sy, F, R> {
    type MaybeKind = Empty;
    type LCadd = TermCollector<F>;
    type LCenforce = TermEnforcer<'table, 'sy, F, R>;
    type ImplField = F;
    type ImplWire = Wire<'table, 'sy, F, R>;
}

impl<'table, 'sy, F: Field, R: Rank> Driver<'table> for Evaluator<'table, 'sy, F, R> {
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
        if let Some(wire) = self.available_b.take() {
            Ok(wire)
        } else {
            let (a, b, _) = self.mul(|| unreachable!())?;
            self.available_b = Some(b);

            Ok(a)
        }
    }

    /// Consumes a multiplication gate, returning wire handles for $(a, b, c)$.
    ///
    /// Pushes zero-initialized coefficient slots to the backward view for each
    /// wire type, then returns [`Wire`] handles pointing to the new slots.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MultiplicationBoundExceeded`] if the gate count reaches
    /// [`Rank::n()`].
    fn mul(
        &mut self,
        _: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(Self::Wire, Self::Wire, Self::Wire)> {
        let index = self.multiplication_constraints;
        if index == R::n() {
            return Err(Error::MultiplicationBoundExceeded(R::n()));
        }
        self.multiplication_constraints += 1;

        {
            let mut table = self.virtual_table.borrow_mut();
            table.sy.a.push(F::ZERO);
            table.sy.b.push(F::ZERO);
            table.sy.c.push(F::ZERO);
        }

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
        let q = self.linear_constraints;
        if q == R::num_coeffs() {
            return Err(Error::LinearBoundExceeded(R::num_coeffs()));
        }
        self.linear_constraints += 1;

        lc(TermEnforcer(
            self.virtual_table,
            Coeff::Arbitrary(self.current_y),
        ));

        self.current_y *= self.y_inv;

        Ok(())
    }

    /// Executes a routine with isolated allocation state.
    fn routine<Ro: Routine<Self::F> + 'table>(
        &mut self,
        routine: Ro,
        input: <Ro::Input as GadgetKind<Self::F>>::Rebind<'table, Self>,
    ) -> Result<<Ro::Output as GadgetKind<Self::F>>::Rebind<'table, Self>> {
        // Temporarily store currently `available_b` to reset the allocation
        // logic within the routine.
        let tmp = self.available_b.take();
        let mut dummy = Emulator::wireless();
        let dummy_input = Ro::Input::map_gadget(&input, &mut dummy)?;
        let result = match routine.predict(&mut dummy, &dummy_input)? {
            Prediction::Known(_, aux) | Prediction::Unknown(aux) => {
                routine.execute(self, input, aux)?
            }
        };

        // Restore the allocation logic state, discarding the state from within
        // the routine.
        self.available_b = tmp;
        Ok(result)
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
/// - `key`: The mesh key that binds this evaluation to a [`Mesh`] context by
///   enforcing `key_wire - key = 0` as a constraint. This randomizes
///   evaluations of $s(X, y)$, preventing trivial forgeries across mesh
///   contexts.
/// - `num_linear_constraints`: The total number of linear constraints expected
///   from synthesis. Used to initialize `current_y = y^{q-1}` for reverse
///   Horner iteration.
///
/// [`Mesh`]: crate::mesh::Mesh
pub fn eval<F: Field, C: Circuit<F>, R: Rank>(
    circuit: &C,
    y: F,
    key: F,
    num_linear_constraints: usize,
) -> Result<structured::Polynomial<F, R>> {
    let mut sy = structured::Polynomial::<F, R>::new();

    if y == F::ZERO {
        // If y is zero, all terms y^j for j > 0 vanish, leaving only the ONE
        // wire coefficient.
        sy.backward().c.push(F::ONE);
        return Ok(sy);
    }

    {
        let virtual_table = RefCell::new(VirtualTable::<F, R> {
            wires: vec![],
            free: vec![],
            sy: sy.backward(),
        });
        {
            let mut evaluator = Evaluator::<'_, '_, F, R> {
                multiplication_constraints: 0,
                linear_constraints: 0,
                y_inv: y.invert().expect("y is not zero"),
                current_y: y.pow_vartime([(num_linear_constraints - 1) as u64]),
                virtual_table: &virtual_table,
                available_b: None,
                _marker: core::marker::PhantomData,
            };

            let (key_wire, _, one) = evaluator.mul(|| unreachable!())?;

            // Enforce linear constraint key_wire = key to randomize non-trivial
            // evaluations of this wiring polynomial.
            evaluator.enforce_zero(|lc| {
                lc.add(&key_wire)
                    .add_term(&one, Coeff::NegativeArbitrary(key))
            })?;

            let mut outputs = vec![];
            let (io, _) = circuit.witness(&mut evaluator, Empty)?;
            io.write(&mut evaluator, &mut outputs)?;

            for output in outputs {
                evaluator.enforce_zero(|lc| lc.add(output.wire()))?;
            }
            evaluator.enforce_zero(|lc| lc.add(&one))?;

            // Invariant: synthesis must produce exactly the expected number of
            // linear constraints.
            assert_eq!(evaluator.linear_constraints, num_linear_constraints);
        }

        // Invariant: all virtual wires must have been freed during synthesis,
        // indicating proper reference counting and no leaked wires.
        let virtual_table = virtual_table.into_inner();
        assert_eq!(virtual_table.free.len(), virtual_table.wires.len());
    }

    Ok(sy)
}

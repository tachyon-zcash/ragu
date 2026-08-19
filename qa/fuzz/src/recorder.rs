//! The patcher engine: a recording driver plus a constraint-graph repair
//! solver (issues #728, #793, #796).
//!
//! [`Recorder`] is a [`Driver`] that captures the constraint graph ragu
//! actually emits during synthesis — every multiplication gate `a·b = c`,
//! every assigned auxiliary wire's `c·d = 0`, every linear-combination
//! wire, every `enforce_zero` — together with the honest wire values, as a
//! flat list of [`Event`]s over `usize` wires.
//!
//! [`repair`] then plays the malicious prover: given a witness whose free
//! advice wires have been mutated, it solves the captured constraints for
//! the remaining wires, propagating the cheat as far as the constraints
//! force it to go — and *no further*. A wire no constraint pins keeps its
//! honest value, and [`constraints_hold`] reports whether the result
//! satisfies every captured constraint. Comparing that verdict against an
//! independent native oracle is the patcher differential: ragu accepting a
//! witness the oracle rejects is an under-constrained-advice signal.
//!
//! The engine lives here rather than in the fuzz target so it is unit
//! tested ([`selftest`] runs in CI as a plain test) and reusable against
//! real circuits (issue #793).

use ff::{Field, PrimeField};
use ragu_arithmetic::Coeff;
use ragu_core::{
    Result,
    drivers::{Driver, DriverTypes, LinearExpression},
    maybe::Always,
};
use ragu_primitives::allocator::{Allocator, Standard};

/// A captured constraint / wire definition, in emission order.
#[derive(Clone, Debug)]
pub enum Event<F> {
    /// `out` is a virtual wire equal to `Σ coeff · wire` over `terms`.
    Lin {
        /// The virtual output wire.
        out: usize,
        /// The `(wire, coefficient)` terms of the combination.
        terms: Vec<(usize, F)>,
    },
    /// A multiplication gate: `values[a] · values[b] == values[c]`.
    Gate {
        /// The left input wire.
        a: usize,
        /// The right input wire.
        b: usize,
        /// The output wire.
        c: usize,
    },
    /// A constraint `Σ coeff · wire == 0` over `terms`.
    Enforce {
        /// The `(wire, coefficient)` terms of the constraint.
        terms: Vec<(usize, F)>,
    },
    /// A gate's auxiliary-wire constraint: `values[c] · values[d] == 0`,
    /// where `c` is the output wire of a gate and `d` the $D$ wire a
    /// pooling allocator assigned to it through
    /// [`DriverTypes::assign_extra`]. A gate whose $D$ wire is never
    /// assigned keeps the driver's default `D = 0`, has no `d` wire in the
    /// recorder, and emits no `Extra` event.
    Extra {
        /// The gate's output wire.
        c: usize,
        /// The gate's assigned $D$ wire.
        d: usize,
    },
}

/// The recording driver. `Wire = usize`, an index into [`Recorder::values`].
pub struct Recorder<F> {
    /// The honest value of each wire, indexed by wire id.
    pub values: Vec<F>,
    /// The captured constraint graph, in emission order.
    pub events: Vec<Event<F>>,
    /// Wires created through [`DriverTypes::assign_extra`] — gate $D$ wires
    /// handed out by a pooling allocator (`Standard`), each pinned by its
    /// [`Event::Extra`] to be zero whenever its gate's `C` is nonzero and
    /// free otherwise. Like an allocation gate's `a` wire they hold
    /// prover-chosen advice, so callers that know every `alloc` result is
    /// advice (the substrate) list them among the free wires for
    /// [`underconstrained_derived`].
    pub extras: Vec<usize>,
}

impl<F: Field> Recorder<F> {
    /// The fixed wire holding the constant `1`.
    pub const ONE: usize = 0;

    /// An empty recorder whose only wire is the fixed ONE wire.
    pub fn new() -> Self {
        Recorder {
            values: vec![F::ONE],
            events: Vec::new(),
            extras: Vec::new(),
        }
    }

    /// Appends a raw wire with the given value and no defining constraint —
    /// free advice from the engine's perspective.
    pub fn push_wire(&mut self, value: F) -> usize {
        let id = self.values.len();
        self.values.push(value);
        id
    }
}

impl<F: Field> Default for Recorder<F> {
    fn default() -> Self {
        Self::new()
    }
}

/// Recording linear expression: accumulates `(wire, resolved_coeff)` terms,
/// folding the running gain into each coefficient as it is added. It records
/// only structure; the driver computes the resulting value from its own
/// wire table afterwards.
pub struct RecLc<F> {
    terms: Vec<(usize, F)>,
    gain: F,
}

impl<F: Field> Default for RecLc<F> {
    fn default() -> Self {
        RecLc {
            terms: Vec::new(),
            gain: F::ONE,
        }
    }
}

impl<F: Field> LinearExpression<usize, F> for RecLc<F> {
    fn add_term(mut self, wire: &usize, coeff: Coeff<F>) -> Self {
        let resolved = coeff.value() * self.gain;
        if resolved != F::ZERO {
            self.terms.push((*wire, resolved));
        }
        self
    }

    fn gain(mut self, coeff: Coeff<F>) -> Self {
        self.gain *= coeff.value();
        self
    }
}

impl<F: Field> DriverTypes for Recorder<F> {
    type ImplField = F;
    type ImplWire = usize;
    type MaybeKind = Always<()>;
    type LCadd = RecLc<F>;
    type LCenforce = RecLc<F>;
    /// The gate's output wire `c`, so that [`assign_extra`](Self::assign_extra)
    /// can record the `c·d = 0` constraint the $D$ wire is subject to.
    type Extra = usize;

    fn gate(
        &mut self,
        values: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(usize, usize, usize, usize)> {
        let (a, b, c) = values()?;
        let (a, b, c) = (a.value(), b.value(), c.value());
        let ia = self.push_wire(a);
        let ib = self.push_wire(b);
        let ic = self.push_wire(c);
        self.events.push(Event::Gate {
            a: ia,
            b: ib,
            c: ic,
        });
        Ok((ia, ib, ic, ic))
    }

    fn assign_extra(&mut self, c: usize, value: impl Fn() -> Result<Coeff<F>>) -> Result<usize> {
        let v = value()?.value();
        let d = self.push_wire(v);
        self.events.push(Event::Extra { c, d });
        self.extras.push(d);
        Ok(d)
    }
}

impl<'dr, F: Field> Driver<'dr> for Recorder<F> {
    type F = F;
    type Wire = usize;
    const ONE: usize = 0;

    fn add(&mut self, lc: impl Fn(RecLc<F>) -> RecLc<F>) -> usize {
        let built = lc(RecLc::default());
        let value = built.terms.iter().map(|(w, c)| self.values[*w] * c).sum();
        let out = self.push_wire(value);
        self.events.push(Event::Lin {
            out,
            terms: built.terms,
        });
        out
    }

    fn enforce_zero(&mut self, lc: impl Fn(RecLc<F>) -> RecLc<F>) -> Result<()> {
        let built = lc(RecLc::default());
        self.events.push(Event::Enforce { terms: built.terms });
        Ok(())
    }
}

/// The [`Standard`] pooling allocator with bookkeeping: it delegates every
/// `alloc` and `donate` to a real `Standard<usize>` — so the recorder sees
/// exactly the gate / [`assign_extra`](DriverTypes::assign_extra) sequence
/// production circuits produce, including $D$ wires redeemed from gadgets
/// like `Boolean::alloc` and `is_zero` that donate their spare token — and
/// records the `b` and `c` wires of each fresh allocation gate `a · 0 = 0`.
///
/// Those wires are real, prover-controlled degrees of freedom — `b` is
/// unconstrained and `c = a·b` follows it — that ragu wastes *by design*,
/// so a whole-graph analysis like [`underconstrained_derived`] must exempt
/// them or it would flag every allocation. (The $D$ wire of such a gate is
/// *not* waste: the allocator hands it out as the next allocation, and the
/// recorder lists it in [`Recorder::extras`].)
///
/// Wrapping `Standard` rather than reimplementing its pooling policy is what
/// lets [`Playback`] replay the same synthesis with a plain `Standard` and
/// land on identical wire ids.
#[derive(Default)]
pub struct TrackingAllocator {
    inner: Standard<usize>,
    /// The `b` and `c` wires of every allocation gate, in creation order.
    pub wasted: Vec<usize>,
}

impl<'dr, F: Field> Allocator<'dr, Recorder<F>> for TrackingAllocator {
    fn alloc(
        &mut self,
        dr: &mut Recorder<F>,
        value: impl Fn() -> Result<Coeff<F>>,
    ) -> Result<usize> {
        // `Standard` either redeems a pooled token (`assign_extra`: one new
        // wire, the `d`) or opens a fresh gate (three new wires `a, b, c`,
        // returning `a`). The recorder allocates ids sequentially, so the
        // wire-count delta tells the two apart and locates `b` and `c`.
        let before = dr.values.len();
        let wire = self.inner.alloc(dr, value)?;
        if dr.values.len() == before + 3 {
            debug_assert_eq!(wire, before, "fresh allocation gate returns its `a` wire");
            self.wasted.push(before + 1);
            self.wasted.push(before + 2);
        }
        Ok(wire)
    }

    fn donate(&mut self, extra: usize) {
        <Standard<usize> as Allocator<'dr, Recorder<F>>>::donate(&mut self.inner, extra);
    }
}

/// A constraint *checker* that re-runs the real gadget synthesis with an
/// injected witness, verifying each gate, each assigned $D$ wire's
/// `c·d = 0`, and each `enforce_zero` against the supplied values rather
/// than the gadget's own closures.
///
/// `Playback` is the independent cross-check for [`Recorder`]/[`repair`]
/// (issue #793, the "remove trust in the recorder" item). The recorder
/// captures the constraint graph *once* and the differential then reasons
/// entirely over that stored snapshot ([`Event`]s, [`constraints_hold`]); a
/// capture bug — a mis-folded `Coeff` gain, a dropped term, a swapped wire —
/// would corrupt every later verdict invisibly. `Playback` re-derives the
/// verdict from scratch: same `synthesize`, same gadget calls, but its own
/// linear-combination evaluator reading the injected `values` directly. If
/// the recorder's stored answer and this live re-execution ever disagree,
/// the recorder mis-captured the circuit.
///
/// `Wire = usize` and allocation is sequential from the fixed ONE wire, so
/// running the *same* `synthesize` (with a plain [`Standard`] allocator,
/// whose gate / `assign_extra` call sequence is exactly what
/// [`TrackingAllocator`] delegates to) assigns wire `i` exactly the
/// recorder's wire `i` — so `values` is the recorder's value vector, honest
/// or repaired, used verbatim.
pub struct Playback<F> {
    values: Vec<F>,
    next: usize,
    /// Set false by the first failed gate, `c·d = 0` check, `add`
    /// definition, or enforce.
    ok: bool,
}

impl<F: Field> Playback<F> {
    /// A checker over the given injected witness (indexed by recorder wire).
    pub fn new(values: Vec<F>) -> Self {
        Playback {
            values,
            next: 1, // wire 0 is the fixed ONE wire
            ok: true,
        }
    }

    fn alloc_wire(&mut self) -> usize {
        let id = self.next;
        self.next += 1;
        id
    }
}

/// Playback's linear-combination evaluator. Like [`RecLc`] it records only
/// structure — `(wire, resolved_coeff)` terms with the running gain folded
/// in — and the driver evaluates `Σ coeff · values[wire]` afterwards from
/// its own table. An implementation independent of [`RecLc`], so a bug in
/// one does not hide a bug in the other.
#[derive(Default)]
pub struct PlayLc<F> {
    terms: Vec<(usize, F)>,
    gain: F,
}

impl<F: Field> LinearExpression<usize, F> for PlayLc<F> {
    fn add_term(mut self, wire: &usize, coeff: Coeff<F>) -> Self {
        self.terms.push((*wire, coeff.value() * self.gain));
        self
    }

    fn gain(mut self, coeff: Coeff<F>) -> Self {
        self.gain *= coeff.value();
        self
    }
}

impl<F: Field> Playback<F> {
    fn eval(&self, built: &PlayLc<F>) -> F {
        built.terms.iter().map(|(w, c)| *c * self.values[*w]).sum()
    }

    fn fresh_lc() -> PlayLc<F> {
        PlayLc {
            terms: Vec::new(),
            gain: F::ONE,
        }
    }
}

impl<F: Field> DriverTypes for Playback<F> {
    type ImplField = F;
    type ImplWire = usize;
    type MaybeKind = Always<()>;
    type LCadd = PlayLc<F>;
    type LCenforce = PlayLc<F>;
    /// The gate's output wire `c`, as in [`Recorder`].
    type Extra = usize;

    fn gate(
        &mut self,
        _values: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(usize, usize, usize, usize)> {
        let (ia, ib, ic) = (self.alloc_wire(), self.alloc_wire(), self.alloc_wire());
        if self.values[ia] * self.values[ib] != self.values[ic] {
            self.ok = false;
        }
        Ok((ia, ib, ic, ic))
    }

    fn assign_extra(&mut self, c: usize, _value: impl Fn() -> Result<Coeff<F>>) -> Result<usize> {
        let d = self.alloc_wire();
        // The gate's `C · D = 0`: an assigned $D$ wire may be nonzero only
        // while the gate's output is zero.
        if self.values[c] * self.values[d] != F::ZERO {
            self.ok = false;
        }
        Ok(d)
    }
}

impl<'dr, F: Field> Driver<'dr> for Playback<F> {
    type F = F;
    type Wire = usize;
    const ONE: usize = 0;

    fn add(&mut self, lc: impl Fn(PlayLc<F>) -> PlayLc<F>) -> usize {
        let built = lc(Self::fresh_lc());
        let value = self.eval(&built);
        let out = self.alloc_wire();
        // A virtual `add` wire is *defined* as the linear combination, so the
        // injected value must already equal it.
        if self.values[out] != value {
            self.ok = false;
        }
        out
    }

    fn enforce_zero(&mut self, lc: impl Fn(PlayLc<F>) -> PlayLc<F>) -> Result<()> {
        let built = lc(Self::fresh_lc());
        if self.eval(&built) != F::ZERO {
            self.ok = false;
        }
        Ok(())
    }
}

impl<F: Field> Playback<F> {
    /// Whether every gate, `add` definition, and `enforce_zero` held, and
    /// every wire of the injected witness was consumed (a length mismatch
    /// means the playback diverged from the recorder's allocation order).
    pub fn accepts(&self) -> bool {
        self.ok && self.next == self.values.len()
    }
}

/// The rank/nullity oracle: derived wires a malicious prover can move, to
/// first order, while every free wire is held fixed.
///
/// Builds the Jacobian of the captured constraints at the (satisfying)
/// witness `values` — `Lin` and `Enforce` are their own (linear) rows, a
/// gate `a·b = c` linearizes to `b̄·da + ā·db − dc = 0`, and an assigned
/// $D$ wire's `c·d = 0` to `d̄·dc + c̄·dd = 0` — restricted to the columns
/// *not* in `free` (advice directions are pinned: `da = 0`).
/// A derived wire is **movable** when some null-space vector of that
/// restricted system is nonzero at its column, computed by Gaussian
/// elimination to reduced row echelon form: non-pivot columns are free
/// parameters, and a pivot column moves exactly when its row reads a free
/// parameter.
///
/// For a correctly constrained circuit the result is **empty**: given the
/// advice, every other wire is locally pinned by the constraints. A
/// non-empty result is an under-constrained wire found *algebraically* —
/// no mutation has to land on the free direction, no repair walk has to
/// propagate it, and no anchor has to observe it. This complements the
/// cheat differential, which covers the advice-level bug class (a wire
/// that should be derived but is exposed as advice) that this check, by
/// construction, cannot see.
///
/// # Exemptions and caveats
///
/// `free` must include every *intentionally* free wire, or the oracle
/// reports false positives: the advice itself, [`Recorder::extras`] (gate
/// $D$ wires a pooling allocator handed out as advice — their `c·d = 0` is
/// captured, but with the gate's output honestly zero it pins nothing), and
/// [`TrackingAllocator::wasted`] (the `b`/`c` wires of allocation gates).
///
/// Rank can only *drop* at special witnesses (vanishing partial
/// derivatives), so this can report movable wires that a generic witness
/// would pin — e.g. an `is_zero` inverse hint when the input is honestly
/// zero — but never the reverse: a clean result at any satisfying witness
/// is a clean result generically. Callers either guard those known
/// degenerate points or re-check at a resampled witness.
pub fn underconstrained_derived<F: Field>(
    events: &[Event<F>],
    values: &[F],
    free: &[usize],
) -> Vec<usize> {
    let rref = Rref::build(events, values, free);
    let d = rref.wire_of.len();

    // Non-pivot columns are free parameters; a pivot column moves iff its
    // RREF row reads a free parameter.
    (0..d)
        .filter(|&c| match rref.pivot_row_of_col[c] {
            None => true,
            Some(pr) => {
                (0..d).any(|x| rref.pivot_row_of_col[x].is_none() && rref.rows[pr][x] != F::ZERO)
            }
        })
        .map(|c| rref.wire_of[c])
        .collect()
}

/// The reduced row echelon form of the Jacobian of `events` at `values`,
/// restricted to the columns not in `free` (those directions are pinned to
/// zero). Backs [`underconstrained_derived`].
struct Rref<F> {
    rows: Vec<Vec<F>>,
    pivot_row_of_col: Vec<Option<usize>>,
    wire_of: Vec<usize>,
}

impl<F: Field> Rref<F> {
    fn build(events: &[Event<F>], values: &[F], free: &[usize]) -> Self {
        let n = values.len();
        let mut fixed = vec![false; n];
        fixed[Recorder::<F>::ONE] = true;
        for &w in free {
            fixed[w] = true;
        }

        // Map derived wires onto dense columns.
        let mut col_of = vec![usize::MAX; n];
        let mut wire_of = Vec::new();
        for (w, fx) in fixed.iter().enumerate() {
            if !fx {
                col_of[w] = wire_of.len();
                wire_of.push(w);
            }
        }
        let d = wire_of.len();

        // Jacobian rows over the derived columns (fixed columns contribute
        // nothing: their direction is zero).
        let mut rows: Vec<Vec<F>> = Vec::new();
        let mut push_row = |entries: &[(usize, F)]| {
            let mut row = vec![F::ZERO; d];
            let mut nonzero = false;
            for &(w, c) in entries {
                if !fixed[w] && c != F::ZERO {
                    row[col_of[w]] += c;
                    nonzero = true;
                }
            }
            if nonzero {
                rows.push(row);
            }
        };
        for ev in events {
            match ev {
                Event::Lin { out, terms } => {
                    let mut entries = terms.clone();
                    entries.push((*out, -F::ONE));
                    push_row(&entries);
                }
                Event::Gate { a, b, c } => {
                    push_row(&[(*a, values[*b]), (*b, values[*a]), (*c, -F::ONE)]);
                }
                Event::Enforce { terms } => push_row(terms),
                Event::Extra { c, d } => push_row(&[(*c, values[*d]), (*d, values[*c])]),
            }
        }

        // Gauss–Jordan elimination to reduced row echelon form.
        let mut pivot_row_of_col: Vec<Option<usize>> = vec![None; d];
        let mut r = 0;
        for (c, pivot) in pivot_row_of_col.iter_mut().enumerate() {
            if r == rows.len() {
                break;
            }
            let Some(pr) = (r..rows.len()).find(|&i| rows[i][c] != F::ZERO) else {
                continue;
            };
            rows.swap(r, pr);
            let inv = rows[r][c].invert().unwrap();
            for x in c..d {
                rows[r][x] *= inv;
            }
            for i in 0..rows.len() {
                if i != r && rows[i][c] != F::ZERO {
                    let f = rows[i][c];
                    for x in c..d {
                        let t = rows[r][x] * f;
                        rows[i][x] -= t;
                    }
                }
            }
            *pivot = Some(r);
            r += 1;
        }

        Rref {
            rows,
            pivot_row_of_col,
            wire_of,
        }
    }
}

/// The largest cluster of coupled unknowns [`repair`] will solve by dense
/// elimination, bounding its cubic cost per pass.
const CLUSTER_SOLVE_CAP: usize = 96;

/// Solve the captured constraint graph for the witness a malicious prover
/// could submit, given the free wires it has chosen.
///
/// `free` seeds the *known* set with the prover's committed degrees of
/// freedom (held at their — possibly mutated — values in `values`) plus the
/// fixed ONE wire; everything else is *derived* and solved from the
/// constraints. Two cooperating passes run to a fixpoint:
///
/// 1. **Single-unknown propagation** (issue #796 item 1): apply any
///    constraint with exactly one unknown wire and solve it. `Lin` once all
///    terms are known; a `Gate` output `c := a·b` or — for `invert`/
///    `divide` — an *input* `a := c/b` / `b := c/a` (requires the known
///    operand nonzero); an `Enforce` with one unknown term; an `Extra`
///    whose known side is nonzero, which zeroes the other (`c ≠ 0 ⇒ d = 0`
///    and vice versa — a known *zero* side pins nothing).
/// 2. **Linear-cluster solving** (issue #796 follow-up): when propagation
///    stalls, the remaining unknowns may still be jointly determined by a
///    coupled *linear* subsystem that no single constraint cracks (e.g. an
///    `invert`/`divide` chain, or two wires pinned only together). Gather
///    every constraint that is linear in the current unknowns — `Lin`,
///    `Enforce`, any `Gate` with at least one *known* operand (a known
///    operand makes `a·b = c` linear), and any `Extra` with a known nonzero
///    side — and solve that system by Gauss–Jordan elimination, committing
///    the wires the system *forces* before resorting to holding
///    under-determined unknowns at their honest values. Newly solved wires
///    can unlock more propagation, so the two passes alternate.
///
/// # Why no false positives
///
/// [`repair`] only ever produces a concrete witness; whether ragu accepts
/// it is decided by [`constraints_hold`] checking *every* captured
/// constraint afterwards — repair never asserts acceptance by inference, so
/// no solving step can manufacture one. The invariants that keep it honest:
///
/// * **Free wires are never overwritten.** Both passes only assign wires
///   outside `free`, so the prover's committed degrees of freedom (the
///   cheated advice, and in accomplice mode the fixed advice) are preserved
///   exactly — repair cannot "fix" a cheat by silently editing what the
///   prover committed.
/// * **Found ⇒ feasible.** Any assignment the linear solve emits satisfies
///   the linear subsystem by construction; the nonlinear gates it could not
///   include are re-checked by `constraints_hold`. An inconsistent subsystem
///   (no extension of the current knowns exists) is left unsolved, so the
///   residual violation surfaces rather than being papered over.
/// * **Under-determination is benign, but only once.** A genuinely free
///   derived direction (an under-constraint) leaves the linear system
///   rank-deficient; repair pins the free parameters to honest values and
///   solves the rest. Picking one satisfying witness is correct — a malicious
///   prover could submit it — and the differential's verdict comes from
///   comparing that witness's *observable* anchors against the native oracle,
///   not from how repair resolved the slack. What is *not* benign is picking
///   early: an assigned wire is never revisited, so a choice made before the
///   available deductions are exhausted can be contradicted later with no way
///   back. Hence the two-tier commitment in `cluster_solve` — deduce first,
///   choose only when nothing is left to deduce.
pub fn repair<F: Field>(events: &[Event<F>], values: &mut [F], free: &[usize]) {
    let mut known = vec![false; values.len()];
    known[Recorder::<F>::ONE] = true;
    for &w in free {
        known[w] = true;
    }

    loop {
        propagate(events, values, &mut known);
        // Propagation has stalled; try to crack a coupled linear cluster.
        // If that solves nothing new, the fixpoint is reached.
        if !cluster_solve(events, values, &mut known) {
            break;
        }
    }
}

/// Single-unknown propagation to a fixpoint (pass 1 of [`repair`]).
fn propagate<F: Field>(events: &[Event<F>], values: &mut [F], known: &mut [bool]) {
    loop {
        let mut changed = false;
        for ev in events {
            match ev {
                Event::Lin { out, terms } => {
                    if !known[*out] && terms.iter().all(|(w, _)| known[*w]) {
                        values[*out] = terms.iter().map(|(w, c)| values[*w] * c).sum();
                        known[*out] = true;
                        changed = true;
                    }
                }
                Event::Gate { a, b, c } => match (known[*a], known[*b], known[*c]) {
                    (true, true, false) => {
                        values[*c] = values[*a] * values[*b];
                        known[*c] = true;
                        changed = true;
                    }
                    (false, true, true) if values[*b] != F::ZERO => {
                        values[*a] = values[*c] * values[*b].invert().unwrap();
                        known[*a] = true;
                        changed = true;
                    }
                    (true, false, true) if values[*a] != F::ZERO => {
                        values[*b] = values[*c] * values[*a].invert().unwrap();
                        known[*b] = true;
                        changed = true;
                    }
                    _ => {}
                },
                Event::Enforce { terms } => {
                    let mut unknown = terms.iter().filter(|(w, _)| !known[*w]);
                    if let Some(&(uw, uc)) = unknown.next()
                        && unknown.next().is_none()
                        && uc != F::ZERO
                    {
                        // Σ cᵢ·wᵢ = 0, one unknown wⱼ ⇒ wⱼ = −(Σ_{i≠j} cᵢ·wᵢ)/cⱼ.
                        let rest: F = terms
                            .iter()
                            .filter(|(w, _)| *w != uw)
                            .map(|(w, c)| values[*w] * c)
                            .sum();
                        values[uw] = -rest * uc.invert().unwrap();
                        known[uw] = true;
                        changed = true;
                    }
                }
                // c·d = 0 with one side known and nonzero forces the other to
                // zero; a known zero side leaves the other side free.
                Event::Extra { c, d } => match (known[*c], known[*d]) {
                    (true, false) if values[*c] != F::ZERO => {
                        values[*d] = F::ZERO;
                        known[*d] = true;
                        changed = true;
                    }
                    (false, true) if values[*d] != F::ZERO => {
                        values[*c] = F::ZERO;
                        known[*c] = true;
                        changed = true;
                    }
                    _ => {}
                },
            }
        }
        if !changed {
            break;
        }
    }
}

/// Linear-cluster solving (pass 2 of [`repair`]): solve the coupled linear
/// subsystem over the currently-unknown wires. Returns whether any wire was
/// newly solved.
///
/// Each linearizable constraint becomes a row `Σ cᵢ·xᵢ = rhs` over the
/// unknown columns, with known wires folded into `rhs`. A `Gate a·b = c`
/// contributes a row only when at least one of `a`, `b` is known (then it
/// is linear); a gate with both operands unknown is genuinely nonlinear and
/// is left for [`constraints_hold`] to check. An `Extra c·d = 0` likewise
/// contributes a row only when one side is known *and nonzero* (`c̄·d = 0`
/// pins `d`); a known zero side constrains nothing. The augmented matrix is
/// reduced to row echelon form; an inconsistent row (`0 = nonzero`, no
/// solution) abandons the solve.
///
/// # Least commitment
///
/// Pivot wires are then assigned in two tiers, and the distinction is load
/// bearing. In reduced row echelon form a pivot row is zero in every *other*
/// pivot column, so its remaining nonzero coefficients all sit in non-pivot
/// (free) columns:
///
/// * **Forced** — the row reads no free column, so the system determines the
///   pivot outright (`x_pc = rhs`). Committing it is a deduction.
/// * **Guessed** — the row still reads a free column, so the pivot's value
///   depends on a choice not yet made. Holding those free columns at their
///   honest values and committing is a *guess*.
///
/// A guess taken too early is unrecoverable: neither pass revisits an
/// assigned wire, so a later constraint that contradicts it can only surface
/// as a spurious rejection. The concrete failure is an `is_zero` whose input
/// is an accomplice advice wire — both operands of its hint gates are
/// unknown on the first pass, so those gates contribute no row at all and the
/// booleanity enforce alone pivots the result bit against the honest branch;
/// once the anchors later move the input across zero, the frozen bit
/// contradicts the gate and the witness is rejected even though a satisfying
/// assignment exists.
///
/// So forced pivots are committed first and alone; a pass that forces
/// anything returns immediately, letting [`propagate`] and a fresh pass run
/// against the larger known set. Only when nothing at all is forced does the
/// guessing tier run, which is the documented benign under-determination —
/// by then every deduction available has already been made.
fn cluster_solve<F: Field>(events: &[Event<F>], values: &mut [F], known: &mut [bool]) -> bool {
    // Columns: the still-unknown wires.
    let mut col_of = vec![usize::MAX; values.len()];
    let mut wire_of = Vec::new();
    for (w, k) in known.iter().enumerate() {
        if !k {
            col_of[w] = wire_of.len();
            wire_of.push(w);
        }
    }
    let m = wire_of.len();
    if m == 0 || m > CLUSTER_SOLVE_CAP {
        return false;
    }

    // Build the augmented system. `entries` is `Σ coeff·wire = 0`; the row
    // builder splits known wires into the constant column at index `m`.
    let mut rows: Vec<Vec<F>> = Vec::new();
    let push = |entries: &[(usize, F)], rows: &mut Vec<Vec<F>>| {
        let mut row = vec![F::ZERO; m + 1];
        let mut has_unknown = false;
        for &(w, c) in entries {
            if known[w] {
                row[m] -= c * values[w]; // move to RHS
            } else {
                row[col_of[w]] += c;
                has_unknown = true;
            }
        }
        if has_unknown {
            rows.push(row);
        }
    };
    for ev in events {
        match ev {
            Event::Lin { out, terms } => {
                let mut entries = terms.clone();
                entries.push((*out, -F::ONE));
                push(&entries, &mut rows);
            }
            Event::Enforce { terms } => push(terms, &mut rows),
            Event::Gate { a, b, c } => {
                // Linear iff an operand is known; pick the known one as the
                // coefficient on the other.
                if known[*a] {
                    push(&[(*b, values[*a]), (*c, -F::ONE)], &mut rows);
                } else if known[*b] {
                    push(&[(*a, values[*b]), (*c, -F::ONE)], &mut rows);
                }
            }
            Event::Extra { c, d } => {
                // Linear iff a side is known; a known zero side would give
                // the empty row `0 = 0`, so only a nonzero side contributes.
                if known[*c] && values[*c] != F::ZERO {
                    push(&[(*d, values[*c])], &mut rows);
                } else if known[*d] && values[*d] != F::ZERO {
                    push(&[(*c, values[*d])], &mut rows);
                }
            }
        }
    }
    if rows.is_empty() {
        return false;
    }

    // Gauss–Jordan over the m unknown columns (the constant sits at m).
    let mut pivot_col_of_row = Vec::new();
    let mut r = 0;
    for c in 0..m {
        let Some(pr) = (r..rows.len()).find(|&i| rows[i][c] != F::ZERO) else {
            continue;
        };
        rows.swap(r, pr);
        let inv = rows[r][c].invert().unwrap();
        for x in c..=m {
            rows[r][x] *= inv;
        }
        for i in 0..rows.len() {
            if i != r && rows[i][c] != F::ZERO {
                let f = rows[i][c];
                for x in c..=m {
                    let t = rows[r][x] * f;
                    rows[i][x] -= t;
                }
            }
        }
        pivot_col_of_row.push(c);
        r += 1;
        if r == rows.len() {
            break;
        }
    }

    // Inconsistent row (all-zero coefficients, nonzero constant) ⇒ the
    // subsystem has no solution: leave everything unsolved.
    if rows
        .iter()
        .any(|row| row[..m].iter().all(|&x| x == F::ZERO) && row[m] != F::ZERO)
    {
        return false;
    }

    // Tier 1: commit the pivots the system forces. An RREF pivot row reads no
    // other pivot column, so a row whose only nonzero coefficient is the pivot
    // itself determines that wire outright — no free column, no choice.
    let mut forced = false;
    for (row_idx, &pc) in pivot_col_of_row.iter().enumerate() {
        let reads_free = rows[row_idx][..m]
            .iter()
            .enumerate()
            .any(|(j, &coeff)| j != pc && coeff != F::ZERO);
        if !reads_free {
            let wire = wire_of[pc];
            values[wire] = rows[row_idx][m];
            known[wire] = true;
            forced = true;
        }
    }
    // Deductions can unlock propagation (and relinearize gates whose operand
    // just became known), so hand control back rather than guessing on top of
    // a half-solved system.
    if forced {
        return true;
    }

    // Tier 2: nothing is forced, so every remaining pivot depends on a free
    // column. Pin those at their honest values and take the resulting
    // solution — a satisfying witness for an under-determined subsystem.
    let mut changed = false;
    for (row_idx, &pc) in pivot_col_of_row.iter().enumerate() {
        // RREF row: x_pc + Σ_{nonpivot j} row[j]·x_j = row[m].
        let mut val = rows[row_idx][m];
        for (j, &coeff) in rows[row_idx][..m].iter().enumerate() {
            if j != pc && coeff != F::ZERO {
                val -= coeff * values[wire_of[j]];
            }
        }
        let wire = wire_of[pc];
        values[wire] = val;
        known[wire] = true;
        changed = true;
    }
    changed
}

/// After repair, do all captured constraints hold?
pub fn constraints_hold<F: Field>(events: &[Event<F>], values: &[F]) -> bool {
    events.iter().all(|ev| match ev {
        Event::Lin { out, terms } => {
            values[*out] == terms.iter().map(|(w, c)| values[*w] * c).sum()
        }
        Event::Gate { a, b, c } => values[*a] * values[*b] == values[*c],
        Event::Enforce { terms } => terms.iter().map(|(w, c)| values[*w] * c).sum::<F>() == F::ZERO,
        Event::Extra { c, d } => values[*c] * values[*d] == F::ZERO,
    })
}

/// Build a deliberately under-constrained circuit in the recorder and
/// assert the patcher's soundness signal fires. Panics if it does not.
///
/// The circuit allocates `root` and `square` as independent free wires and
/// anchors `square` to its honest value `root²`, but omits the
/// `square = root²` gate. Mutating `root` and repairing through the
/// captured constraints leaves `square` untouched (no rule carries the
/// change), so ragu accepts — while the true semantics say `square` must
/// move, violating the anchor. The mismatch is the signal.
///
/// This runs as a unit test (`tests::selftest_fires`) and on demand in the
/// fuzz target (`PATCHER_SELFTEST=1`): proof the soundness direction is not
/// vacuous.
pub fn selftest<F: PrimeField>() {
    let root_honest = F::from(7u64);

    let mut rec = Recorder::<F>::new();
    let root = rec.push_wire(root_honest); // free advice
    let square = rec.push_wire(root_honest.square()); // free advice — BUG: not gated to root²

    // Anchor `square` to its honest value via `enforce_zero(square - 49)`,
    // exactly as the substrate's `Op::Anchor` would: a constant wire, a
    // difference Lin, and a 1-term check.
    let pin =
        rec.add(|lc| lc.add_term(&Recorder::<F>::ONE, Coeff::Arbitrary(root_honest.square())));
    let diff = rec.add(|lc| lc.add(&square).add_term(&pin, Coeff::NegativeOne));
    rec.enforce_zero(|lc| lc.add(&diff)).unwrap();

    assert!(
        constraints_hold(&rec.events, &rec.values),
        "self-test honest circuit must satisfy its own constraints",
    );

    // Cheat the root; repair cannot reach `square` (no gate links them).
    let mut values = rec.values.clone();
    let delta = F::from(3u64);
    values[root] += delta;
    repair(&rec.events, &mut values, &[root]);
    let ragu_accepts = constraints_hold(&rec.events, &values);

    // True semantics: square must be root²; after the cheat it isn't.
    let native_ok = (root_honest + delta).square() == root_honest.square();

    assert_ne!(
        ragu_accepts, native_ok,
        "PATCHER SELF-TEST: the oracle failed to fire on a known \
         under-constrained alloc_square (ragu_accepts={ragu_accepts}, \
         native_ok={native_ok}). The soundness direction is vacuous — the \
         engine would miss real bugs.",
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use pasta_curves::{Fp, Fq};
    use ragu_core::{
        drivers::DriverValue,
        gadgets::{Bound, Kind},
        maybe::Maybe,
        routines::{Prediction, Routine},
    };
    use ragu_primitives::{Boolean, Element};

    /// A small routine whose emitted linear relation is visible to both the
    /// recorder and playback drivers.
    #[derive(Clone)]
    struct ScaleByThreeRoutine;

    impl Routine<Fp> for ScaleByThreeRoutine {
        type Input = Kind![Fp; Element<'_, _>];
        type Output = Kind![Fp; Element<'_, _>];
        type Aux<'dr> = Fp;

        fn execute<'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            input: Bound<'dr, D, Self::Input>,
            aux: DriverValue<D, Self::Aux<'dr>>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            let output = Element::alloc(dr, &mut (), aux)?;
            let expected = input.scale(dr, Coeff::Arbitrary(Fp::from(3u64)));
            dr.enforce_zero(|lc| lc.add(expected.wire()).sub(output.wire()))?;
            Ok(output)
        }

        fn predict<'dr, D: Driver<'dr, F = Fp, Wire = ()>>(
            &self,
            _dr: &mut D,
            input: &Bound<'dr, D, Self::Input>,
        ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>>
        {
            Ok(Prediction::Unknown(
                input.value().map(|value| *value * Fp::from(3u64)),
            ))
        }
    }

    fn replay_routine(values: Vec<Fp>) -> Result<bool> {
        let mut playback = Playback::new(values);
        let input = Element::alloc(
            &mut playback,
            &mut (),
            Playback::<Fp>::just(|| Fp::from(7u64)),
        )?;
        playback.routine(ScaleByThreeRoutine, input)?;
        Ok(playback.accepts())
    }

    #[test]
    fn routines_are_recorded_and_played_back() -> Result<()> {
        let mut recorder = Recorder::<Fp>::new();
        let input = Element::alloc(
            &mut recorder,
            &mut TrackingAllocator::default(),
            Recorder::<Fp>::just(|| Fp::from(7u64)),
        )?;
        let output = recorder.routine(ScaleByThreeRoutine, input)?;
        let output_wire = *output.wire();

        assert!(constraints_hold(&recorder.events, &recorder.values));
        assert!(replay_routine(recorder.values.clone())?);

        let mut corrupted = recorder.values;
        corrupted[output_wire] += Fp::ONE;
        assert!(!replay_routine(corrupted)?);

        Ok(())
    }

    /// Replays two `Element::alloc`s through a plain `Standard` allocator —
    /// the production call sequence [`TrackingAllocator`] delegates to.
    fn replay_two_allocs(values: Vec<Fp>) -> Result<bool> {
        let mut playback = Playback::new(values);
        let mut alloc = Standard::<usize>::new();
        Element::alloc(
            &mut playback,
            &mut alloc,
            Playback::<Fp>::just(|| Fp::from(5u64)),
        )?;
        Element::alloc(
            &mut playback,
            &mut alloc,
            Playback::<Fp>::just(|| Fp::from(9u64)),
        )?;
        Ok(playback.accepts())
    }

    /// Two allocations through the pooling allocator share one gate: the
    /// second lands on the gate's $D$ wire via `assign_extra`, and the
    /// recorder captures its `c·d = 0`. The regression: a witness that keeps
    /// the gate itself satisfied (`b = 1`, `c = a`) but leaves `d` at its
    /// nonzero advice value is rejected — by the stored events and by a
    /// `Standard` playback alike — where a recorder that never saw the
    /// auxiliary constraint accepted it.
    #[test]
    fn pooled_allocation_captures_extra_constraint() -> Result<()> {
        let mut rec = Recorder::<Fp>::new();
        let mut alloc = TrackingAllocator::default();
        let first = Element::alloc(
            &mut rec,
            &mut alloc,
            Recorder::<Fp>::just(|| Fp::from(5u64)),
        )?;
        let second = Element::alloc(
            &mut rec,
            &mut alloc,
            Recorder::<Fp>::just(|| Fp::from(9u64)),
        )?;
        let (a, d) = (*first.wire(), *second.wire());

        // One gate `(a, b, c)` at wires 1..=3 plus the redeemed `d` at 4.
        assert_eq!((a, d), (1, 4));
        assert_eq!(rec.values.len(), 5);
        assert_eq!(alloc.wasted, vec![2, 3]);
        assert_eq!(rec.extras, vec![d]);
        assert!(matches!(
            rec.events.as_slice(),
            [
                Event::Gate { a: 1, b: 2, c: 3 },
                Event::Extra { c: 3, d: 4 }
            ]
        ));
        assert!(constraints_hold(&rec.events, &rec.values));
        assert!(replay_two_allocs(rec.values.clone())?);

        // `a·b = c` still holds, but `c` is now nonzero next to `d = 9`:
        // only `C · D = 0` can reject this.
        let mut corrupted = rec.values.clone();
        corrupted[2] = Fp::ONE;
        corrupted[3] = corrupted[1];
        assert!(!constraints_hold(&rec.events, &corrupted));
        assert!(!replay_two_allocs(corrupted)?);

        Ok(())
    }

    /// `Boolean::alloc` donates its gate's spare $D$ token to the allocator,
    /// so the next `Element::alloc` redeems it instead of opening a gate, and
    /// the recorder pins that wire against the boolean gate's output with an
    /// [`Event::Extra`]. No fresh gate means no wasted wires.
    #[test]
    fn donated_extra_is_redeemed() -> Result<()> {
        let mut rec = Recorder::<Fp>::new();
        let mut alloc = TrackingAllocator::default();
        let bit = Boolean::alloc(&mut rec, &mut alloc, Recorder::<Fp>::just(|| true))?;
        let elem = Element::alloc(
            &mut rec,
            &mut alloc,
            Recorder::<Fp>::just(|| Fp::from(11u64)),
        )?;

        // Boolean gate `(bit, 1 − bit, 0)` at wires 1..=3; the element is
        // its `d` at wire 4.
        assert_eq!((*bit.wire(), *elem.wire()), (1, 4));
        assert!(alloc.wasted.is_empty());
        assert_eq!(rec.extras, vec![4]);
        assert_eq!(
            rec.events
                .iter()
                .filter(|ev| matches!(ev, Event::Gate { .. }))
                .count(),
            1
        );
        assert!(matches!(
            rec.events.last(),
            Some(Event::Extra { c: 3, d: 4 })
        ));
        assert!(constraints_hold(&rec.events, &rec.values));

        let mut playback = Playback::new(rec.values.clone());
        let mut alloc = Standard::<usize>::new();
        Boolean::alloc(&mut playback, &mut alloc, Playback::<Fp>::just(|| true))?;
        Element::alloc(
            &mut playback,
            &mut alloc,
            Playback::<Fp>::just(|| Fp::from(11u64)),
        )?;
        assert!(playback.accepts());

        Ok(())
    }

    /// The solver and the rank oracle both model `c·d = 0`. Repair: cheating
    /// the allocation gate's `b` propagates `c := a·b` nonzero, which forces
    /// the (solvable) `d` to zero — the only satisfying completion. Rank: at
    /// the honest witness `d` is a genuinely free direction the `Extra`
    /// cannot pin while `c = 0`, so it is movable unless listed free; once
    /// `c` is honestly nonzero the row `c̄·dd = 0` pins it.
    #[test]
    fn extra_constraint_in_repair_and_rank_oracle() -> Result<()> {
        let mut rec = Recorder::<Fp>::new();
        let mut alloc = TrackingAllocator::default();
        let a = *Element::alloc(
            &mut rec,
            &mut alloc,
            Recorder::<Fp>::just(|| Fp::from(5u64)),
        )?
        .wire();
        let d = *Element::alloc(
            &mut rec,
            &mut alloc,
            Recorder::<Fp>::just(|| Fp::from(9u64)),
        )?
        .wire();
        let (b, c) = (alloc.wasted[0], alloc.wasted[1]);

        let mut values = rec.values.clone();
        values[b] = Fp::ONE;
        repair(&rec.events, &mut values, &[a, b]);
        assert_eq!(values[c], values[a]);
        assert_eq!(values[d], Fp::ZERO);
        assert!(constraints_hold(&rec.events, &values));

        assert_eq!(
            underconstrained_derived(&rec.events, &rec.values, &[a, b]),
            vec![d]
        );
        assert!(underconstrained_derived(&rec.events, &rec.values, &[a, b, d]).is_empty());

        let mut pinned = rec.values.clone();
        pinned[b] = Fp::ONE;
        pinned[c] = pinned[a];
        pinned[d] = Fp::ZERO;
        assert!(constraints_hold(&rec.events, &pinned));
        assert!(underconstrained_derived(&rec.events, &pinned, &[a, b]).is_empty());

        Ok(())
    }

    /// Builds the circuit that the continuous-fuzzing crashes minimised down
    /// to, and returns whether [`repair`] finds the satisfying witness.
    ///
    /// Two advice wires `a` and `x`, an anchor pinning their difference, and
    /// `is_zero(x)` — the gadget's two hint gates (`x·b = 0`, `x·inv = 1 − b`)
    /// captured exactly as `ragu_primitives::boolean::is_zero` emits them.
    /// Only `a` is free: `x` is an *accomplice* the solver must derive from
    /// the anchor, which is what makes the hint gates nonlinear on the first
    /// cluster pass.
    ///
    /// Cheating `a` drags `x` along by the same delta to hold the anchor, so
    /// `x_target` is what the accomplice is forced to become. When `x_honest`
    /// and `x_target` sit on opposite sides of zero the honest `is_zero`
    /// branch and the repaired one disagree. A satisfying witness always
    /// exists (`b`, `inv` and `nb` are fully determined once `x` is), so this
    /// must return `true`; returning `false` is the frozen-guess bug.
    fn accomplice_crosses_zero<F: PrimeField>(x_honest: u64, x_target: u64) -> bool {
        let one = Recorder::<F>::ONE;
        let delta = F::from(x_target) - F::from(x_honest);
        let x_honest = F::from(x_honest);
        let a_honest = F::from(100u64);
        let anchor = a_honest - x_honest;

        let mut rec = Recorder::<F>::new();
        let a = rec.push_wire(a_honest);
        let x = rec.push_wire(x_honest);

        // Anchor: enforce (a − x) − anchor = 0, pinning the difference so a
        // cheat on `a` propagates into the accomplice `x`.
        let diff = rec.add(|lc| lc.add(&a).add_term(&x, Coeff::NegativeOne));
        rec.enforce_zero(|lc| lc.add(&diff).add_term(&one, Coeff::Arbitrary(-anchor)))
            .unwrap();

        // is_zero(x), constraint 1: x · b = 0.
        let is_zero_honest = if x_honest == F::ZERO { F::ONE } else { F::ZERO };
        let (xc1, b, zp) = rec
            .mul(|| {
                Ok((
                    Coeff::Arbitrary(x_honest),
                    Coeff::Arbitrary(is_zero_honest),
                    Coeff::Zero,
                ))
            })
            .unwrap();
        rec.enforce_equal(&xc1, &x).unwrap();
        rec.enforce_zero(|lc| lc.add(&zp)).unwrap();

        // is_zero(x), constraint 2: x · inv = 1 − b.
        let inv_honest = x_honest.invert().unwrap_or(F::ZERO);
        let (xc2, _inv, nb) = rec
            .mul(|| {
                Ok((
                    Coeff::Arbitrary(x_honest),
                    Coeff::Arbitrary(inv_honest),
                    Coeff::Arbitrary(F::ONE - is_zero_honest),
                ))
            })
            .unwrap();
        rec.enforce_equal(&xc2, &x).unwrap();
        rec.enforce_zero(|lc| lc.add(&nb).sub(&one).add(&b))
            .unwrap();

        assert!(
            constraints_hold(&rec.events, &rec.values),
            "planted circuit must satisfy its own constraints honestly",
        );

        // Cheat `a`; only `a` is committed, so `x` is solvable.
        let mut values = rec.values.clone();
        values[a] = a_honest + delta;
        repair(&rec.events, &mut values, &[a]);
        constraints_hold(&rec.events, &values)
    }

    /// The accomplice moves an honestly-*zero* `is_zero` input off zero, so
    /// the result bit must fall from 1 to 0. This is the Aug 16 reproducer.
    #[test]
    fn accomplice_moves_is_zero_input_off_zero() {
        assert!(
            accomplice_crosses_zero::<Fp>(0, 1),
            "repair failed to re-solve the is_zero hint after the accomplice \
             left zero, rejecting a satisfiable witness",
        );
        assert!(accomplice_crosses_zero::<Fq>(0, 1));
    }

    /// The mirror: the accomplice drives an honestly-*nonzero* `is_zero` input
    /// to zero, so the result bit must rise from 0 to 1. This is the Aug 12
    /// and Aug 14 reproducers.
    #[test]
    fn accomplice_moves_is_zero_input_onto_zero() {
        assert!(
            accomplice_crosses_zero::<Fp>(7, 0),
            "repair failed to re-solve the is_zero hint after the accomplice \
             reached zero, rejecting a satisfiable witness",
        );
        assert!(accomplice_crosses_zero::<Fq>(7, 0));
    }

    /// A cheat that leaves the `is_zero` input on the same side of zero is the
    /// easy case, and must keep working.
    #[test]
    fn accomplice_stays_off_zero() {
        assert!(accomplice_crosses_zero::<Fp>(7, 9));
        assert!(accomplice_crosses_zero::<Fq>(7, 9));
    }

    /// The planted under-constrained circuit must still produce the soundness
    /// disagreement — the guard that the two-tier commitment in
    /// [`cluster_solve`] made repair *more* complete without making it
    /// permissive enough to mask a genuinely missing constraint.
    #[test]
    fn selftest_fires() {
        selftest::<Fp>();
        selftest::<Fq>();
    }

    /// An under-determined subsystem must still be solved: with nothing left
    /// to deduce, the guessing tier has to run and pick a witness rather than
    /// stalling. Two raw wires appear only as `p + q = 3`, so neither is
    /// forced.
    #[test]
    fn under_determined_subsystem_still_solved() {
        let one = Recorder::<Fp>::ONE;
        let mut rec = Recorder::<Fp>::new();
        let p = rec.push_wire(Fp::ONE);
        let q = rec.push_wire(Fp::from(2u64));
        rec.enforce_zero(|lc| {
            lc.add(&p)
                .add(&q)
                .add_term(&one, Coeff::Arbitrary(-Fp::from(3u64)))
        })
        .unwrap();
        assert!(constraints_hold(&rec.events, &rec.values));

        // Start both unknown wires from a non-satisfying choice. The guessing
        // tier must retain one free direction and solve the other.
        let mut values = rec.values.clone();
        values[p] += Fp::ONE;
        values[q] += Fp::ONE;
        repair(&rec.events, &mut values, &[]);
        assert!(
            constraints_hold(&rec.events, &values),
            "the guessing tier must still resolve an under-determined system",
        );
    }
}

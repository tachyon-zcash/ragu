//! The "patcher" technique with a real repair engine (issues #728, #793).
//!
//! `fuzz_circuit_cheat` is a patcher whose "repair" is re-tracing the
//! circuit on the mutated witness: every wire — including advice — is
//! recomputed by the gadget's own witness logic. That can never expose an
//! under-constrained *advice* wire, because the gadget always recomputes
//! the *correct* advice on a re-run, masking a missing constraint.
//!
//! This target closes that gap. It synthesizes a [`ragu_testing_fuzz::substrate`]
//! program through a **recording driver** that captures the constraint
//! graph ragu actually emits — every multiplication gate `a·b=c`, every
//! linear-combination wire, every `enforce_zero` — together with the honest
//! wire values. The patcher then mutates one or more *free advice* wires
//! and **repairs through the captured constraints**, not through the gadget
//! logic:
//!
//! * a multiplication gate forces `c := a·b`,
//! * a linear-combination wire is recomputed from its terms,
//! * a copy constraint (`enforce_equal`, the 2-term `enforce_zero` ragu
//!   emits to wire a fresh gate input to an operand) forces the later wire
//!   to equal the earlier one,
//! * every other `enforce_zero` is a *check*, not a repair rule.
//!
//! A fixpoint pass searches for a witness a malicious prover could submit.
//! Acceptance is checked against every captured constraint afterwards; a
//! failed repair is inconclusive because the solver is deliberately bounded.
//!
//! # Vocabulary
//!
//! The vocabulary is `OpSet::ALL` minus [`Op::ConditionalSelect`] (it routes
//! a boolean back into an element, which needs field-valued select semantics
//! to compare soundly) and [`Op::AllocRaw`] (its skip depends on fuzzer
//! bytes, not a mutatable value). Everything else participates: the
//! arithmetic and allocation gadgets, the value-fallible `invert`/`divide`
//! (whose freshly-allocated inverse/quotient the single-unknown solver
//! back-solves), `is_zero`, and the boolean allocator/combinators
//! `BoolAlloc`/`BoolNot`/`BoolAnd` (whose booleanity and result constraints
//! are plain gates and enforces the solver already models). The free advice
//! the patcher mutates is the element-stack advice (witness inputs,
//! `AllocSpecial`, `AllocSquare` roots) plus, via a dedicated boolean cheat,
//! the `BoolAlloc` wires.
//!
//! [`Op::ConditionalSelect`]: ragu_testing_fuzz::substrate::Op::ConditionalSelect
//! [`Op::AllocRaw`]: ragu_testing_fuzz::substrate::Op::AllocRaw
//!
//! # Mutations
//!
//! A cheat rewrites a free advice wire's value, and the vocabulary targets
//! the corner cases under-constrained bugs live in (see [`Mutation`]):
//! small and full-width additive deltas, exact special values, negation
//! and scaling, and aliasing/swaps against other advice wires — the direct
//! probe for missing copy constraints. All three kinds of prover-controlled
//! advice are cheatable: element-stack witnesses, `Fold` scales (replayed
//! through the native shadow's `fold_scales` so both sides judge the same
//! commitment), and `BoolAlloc` booleans (set to a non-`{0,1}` field value,
//! which the captured booleanity constraints must reject — the canonical
//! booleanity under-constraint).
//!
//! The whole differential is field-generic and runs over **both** pasta
//! fields (`Fp` and `Fq`) per input, catching field-dependent constant bugs
//! for nearly free.
//!
//! # The differential
//!
//! Alongside the captured graph the substrate's native shadow knows each
//! gadget's true semantics (the oracle), independent of ragu. For the
//! mutated witness:
//!
//! * `ragu_accepts` — do all captured constraints hold after repair?
//! * `native_satisfied` — does the native shadow, recomputing the full
//!   dependency chain, still satisfy every anchor?
//!
//! The load-bearing assertion is `!(ragu_accepts && !native_satisfied)`.
//! A rejected repaired witness is inconclusive—the bounded solver may simply
//! have missed a satisfying extension—and completeness has its own exact
//! target. **If a gadget omits a constraint, repair fails to
//! propagate the cheat** (there is no captured rule to carry it), so the
//! anchored wire keeps its honest value and ragu accepts, while the native
//! shadow — which knows the true relation — reports the anchor violated.
//! That disagreement is the under-constrained-advice signal.
//!
//! Independently of any cheat, every input also runs the **rank/nullity
//! oracle** (`underconstrained_derived`): the Jacobian of the captured
//! constraints at the honest witness, restricted to the non-free wires,
//! must have a trivial null space — an algebraic, mutation-free detector
//! for wires the constraints fail to pin.
//!
//! Every input also runs a **free-advice discovery cross-check**
//! (`discover_free_advice`): the wires the captured graph leaves
//! undetermined — found structurally, with no help from the substrate —
//! must all be allocations the substrate knows it made (advice, pooled $D$
//! wires, allocation waste). A free wire that is *not* an allocation is a
//! hint some gadget left unpinned, found without any cheat; and since the
//! substrate's allocation list is ground truth, the check also keeps
//! discovery honest for the circuits it will be pointed at without one.
//!
//! Every input also runs a **playback cross-check**: the repaired witness is
//! re-verified by a fresh synthesis of the *real* gadget calls
//! (`patcher::Playback`) with an independent linear-combination evaluator.
//! If that live re-execution disagrees with the recorder's stored-event
//! verdict, the recorder mis-captured the circuit and every signal is
//! suspect — so the engine validates its own model on every run.
//!
//! Allocation goes through the production pooling allocator on both sides
//! (`patcher::TrackingAllocator` wraps a `Standard`; playback uses a plain
//! `Standard`), so the captured graph includes the gate $D$ wires a pooled
//! allocation hands out — redeemed from `BoolAlloc`/`IsZero` donations or
//! paired with the previous allocation — and their `C · D = 0` constraint.
//!
//! The engine — the recording driver, the repair solver, the oracles, and
//! the planted-bug selftest — lives in `ragu_testing::patcher`, where it is
//! unit tested in CI and available to `ragu_pcd`'s own tests for the
//! internal recursion circuits (issue #793). `PATCHER_SELFTEST=1` runs that
//! selftest here on demand: a deliberately under-constrained circuit (a root
//! and a "square" allocated as independent free wires, with the
//! `square = root²` gate omitted) whose oracle must fire — proof the
//! soundness direction is not vacuous.

#![no_main]

use arbitrary::Arbitrary;
use ff::PrimeField;
use libfuzzer_sys::fuzz_target;
use pasta_curves::{Fp, Fq};
use ragu_primitives::allocator::Standard;
use ragu_testing::patcher::{
    Playback, Recorder, TrackingAllocator, constraints_hold, discover_free_advice, repair,
    selftest, underconstrained_derived,
};
use ragu_testing_fuzz::substrate::{
    AdviceSlot, Limits, OpKind, OpSet, Overrides, Program, anchor_tail, native_satisfied,
    shadow_eval, special_value, synthesize,
};
use std::sync::atomic::{AtomicU64, Ordering};

/// Vacuity telemetry (`PATCHER_STATS=1`): a run is *vacuous* when no oracle
/// observed its cheat — it bailed on an out-of-model control flip, or both
/// sides accepted because the cheat dissolved into unobserved freedom. The
/// anchor tail exists to keep this fraction low; if it creeps up, the
/// differential is going soft.
static RUNS: AtomicU64 = AtomicU64::new(0);
/// See [`RUNS`].
static VACUOUS: AtomicU64 = AtomicU64::new(0);
/// Runs bailed because a cheat un-skipped an `invert`/`divide`.
static GREW: AtomicU64 = AtomicU64::new(0);
/// Runs where a cheat zeroed an `invert`/`divide` input and
/// the zero-divisor rejection check ran instead of bailing.
static SHRANK: AtomicU64 = AtomicU64::new(0);
/// Runs where only an `is_zero` result flipped, now compared instead of
/// bailed.
static BOOL_FLIP: AtomicU64 = AtomicU64::new(0);

/// Wire-count cap for the rank/nullity oracle: the dense elimination is
/// cubic, so outsized graphs skip it (the cheat differential still runs).
const RANK_WIRE_CAP: usize = 384;

// ---------------------------------------------------------------------------
// Harness.
// ---------------------------------------------------------------------------

/// How a cheat rewrites the honest value of its target advice wire.
///
/// `AddSmall` is the historical mutation, but a `u64` delta explores only a
/// ~2⁻¹⁹⁰ sliver of the field around the honest value, and issue #728's
/// premise is that under-constrained bugs live at corner cases. The rest
/// aim directly at them: exact special values (0, ±1, p−2, 2⁻¹, roots of
/// unity, 2^k boundaries), full-width deltas, sign/scale flips, and
/// aliasing against another advice wire — the direct probe for a missing
/// copy constraint ("these two should both be pinned, but only one is").
#[derive(Arbitrary, Debug, Clone, Copy)]
enum Mutation {
    /// `v + δ` for a small delta `δ ∈ [0, 2⁶⁴)`.
    AddSmall(u64),
    /// `v + δ` for a full-width delta assembled from 32 LE bytes (see
    /// [`wide_value`]).
    AddWide([u8; 32]),
    /// Set to [`special_value`] of the index.
    SetSpecial(u8),
    /// `−v`.
    Negate,
    /// `v · m` for a small factor.
    MulSmall(u64),
    /// Set to the honest value of another advice wire (mod advice count).
    CopyFrom(u16),
    /// Swap honest values with another advice wire — the coordinated form
    /// of [`Mutation::CopyFrom`], moving both wires at once.
    SwapWith(u16),
}

/// A coordinated cheat: which free advice wire (mod advice count) and how
/// to rewrite its value. A run may apply several at once.
#[derive(Arbitrary, Debug, Clone, Copy)]
struct Cheat {
    advice: u16,
    mutation: Mutation,
}

/// Assembles a full-width field element from 32 LE bytes as four `u64`
/// limbs `Σ limbᵢ · 2⁶⁴ⁱ`, covering `[0, 2²⁵⁶) mod p` — deltas the `u64`
/// mutation can never reach. Generic over the field for dual-field runs.
fn wide_value<F: PrimeField>(bytes: &[u8; 32]) -> F {
    let two64 = F::from(u64::MAX) + F::ONE; // 2⁶⁴
    let mut acc = F::ZERO;
    for chunk in bytes.chunks(8).rev() {
        let limb = u64::from_le_bytes(chunk.try_into().unwrap());
        acc = acc * two64 + F::from(limb);
    }
    acc
}

#[derive(Arbitrary, Debug)]
struct Input {
    /// Element-advice wires to mutate simultaneously. Coordinated multi-wire
    /// cheats catch under-constraint that no single-wire change exposes
    /// (e.g. two wires whose product is pinned but neither is).
    cheats: Vec<Cheat>,
    /// Fold-scale advice wires to mutate (the freshly-allocated scale of an
    /// [`Op::Fold`]). These are prover-controlled advice just like element
    /// witnesses; the cheats flow through the native shadow's
    /// `Overrides::fold_scales` so both sides judge the same commitment.
    fold_cheats: Vec<Cheat>,
    /// Boolean-advice wires (mod boolean-advice count) to corrupt to a
    /// non-`{0,1}` field value. A non-empty list turns the run into a
    /// booleanity check: the captured `a·(1−a) = 0` constraints must reject
    /// the witness, or the boolean is under-constrained.
    bool_cheats: Vec<u16>,
    /// Raw program bytes, decoded via [`Program::decode`]. Last field, so
    /// `arbitrary_take_rest` hands it the remainder of the input.
    program: Vec<u8>,
}

/// Resolves a coordinated cheat over an advice list into `(index, new value)`
/// pairs, where `index` selects `honest[index]`. Deduplicated (first cheat on
/// an index wins, including the second leg of a swap), and every result is
/// nudged off the honest value so each cheat does real work. Shared by the
/// element- and fold-advice paths.
fn resolve_cheats<F: PrimeField>(cheats: &[Cheat], honest: &[F]) -> Vec<(usize, F)> {
    let n = honest.len();
    let mut out: Vec<(usize, F)> = Vec::new();
    if n == 0 {
        return out;
    }
    for ch in cheats {
        let i = ch.advice as usize % n;
        if out.iter().any(|(j, _)| *j == i) {
            continue;
        }
        let other = |o: u16| o as usize % n;
        let value = match ch.mutation {
            Mutation::AddSmall(d) => honest[i] + F::from(d),
            Mutation::AddWide(b) => honest[i] + wide_value::<F>(&b),
            Mutation::SetSpecial(s) => special_value(s),
            Mutation::Negate => -honest[i],
            Mutation::MulSmall(m) => honest[i] * F::from(m),
            Mutation::CopyFrom(o) => honest[other(o)],
            Mutation::SwapWith(o) => {
                let oj = other(o);
                if oj != i && !out.iter().any(|(j, _)| *j == oj) {
                    out.push((oj, honest[i]));
                }
                honest[oj]
            }
        };
        out.push((i, value));
    }
    for (i, v) in &mut out {
        if *v == honest[*i] {
            *v += F::ONE;
        }
    }
    out
}

/// The patcher vocabulary: `OpSet::ALL` minus `ConditionalSelect` and
/// `AllocRaw`.
///
/// The single-unknown solver (issue #796 item 1) handles any constraint
/// with one unknown, so the value-fallible arithmetic gadgets `invert` and
/// `divide` — whose freshly-allocated inverse/quotient is a *gate input*
/// the solver back-solves — are in scope (issue #796 item 2), as is
/// `is_zero` (`x·is_zero = 0`, `x·inv = 1 − is_zero`). The boolean
/// allocator and combinators `BoolAlloc`/`BoolNot`/`BoolAnd` also
/// participate: their booleanity (`a·b = 0`, `a + b = 1`) and result
/// constraints are plain gates and enforces the solver already models, and
/// a dedicated boolean cheat exercises booleanity directly.
///
/// Excluded: `ConditionalSelect` (it routes a boolean back into an element,
/// which needs field-valued select semantics to compare soundly) and
/// `AllocRaw` (a non-canonical 32-byte chunk skips its push, and unlike
/// `invert`/`divide` that skip depends on fuzzer bytes, not a mutatable
/// value, so the zero-crossing classification cannot neutralize it).
///
/// # Value-dependent solvability (classified in the harness)
///
/// A *cheat* that moves an `invert`/`divide`/`is_zero` input across zero
/// changes the native run's control flow. The harness classifies the three
/// resulting cases (see the zero-crossing block in the target) rather than
/// discarding them wholesale: a zeroed `invert`/`divide` input (stack
/// shrank) becomes a soundness check that ragu rejects; a flipped `is_zero`
/// result is compared normally (its hint witness is re-solved by the
/// cluster pass, and no `ConditionalSelect` can route the boolean into an
/// anchored element); only an honestly-skipped op that a cheat *un-skips*
/// (stack grew) remains out of model and bails.
fn opset() -> OpSet {
    OpSet::filtered(|k| {
        // Boolean allocation and the and/not combinators participate (their
        // booleanity and result constraints are plain gates/enforces the
        // solver already models, and the boolean cheat checks booleanity).
        // `ConditionalSelect` stays out — it routes a boolean back into an
        // element, which needs field-valued select semantics to compare
        // soundly. `AllocRaw` stays out (its skip depends on fuzzer bytes,
        // not a mutatable value).
        !matches!(k, OpKind::ConditionalSelect | OpKind::AllocRaw)
    })
}

fuzz_target!(|input: Input| {
    if std::env::var("PATCHER_SELFTEST").is_ok() {
        selftest::<Fp>();
        selftest::<Fq>();
        return;
    }

    let program = Program::decode(&input.program, opset(), Limits::default());

    if std::env::var("DEBUG_INPUT").is_ok() {
        eprintln!(
            "cheats = {:?}\nfold_cheats = {:?}\nbool_cheats = {:?}\n{program:#?}",
            input.cheats, input.fold_cheats, input.bool_cheats,
        );
        return;
    }
    if program.ops.is_empty() {
        return;
    }

    // Dual-field: run the whole differential over both pasta fields. The
    // substrate is field-generic, so this catches field-dependent constant
    // bugs (a hard-coded modulus, a `2^k` boundary) for nearly free.
    patch_round::<Fp>(&input, &program);
    patch_round::<Fq>(&input, &program);
});

/// One field's worth of the patcher differential over the decoded `program`.
fn patch_round<F: PrimeField<Repr = [u8; 32]>>(input: &Input, decoded: &Program) {
    // Maximize observability: anchor every derived slot the honest run
    // leaves live, so a cheat that propagates anywhere is observed by some
    // anchor (advice slots stay unanchored — see `anchor_tail`).
    let program = anchor_tail::<F>(decoded);

    // Honest native shadow: correct semantics, anchor observations, and the
    // free-advice inventory. Element-stack advice (witness inputs,
    // AllocSpecial, AllocSquare roots) are the mutation targets.
    let shadow = shadow_eval::<F>(&program, Overrides::none());
    let honest_anchors = shadow.anchors.clone();
    let advice_slots: Vec<usize> = shadow
        .advice
        .iter()
        .filter_map(|a| match a {
            AdviceSlot::Elem(i) => Some(*i),
            _ => None,
        })
        .collect();

    // Capture the honest constraint graph and per-slot wire ids.
    let mut rec = Recorder::<F>::new();
    let mut alloc = TrackingAllocator::default();
    let stacks = synthesize(&mut rec, &mut alloc, &program, &honest_anchors)
        .unwrap_or_else(|err| panic!("recorder rejected an honest generated program: {err:?}"));
    let slot_wires: Vec<usize> = stacks.elems.iter().map(|e| *e.wire()).collect();

    // The prover controls three kinds of advice: element-stack witnesses
    // (mutated directly), Fold scales (mutated and replayed through the
    // native shadow's `fold_scales`), and BoolAlloc booleans (corrupted to
    // non-`{0,1}`). A program with *any* of them has real advice — an
    // all-constant-preamble program that only allocates a boolean or a fold
    // scale still gets fuzzed, instead of being dropped for lack of element
    // advice.
    if advice_slots.is_empty()
        && stacks.fold_advice.is_empty()
        && stacks.bool_advice_wires.is_empty()
    {
        return;
    }

    // Completeness: the honest witness satisfies the captured constraints
    // and the native oracle agrees. Both hold by construction.
    assert!(
        constraints_hold(&rec.events, &rec.values),
        "honest witness violated a captured constraint (harness bug): {program:?}"
    );
    assert!(
        native_satisfied(&program, &honest_anchors, Overrides::none()),
        "honest native oracle disagreed with itself (harness bug): {program:?}"
    );

    // The wires the substrate knows it allocated: advice, the gate-D wires
    // pooled allocation handed out as advice, and allocation waste. These are
    // the genuine free wires of the honest graph.
    let allocations: Vec<usize> = stacks
        .advice_wires
        .iter()
        .copied()
        .chain(rec.extras.iter().copied())
        .chain(alloc.wasted.iter().flat_map(|&(b, c)| [b, c]))
        .collect();

    // Free-advice discovery cross-check, independent of any cheat: every
    // wire the captured graph leaves undetermined must be one of those
    // allocations. A free wire outside the list is a hint some gadget left
    // unpinned — and the list is ground truth the engine will not have for
    // the real circuits, so this also validates discovery itself. Skipped on
    // the genuine degeneracy — an honest `is_zero(0)`, whose inverse hint is
    // benignly free — exactly as the rank oracle below is.
    if !shadow.is_zero_degenerate {
        let discovered = discover_free_advice(&rec.events, &rec.values);
        let unexplained: Vec<usize> = discovered
            .iter()
            .copied()
            .filter(|w| !allocations.contains(w))
            .collect();
        assert!(
            unexplained.is_empty(),
            "DISCOVERY SIGNAL: the captured constraints leave wires {unexplained:?} \
             free, but the substrate allocated none of them — a gadget hint is \
             unpinned (or discovery is wrong). Program: {program:?}",
        );
    }

    // Rank/nullity oracle, independent of any cheat: with the genuine free
    // wires held fixed, every remaining wire must be locally pinned by the
    // captured constraints. Skipped only on the genuine degeneracy above —
    // not on every true boolean (a `BoolAlloc(true)`/`BoolNot` produces no
    // free hint) — and on outsized graphs.
    if rec.values.len() <= RANK_WIRE_CAP && !shadow.is_zero_degenerate {
        let movable = underconstrained_derived(&rec.events, &rec.values, &allocations);
        assert!(
            movable.is_empty(),
            "RANK ORACLE SIGNAL: derived wires {movable:?} can move while every \
             free wire is held fixed — an under-constrained wire, found \
             algebraically (no cheat, repair, or anchor needed). Program: {program:?}",
        );
    }

    // The honest value of each advice in its list order. Element honest
    // values come from the shadow; fold-scale honest values from the
    // recorder (the freshly-allocated scale wire).
    let elem_honest: Vec<F> = advice_slots.iter().map(|s| shadow.elems[*s]).collect();
    let fold_honest: Vec<F> = stacks
        .fold_advice
        .iter()
        .map(|(_, w)| rec.values[*w])
        .collect();

    // Default to one small cheat when the input names none, so every run does
    // work; it lands on whichever advice kind the program actually has.
    let no_cheats =
        input.cheats.is_empty() && input.fold_cheats.is_empty() && input.bool_cheats.is_empty();
    let default_cheat = [Cheat {
        advice: 0,
        mutation: Mutation::AddSmall(1),
    }];
    let default_bool = [0u16];
    let elem_cheats: &[Cheat] = if no_cheats && !elem_honest.is_empty() {
        &default_cheat
    } else {
        &input.cheats
    };
    let fold_cheats: &[Cheat] = if no_cheats && elem_honest.is_empty() && !fold_honest.is_empty() {
        &default_cheat
    } else {
        &input.fold_cheats
    };
    let bool_cheats: &[u16] = if no_cheats
        && elem_honest.is_empty()
        && fold_honest.is_empty()
        && !stacks.bool_advice_wires.is_empty()
    {
        &default_bool
    } else {
        &input.bool_cheats
    };

    // Resolve element and fold cheats into concrete new values (indexed into
    // each advice list).
    let elem_value = resolve_cheats::<F>(elem_cheats, &elem_honest);
    let fold_value = resolve_cheats::<F>(fold_cheats, &fold_honest);

    // ragu side, accomplice model: hold the cheated element advice, every
    // fold scale, and every boolean fixed; leave each *non-cheated*
    // element-advice wire solvable so the solver can pick accomplice values
    // that mask the cheat. Those are fed back to the native oracle below so
    // both sides judge the same commitment.
    let cheated_elem_wires: Vec<usize> = elem_value
        .iter()
        .map(|(k, _)| slot_wires[advice_slots[*k]])
        .collect();
    let accomplice_wires: Vec<usize> = advice_slots
        .iter()
        .map(|s| slot_wires[*s])
        .filter(|w| !cheated_elem_wires.contains(w))
        .collect();
    let fixed_free: Vec<usize> = stacks
        .advice_wires
        .iter()
        .copied()
        .filter(|w| !accomplice_wires.contains(w))
        .collect();

    let mut ragu_values = rec.values.clone();
    for (k, v) in &elem_value {
        ragu_values[slot_wires[advice_slots[*k]]] = *v;
    }
    for (k, v) in &fold_value {
        let (_, wire) = stacks.fold_advice[*k];
        ragu_values[wire] = *v;
    }

    // Boolean cheats: corrupt chosen boolean-advice wires to non-`{0,1}`
    // field values. Booleanity (`a·(1−a) = 0`) must reject them, so the run
    // becomes a must-reject check independent of the element anchors.
    let mut bool_cheated = false;
    for (i, raw) in bool_cheats.iter().enumerate() {
        if stacks.bool_advice_wires.is_empty() {
            break;
        }
        let wire = stacks.bool_advice_wires[*raw as usize % stacks.bool_advice_wires.len()];
        // 2, 3, 4, … — never 0 or 1, so always a booleanity violation.
        ragu_values[wire] = F::from(i as u64 + 2);
        bool_cheated = true;
    }

    repair(&rec.events, &mut ragu_values, &fixed_free);
    let ragu_accepts = constraints_hold(&rec.events, &ragu_values);

    // Playback cross-check: re-derive the verdict from a fresh synthesis of
    // the *real* gadget calls over the repaired witness, with an independent
    // linear-combination evaluator. If the recorder's stored-event verdict
    // and this live re-execution disagree, the recorder mis-captured the
    // circuit and every signal above is suspect. A plain `Standard` replays
    // exactly the gate / `assign_extra` sequence `TrackingAllocator` made,
    // so wire ids line up with the recorder's.
    let mut playback = Playback::new(ragu_values.clone());
    synthesize(
        &mut playback,
        &mut Standard::new(),
        &program,
        &honest_anchors,
    )
    .unwrap_or_else(|err| panic!("playback diverged from honest circuit shape: {err:?}"));
    assert_eq!(
        playback.accepts(),
        ragu_accepts,
        "RECORDER CAPTURE BUG: the stored constraint graph accepts={ragu_accepts} but a \
         fresh playback of the real gadget synthesis says accepts={}. The recorder \
         mis-captured the circuit. Program: {program:?}",
        playback.accepts(),
    );

    if bool_cheated {
        assert!(
            !ragu_accepts,
            "PATCHER BOOLEANITY SIGNAL: a boolean-advice wire was set to a \
             non-{{0,1}} value, yet ragu ACCEPTED the witness — the \
             booleanity constraints are under-constrained (the soundness \
             direction). Program: {program:?}",
        );
        return;
    }

    // native side: judge the exact commitment ragu accepted — the cheats
    // *and* the accomplice advice the solver chose. Each element-advice slot
    // and each fold scale is overridden to its post-repair value; derived
    // wires the shadow recomputes itself from true semantics. Routing fold
    // scales through `fold_scales` is what lets a cheated fold scale be
    // observed (rather than silently held fixed).
    let elem_overrides: Vec<(usize, F)> = advice_slots
        .iter()
        .map(|s| (*s, ragu_values[slot_wires[*s]]))
        .collect();
    let fold_overrides: Vec<(usize, F)> = stacks
        .fold_advice
        .iter()
        .map(|(op_idx, w)| (*op_idx, ragu_values[*w]))
        .collect();
    let mutated = shadow_eval::<F>(
        &program,
        Overrides {
            elems: &elem_overrides,
            fold_scales: &fold_overrides,
            ..Overrides::none()
        },
    );

    // Zero-crossing classification. Compare the per-op execution trace, not
    // only final stack lengths: one newly-executed op and one newly-skipped
    // op can cancel in length while the captured circuit shapes still differ.
    //
    //  * an op was newly skipped — an `invert`/`divide` whose input the cheat
    //    zeroed now skips natively. The honest captured graph still contains
    //    that gadget's nonzero enforcement (`x · x⁻¹ = 1`), which is
    //    unsatisfiable at `x = 0`, so ragu *must* reject. Accepting it means
    //    the nonzero check is under-constrained — a soundness bug. This is
    //    the formerly-bailed case turned into a real oracle.
    //  * an op was newly executed — an `invert`/`divide` the honest run skipped
    //    (input honestly zero) now executes. The honest graph never captured
    //    that gadget, so there is nothing to compare against; still out of
    //    model, so bail.
    //  * only the boolean stack changed — an `is_zero` result flipped. The
    //    patcher vocabulary excludes `ConditionalSelect`, so a flipped
    //    boolean cannot move any anchored element, and `repair` re-derives the
    //    `is_zero` hint witness (`prod = x·inv`, the result bit, the inverse)
    //    from the input. The element-anchor comparison therefore stays valid
    //    — no bail.
    //
    //    That re-derivation is not free: the hint gates have the input on one
    //    side and a hint on the other, so while the input is still unknown
    //    neither gate is linear and the cluster pass cannot see the coupling
    //    at all. It holds only because `cluster_solve` commits forced wires
    //    before guessed ones, which lets the input be deduced first and the
    //    hints fall out by propagation. Weakening that ordering resurfaces as
    //    spurious rejections here, not as a solver error — see the
    //    least-commitment section on `patcher::recorder::cluster_solve` and the
    //    `regressions/fuzz_advice_patcher/` reproducers.
    assert_eq!(
        shadow.value_fallible_pushes.len(),
        mutated.value_fallible_pushes.len(),
    );
    let grew = shadow
        .value_fallible_pushes
        .iter()
        .zip(&mutated.value_fallible_pushes)
        .any(|(&honest, &changed)| !honest && changed);
    let shrank = shadow
        .value_fallible_pushes
        .iter()
        .zip(&mutated.value_fallible_pushes)
        .any(|(&honest, &changed)| honest && !changed);
    let bools_flipped = mutated.bools != shadow.bools;
    let native_ok = mutated.anchors == honest_anchors;

    if std::env::var("PATCHER_STATS").is_ok() {
        let runs = RUNS.fetch_add(1, Ordering::Relaxed) + 1;
        if grew {
            GREW.fetch_add(1, Ordering::Relaxed);
        }
        if shrank {
            SHRANK.fetch_add(1, Ordering::Relaxed);
        }
        if bools_flipped && !shrank && !grew {
            BOOL_FLIP.fetch_add(1, Ordering::Relaxed);
        }
        if grew || (ragu_accepts && native_ok) {
            VACUOUS.fetch_add(1, Ordering::Relaxed);
        }
        if runs % (1 << 14) == 0 {
            eprintln!(
                "[advice_patcher] runs {runs}: vacuous {}, grew(bail) {}, \
                 shrank(reject-check) {}, bool-flip {}",
                VACUOUS.load(Ordering::Relaxed),
                GREW.load(Ordering::Relaxed),
                SHRANK.load(Ordering::Relaxed),
                BOOL_FLIP.load(Ordering::Relaxed),
            );
        }
    }

    if grew {
        return;
    }
    if shrank {
        assert!(
            !ragu_accepts,
            "PATCHER ZERO-DIVISOR SIGNAL: cheating advice (elem {elem_value:?}, \
             fold {fold_value:?}) drove an invert/divide input to zero, yet ragu \
             ACCEPTED the repaired witness — the gadget's nonzero enforcement \
             is under-constrained (the soundness direction). Program: {program:?}",
        );
        return;
    }

    assert!(
        !(ragu_accepts && !native_ok),
        "PATCHER SOUNDNESS SIGNAL: cheating advice (elem {elem_value:?}, fold \
         {fold_value:?}) and repairing through the captured constraints, ragu ACCEPTED \
         the witness but the native oracle says it is VIOLATED. Program: {program:?}",
    );
}

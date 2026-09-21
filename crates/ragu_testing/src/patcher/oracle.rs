//! The pinned-input soundness oracle: same inputs must give same outputs.
//!
//! The cheat differential in `fuzz_advice_patcher` needs a native shadow
//! that knows each gadget's true semantics — a spec the generated programs
//! carry with them. A real circuit brings no shadow, but once it has
//! declared inputs and outputs it carries one specification for free:
//! **the outputs must be a function of the inputs**. Pin the inputs at
//! their honest values, let a malicious prover wiggle the remaining free
//! advice, [`repair`] the rest of the witness through the captured
//! constraints — and if every constraint still holds while an output moved,
//! the circuit accepts two witnesses that agree on the inputs and disagree
//! on an output. That is a determinism violation, and the returned witness
//! is the evidence.
//!
//! # Declaring the inputs is the caller's spec
//!
//! `inputs` must list every free wire the outputs are *allowed* to depend
//! on — public inputs and genuine private witness alike (for
//! `MySimpleCircuit`, the private `a` and `b`; for a recursion circuit, the
//! received instance slots). What remains cheatable is exactly the freedom
//! the circuit's constraints are supposed to neutralize: hints, allocator
//! waste, anything [`discover_free_advice`] reports beyond the declared
//! set. An under-declared input set produces false positives (an output
//! legitimately follows the forgotten input); an over-declared one wastes
//! probes but never manufactures a violation.
//!
//! # Verdict semantics
//!
//! * A **violation is sound by construction**: honest capture and returned
//!   witness both satisfy every captured constraint (checked by
//!   [`constraints_hold`], re-checkable independently via
//!   [`playback`](super::playback)), agree on every pinned input, and
//!   differ on a watched output. No solver heuristic can fabricate one.
//! * A **rejection is inconclusive**, never a signal: the bounded solver
//!   may simply have missed a satisfying repair. Completeness has its own
//!   oracles.
//! * **No violation is not a proof of soundness**: [`determinism_sweep`]
//!   nudges each cheatable wire with two values; a bug reachable only
//!   through a specific value or a coordinated multi-wire cheat needs a
//!   richer harness on top of [`determinism_probe`] (the fuzz target's
//!   mutation vocabulary is the model).

use ragu_arithmetic::ff::{Field, PrimeFieldBits};

use super::{
    discover::discover_free_advice,
    recorder::{
        Event, JacobianDirection, Recorder, constraints_hold, constraints_hold_over,
        deduce_by_cases, repair, repair_over,
    },
};

/// The outcome of one [`determinism_probe`].
#[derive(Debug)]
pub enum ProbeOutcome<F> {
    /// The repaired witness violates a captured constraint. Inconclusive:
    /// the bounded solver may have missed a satisfying repair, so this is
    /// never treated as a signal in either direction.
    Rejected,
    /// Every captured constraint holds and every watched output kept its
    /// honest value — the cheat was neutralized (or absorbed by freedom no
    /// output depends on).
    OutputsPinned,
    /// Every captured constraint holds and at least one watched output
    /// moved: a determinism violation, with the accepting witness as
    /// evidence.
    OutputsMoved {
        /// The full repaired witness ragu accepts, indexed by wire.
        witness: Vec<F>,
        /// Each moved output as `(wire, honest value, repaired value)`.
        moved: Vec<(usize, F, F)>,
    },
}

/// A determinism violation found by [`determinism_sweep`].
#[derive(Debug)]
pub struct Violation<F> {
    /// The cheated free-advice wire.
    pub advice: usize,
    /// The value the cheat committed it to.
    pub value: F,
    /// The full accepting witness, indexed by wire.
    pub witness: Vec<F>,
    /// Each moved output as `(wire, honest value, repaired value)`.
    pub moved: Vec<(usize, F, F)>,
}

/// What a [`determinism_sweep`] found — and how much it actually exercised.
///
/// The counters classify every cheatable wire that did *not* violate:
/// without them, "no violations" cannot be told apart from a sweep whose
/// every probe was rejected by the bounded solver and so tested nothing.
/// A report with `violations` empty and `pinned == 0` while `rejected > 0`
/// is **vacuous**, not clean.
#[derive(Debug)]
pub struct SweepReport<F> {
    /// The determinism violations, one per violating wire.
    pub violations: Vec<Violation<F>>,
    /// Wires where at least one probe was accepted with every output at
    /// its honest value — cheats the constraints genuinely neutralized.
    pub pinned: usize,
    /// Wires where every probe was rejected — the bounded solver found no
    /// satisfying repair, so nothing about them was demonstrated.
    pub rejected: usize,
}

/// One probe of the pinned-input oracle: pin `inputs` at their honest
/// values, commit each `(wire, value)` in `cheats`, [`repair`] everything
/// else through `events`, and judge `outputs`.
///
/// Non-cheated free advice outside `inputs` is left solvable, so the
/// repair may recruit accomplices — the strongest prover the engine can
/// model. `honest` must be a satisfying witness of `events` (the honest
/// capture). A cheat listed on an input wire would probe a different
/// statement, not a determinism violation; don't do that (callers sweep
/// the complement of `inputs`).
pub fn determinism_probe<F: Field>(
    events: &[Event<F>],
    honest: &[F],
    inputs: &[usize],
    outputs: &[usize],
    cheats: &[(usize, F)],
) -> ProbeOutcome<F> {
    let mut values = honest.to_vec();
    let mut fixed = inputs.to_vec();
    for &(wire, value) in cheats {
        debug_assert!(!inputs.contains(&wire), "cheating a pinned input");
        values[wire] = value;
        fixed.push(wire);
    }

    repair(events, &mut values, &fixed);
    if !constraints_hold(events, &values) {
        return ProbeOutcome::Rejected;
    }

    let moved: Vec<(usize, F, F)> = outputs
        .iter()
        .copied()
        .filter(|&o| values[o] != honest[o])
        .map(|o| (o, honest[o], values[o]))
        .collect();
    if moved.is_empty() {
        ProbeOutcome::OutputsPinned
    } else {
        ProbeOutcome::OutputsMoved {
            witness: values,
            moved,
        }
    }
}

/// Repairs one Jacobian-kernel direction into an exact witness, if possible.
///
/// The tangent proposal starts at `honest + step · direction`. Wires in
/// `frozen` retain their honest values (the public inputs and causal
/// commitment frontier), while the proposed values of `committed` wires are
/// held fixed. Every other wire is available to [`repair`] for nonlinear
/// correction. The candidate is returned only after exact evaluation of all
/// `events`; a tangent direction that cannot be repaired returns `None`.
/// Callers with a live circuit should pass the returned witness to
/// [`playback`](super::playback) before treating it as evidence.
///
/// # Panics
///
/// Panics when a frozen wire occurs in the direction, a committed wire does
/// not occur in it, or either list references an invalid wire.
pub fn jacobian_witness<F: Field>(
    events: &[Event<F>],
    honest: &[F],
    frozen: &[usize],
    direction: &JacobianDirection<F>,
    step: F,
    committed: &[usize],
) -> Option<Vec<F>> {
    let mut values = honest.to_vec();
    let mut proposed = vec![false; honest.len()];
    for &(wire, delta) in direction.entries() {
        assert!(
            wire < honest.len(),
            "direction wire {wire} is outside the witness"
        );
        assert!(
            !frozen.contains(&wire),
            "direction moves frozen frontier wire {wire}",
        );
        values[wire] += delta * step;
        proposed[wire] = true;
    }

    let mut fixed = frozen.to_vec();
    for &wire in committed {
        assert!(
            wire < honest.len(),
            "committed wire {wire} is outside the witness"
        );
        assert!(
            proposed[wire],
            "committed wire {wire} is absent from the direction"
        );
        if !fixed.contains(&wire) {
            fixed.push(wire);
        }
    }
    repair(events, &mut values, &fixed);
    constraints_hold(events, &values).then_some(values)
}

/// Turns one Jacobian-kernel direction into an exact witness probe.
///
/// This classifies the exact candidate from [`jacobian_witness`] against
/// `outputs` using the same verdicts as [`determinism_probe`]. A tangent
/// direction that cannot be repaired is [`ProbeOutcome::Rejected`], never an
/// exploit.
///
/// `outputs` are watched against the honest witness using the same verdicts
/// as [`determinism_probe`]. Callers should additionally replay an accepted
/// witness through the live circuit driver when one is available.
///
/// # Panics
///
/// Panics when a frozen wire occurs in the direction, a committed wire does
/// not occur in it, or either list references an invalid wire.
pub fn jacobian_probe<F: Field>(
    events: &[Event<F>],
    honest: &[F],
    frozen: &[usize],
    outputs: &[usize],
    direction: &JacobianDirection<F>,
    step: F,
    committed: &[usize],
) -> ProbeOutcome<F> {
    let Some(values) = jacobian_witness(events, honest, frozen, direction, step, committed) else {
        return ProbeOutcome::Rejected;
    };

    let moved = outputs
        .iter()
        .copied()
        .filter(|&wire| values[wire] != honest[wire])
        .map(|wire| (wire, honest[wire], values[wire]))
        .collect::<Vec<_>>();
    if moved.is_empty() {
        ProbeOutcome::OutputsPinned
    } else {
        ProbeOutcome::OutputsMoved {
            witness: values,
            moved,
        }
    }
}

/// A circuit prepared for many probes of the pinned-input oracle.
///
/// [`determinism_probe`] re-derives the whole witness from the inputs on
/// every call. Most of that work never changes: a wire the inputs alone
/// force (see [`forced_by`](super::forced_by)) takes the same value in every
/// witness that agrees with the honest one on the inputs — the solver's
/// deductions are unique consequences, so a cheat that disagrees with such a
/// wire shows up as a violated constraint, never as a different value. The
/// preparation therefore solves that part once, from the honest capture. A
/// probe then starts from `known = inputs ∪ forced ∪ cheats` and solves only
/// the *residual* wires — hints the inputs do not determine, and whatever
/// reads them — over only the events that mention a residual or cheated
/// wire. Every other event sees nothing but honest values and holds, so the
/// acceptance check is exact over that subset too.
///
/// The verdict is [`determinism_probe`]'s, with one difference in the
/// prover's favour: with far fewer unknowns the linear-cluster solver is
/// within its cap more often, so a probe the full repair would have left
/// `Rejected` can come back conclusive. Rejections are never signals, so
/// this only adds coverage, and the evidence of a violation is still a
/// complete witness that [`constraints_hold`] accepts.
pub struct Prepared<F> {
    events: Vec<Event<F>>,
    honest: Vec<F>,
    inputs: Vec<usize>,
    outputs: Vec<usize>,
    /// Known before any cheat: the ONE wire, the inputs, and what they force.
    base_known: Vec<bool>,
    /// The events that mention a wire outside `base_known`, ascending.
    residual: Vec<usize>,
    /// Whether each event is in `residual`.
    is_residual: Vec<bool>,
    /// For each wire, the events that mention it.
    events_of: Vec<Vec<usize>>,
}

impl<F: PrimeFieldBits> Prepared<F> {
    /// Prepares `events` at the satisfying witness `honest` for probes that
    /// pin `inputs` and watch `outputs`.
    pub fn new(
        events: Vec<Event<F>>,
        honest: Vec<F>,
        inputs: Vec<usize>,
        outputs: Vec<usize>,
    ) -> Self {
        debug_assert!(
            constraints_hold(&events, &honest),
            "the pinned-input oracle needs an honest, satisfying capture",
        );
        let n = honest.len();
        let mut base_known = vec![false; n];
        base_known[Recorder::<F>::ONE] = true;
        for &w in &inputs {
            base_known[w] = true;
        }
        let mut forced = honest.clone();
        deduce_by_cases(&events, &mut forced, &mut base_known);
        debug_assert!(
            forced == honest,
            "what the inputs force is the honest value at a satisfying witness",
        );

        let mut events_of = vec![Vec::new(); n];
        let mut residual = Vec::new();
        let mut is_residual = vec![false; events.len()];
        for (i, ev) in events.iter().enumerate() {
            let mut touches_residual = false;
            for w in wires_of(ev) {
                events_of[w].push(i);
                touches_residual |= !base_known[w];
            }
            if touches_residual {
                residual.push(i);
                is_residual[i] = true;
            }
        }

        Prepared {
            events,
            honest,
            inputs,
            outputs,
            base_known,
            residual,
            is_residual,
            events_of,
        }
    }

    /// The honest witness, indexed by wire.
    pub fn honest(&self) -> &[F] {
        &self.honest
    }

    /// The pinned inputs.
    pub fn inputs(&self) -> &[usize] {
        &self.inputs
    }

    /// The watched outputs.
    pub fn outputs(&self) -> &[usize] {
        &self.outputs
    }

    /// How many events a probe solves and checks, out of how many the
    /// capture has.
    pub fn residual_events(&self) -> (usize, usize) {
        (self.residual.len(), self.events.len())
    }

    /// [`determinism_sweep`] through this prepared capture: every cheatable
    /// wire nudged, one at a time, at a fraction of the cost.
    pub fn sweep(&self) -> SweepReport<F> {
        sweep_with(&self.events, &self.honest, &self.inputs, |cheats| {
            self.probe(cheats)
        })
    }

    /// One probe: [`determinism_probe`] from the prepared state.
    pub fn probe(&self, cheats: &[(usize, F)]) -> ProbeOutcome<F> {
        let mut values = self.honest.clone();
        let mut known = self.base_known.clone();
        // A cheat on a wire the inputs force is allowed — it asks whether a
        // different value passes — but the events that would contradict it
        // lie outside the residual, so they are pulled in.
        let mut extra: Vec<usize> = Vec::new();
        for &(wire, value) in cheats {
            debug_assert!(!self.inputs.contains(&wire), "cheating a pinned input");
            values[wire] = value;
            known[wire] = true;
            for &e in &self.events_of[wire] {
                if !self.is_residual[e] && !extra.contains(&e) {
                    extra.push(e);
                }
            }
        }
        let active = || {
            self.residual
                .iter()
                .chain(extra.iter())
                .map(|&i| &self.events[i])
        };

        repair_over(active(), &mut values, &mut known);
        if !constraints_hold_over(active(), &values) {
            return ProbeOutcome::Rejected;
        }

        let moved: Vec<(usize, F, F)> = self
            .outputs
            .iter()
            .copied()
            .filter(|&o| values[o] != self.honest[o])
            .map(|o| (o, self.honest[o], values[o]))
            .collect();
        if moved.is_empty() {
            ProbeOutcome::OutputsPinned
        } else {
            ProbeOutcome::OutputsMoved {
                witness: values,
                moved,
            }
        }
    }
}

/// The wires an event mentions.
fn wires_of<F>(ev: &Event<F>) -> Vec<usize> {
    match ev {
        Event::Lin { out, terms } => core::iter::once(*out)
            .chain(terms.iter().map(|(w, _)| *w))
            .collect(),
        Event::Gate { a, b, c } => vec![*a, *b, *c],
        Event::Enforce { terms } => terms.iter().map(|(w, _)| *w).collect(),
        Event::Extra { c, d } => vec![*c, *d],
    }
}

/// Sweeps the pinned-input oracle over every cheatable wire: each wire
/// [`discover_free_advice`] reports outside `inputs` is nudged to
/// `honest + 1` and (when distinct from both) to `0`, one wire at a time.
/// At most one violation is collected per wire; non-violating wires are
/// tallied in the report as pinned or rejected, so a vacuous sweep is
/// visible as such.
///
/// A cheap smoke sweep, not an exhaustive search: single-wire cheats and
/// two nudge values (see the module docs on verdict semantics). Richer
/// cheat vocabularies and coordinated multi-wire cheats belong to the
/// harness, built on [`determinism_probe`] directly.
pub fn determinism_sweep<F: Field>(
    events: &[Event<F>],
    honest: &[F],
    inputs: &[usize],
    outputs: &[usize],
) -> SweepReport<F> {
    // Checked once here rather than per probe: `honest` is the same witness
    // throughout the sweep, and `constraints_hold` is O(wires × events).
    debug_assert!(
        constraints_hold(events, honest),
        "the pinned-input oracle needs an honest, satisfying capture",
    );
    sweep_with(events, honest, inputs, |cheats| {
        determinism_probe(events, honest, inputs, outputs, cheats)
    })
}

/// The sweep's loop over any probe: [`determinism_sweep`]'s policy of which
/// wires to nudge and to what, tallied into a [`SweepReport`].
fn sweep_with<F: Field>(
    events: &[Event<F>],
    honest: &[F],
    inputs: &[usize],
    probe: impl Fn(&[(usize, F)]) -> ProbeOutcome<F>,
) -> SweepReport<F> {
    let mut report = SweepReport {
        violations: Vec::new(),
        pinned: 0,
        rejected: 0,
    };
    for wire in discover_free_advice(events, honest) {
        if inputs.contains(&wire) {
            continue;
        }
        let nudged = honest[wire] + F::ONE;
        let mut tries = vec![nudged];
        if honest[wire] != F::ZERO && nudged != F::ZERO {
            tries.push(F::ZERO);
        }
        let mut violation = None;
        let mut any_pinned = false;
        for value in tries {
            match probe(&[(wire, value)]) {
                ProbeOutcome::OutputsMoved { witness, moved } => {
                    violation = Some(Violation {
                        advice: wire,
                        value,
                        witness,
                        moved,
                    });
                    break;
                }
                ProbeOutcome::OutputsPinned => any_pinned = true,
                ProbeOutcome::Rejected => {}
            }
        }
        match violation {
            Some(violation) => report.violations.push(violation),
            None if any_pinned => report.pinned += 1,
            None => report.rejected += 1,
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use ragu_arithmetic::Coeff;
    use ragu_core::drivers::{Driver, LinearExpression};
    use ragu_pasta::Fp;

    use super::{
        super::recorder::{Recorder, jacobian_kernel},
        *,
    };

    /// The planted under-constrained square, judged by the pinned-input
    /// oracle instead of an anchor: `root` is the declared input, `square`
    /// the output, and the missing `square = root²` gate means the prover
    /// can move the output with the input pinned. Adding the gate derives
    /// `square`, so nothing cheatable remains — the report shows that
    /// honestly (no probes at all), rather than passing off a vacuous
    /// sweep as a neutralized one.
    #[test]
    fn sweep_finds_missing_square_gate() {
        let root_honest = Fp::from(7u64);

        // Buggy: `square` is free advice, no gate ties it to `root`.
        let mut rec = Recorder::<Fp>::new();
        let root = rec.push_wire(root_honest);
        let square = rec.push_wire(root_honest.square());

        let report = determinism_sweep(&rec.events, &rec.values, &[root], &[square]);
        assert_eq!(
            report.violations.len(),
            1,
            "exactly the square hint violates"
        );
        assert_eq!(report.violations[0].advice, square);
        assert_eq!(
            report.violations[0].moved,
            vec![(square, root_honest.square(), root_honest.square() + Fp::ONE,)]
        );
        assert!(constraints_hold(&rec.events, &report.violations[0].witness));

        // Fixed: emit the gate as `Element::square` would (operands copy-
        // constrained to `root`, output to `square`).
        let (a, b, c) = rec
            .mul(|| {
                Ok((
                    Coeff::Arbitrary(root_honest),
                    Coeff::Arbitrary(root_honest),
                    Coeff::Arbitrary(root_honest.square()),
                ))
            })
            .unwrap();
        rec.enforce_equal(&a, &root).unwrap();
        rec.enforce_equal(&b, &root).unwrap();
        rec.enforce_equal(&c, &square).unwrap();
        assert!(constraints_hold(&rec.events, &rec.values));
        let report = determinism_sweep(&rec.events, &rec.values, &[root], &[square]);
        assert!(report.violations.is_empty());
        assert_eq!(
            (report.pinned, report.rejected),
            (0, 0),
            "with the gate emitted, `square` is derived: nothing cheatable remains",
        );
    }

    /// Outputs may follow declared inputs: probing is only ever done on
    /// the complement, so a circuit whose output is a direct function of
    /// its two inputs sweeps clean — while forgetting to declare one input
    /// produces the documented false positive.
    #[test]
    fn declared_inputs_are_the_spec() {
        let mut rec = Recorder::<Fp>::new();
        let p = rec.push_wire(Fp::from(3u64));
        let q = rec.push_wire(Fp::from(4u64));
        let sum = rec.add(|lc| lc.add(&p).add(&q));

        assert!(
            determinism_sweep(&rec.events, &rec.values, &[p, q], &[sum])
                .violations
                .is_empty()
        );

        // Under-declaring: with only `p` pinned, `q` is (correctly, per the
        // caller's spec) reported as freedom that moves the output.
        let report = determinism_sweep(&rec.events, &rec.values, &[p], &[sum]);
        assert_eq!(report.violations.len(), 1);
        assert_eq!(report.violations[0].advice, q);
    }

    /// Accomplice-neutralized cheats are not violations: two hints pinned
    /// only by their sum feeding the output can shift jointly, but the
    /// output — which reads the *sum* — cannot move, and a cheat on either
    /// hint is repaired by the other absorbing it.
    #[test]
    fn accomplice_absorbed_cheat_is_pinned() {
        let mut rec = Recorder::<Fp>::new();
        let input = rec.push_wire(Fp::from(9u64));
        let h1 = rec.push_wire(Fp::from(2u64));
        let h2 = rec.push_wire(Fp::from(7u64));
        // h1 + h2 = input, and the output reads input − (h1 + h2) + input.
        let sum = rec.add(|lc| lc.add(&h1).add(&h2));
        rec.enforce_zero(|lc| lc.add(&sum).add_term(&input, Coeff::NegativeOne))
            .unwrap();
        let output = rec.add(|lc| {
            lc.add(&input)
                .add(&input)
                .add_term(&sum, Coeff::NegativeOne)
        });
        assert!(constraints_hold(&rec.events, &rec.values));

        let report = determinism_sweep(&rec.events, &rec.values, &[input], &[output]);
        assert!(
            report.violations.is_empty(),
            "cheating h1 forces h2 to compensate; the output cannot move: {:?}",
            report.violations,
        );
        assert_eq!(
            (report.pinned, report.rejected),
            (1, 0),
            "the hint cheat was genuinely exercised and neutralized, not rejected",
        );
    }

    /// The oracle at the rank oracle's blind spot: an honest `is_zero(0)`
    /// leaves the inverse hint genuinely free (the rank oracle must skip
    /// the whole graph there), yet the result bit is still forced — with
    /// `x = 0` pinned, `x · inv = 1 − bit` reads `bit = 1` no matter what
    /// the hint says. The sweep exercises both the hint and the allocation
    /// waste, neutralizes both, and reports no false positive.
    #[test]
    fn is_zero_degenerate_hint_is_not_a_false_positive() -> ragu_core::Result<()> {
        use ragu_primitives::Element;

        use super::super::TrackingAllocator;

        let mut rec = Recorder::<Fp>::new();
        let mut alloc = TrackingAllocator::default();
        let x = Element::alloc(&mut rec, &mut alloc, Recorder::<Fp>::just(|| Fp::ZERO))?;
        let bit = x.is_zero(&mut rec, &mut alloc)?;
        assert!(constraints_hold(&rec.events, &rec.values));
        assert_eq!(rec.values[*bit.wire()], Fp::ONE);

        let report = determinism_sweep(&rec.events, &rec.values, &[*x.wire()], &[*bit.wire()]);
        assert!(report.violations.is_empty(), "{:?}", report.violations);
        assert_eq!(
            (report.pinned, report.rejected),
            (2, 0),
            "the inverse hint and the allocation waste were both exercised \
             and neutralized",
        );
        Ok(())
    }

    /// The prepared probe gives the full probe's verdict: the planted square
    /// moves, an accomplice-absorbed cheat is pinned, and a cheat on a wire
    /// the inputs force is rejected — while solving only the events that can
    /// change.
    #[test]
    fn prepared_probe_matches_full_probe() {
        // Planted bug: `square` is free, so cheating it moves the output.
        let root_honest = Fp::from(7u64);
        let mut rec = Recorder::<Fp>::new();
        let root = rec.push_wire(root_honest);
        let square = rec.push_wire(root_honest.square());
        let prepared = Prepared::new(
            rec.events.clone(),
            rec.values.clone(),
            vec![root],
            vec![square],
        );
        let cheat = [(square, root_honest.square() + Fp::ONE)];
        match (
            determinism_probe(&rec.events, &rec.values, &[root], &[square], &cheat),
            prepared.probe(&cheat),
        ) {
            (
                ProbeOutcome::OutputsMoved { moved: full, .. },
                ProbeOutcome::OutputsMoved { moved: fast, .. },
            ) => assert_eq!(full, fast),
            other => panic!("both must report the move: {other:?}"),
        }

        // Accomplices: h1 + h2 = input, output reads input − (h1 + h2) + input.
        let mut rec = Recorder::<Fp>::new();
        let input = rec.push_wire(Fp::from(9u64));
        let h1 = rec.push_wire(Fp::from(2u64));
        let h2 = rec.push_wire(Fp::from(7u64));
        let sum = rec.add(|lc| lc.add(&h1).add(&h2));
        rec.enforce_zero(|lc| lc.add(&sum).add_term(&input, Coeff::NegativeOne))
            .unwrap();
        let output = rec.add(|lc| {
            lc.add(&input)
                .add(&input)
                .add_term(&sum, Coeff::NegativeOne)
        });
        let prepared = Prepared::new(
            rec.events.clone(),
            rec.values.clone(),
            vec![input],
            vec![output],
        );
        // `sum` and `output` are forced by `input`; only the hints' sum
        // definition is residual.
        assert_eq!(prepared.residual_events(), (1, 3));
        let cheat = [(h1, Fp::from(3u64))];
        assert!(matches!(
            determinism_probe(&rec.events, &rec.values, &[input], &[output], &cheat),
            ProbeOutcome::OutputsPinned
        ));
        assert!(matches!(
            prepared.probe(&cheat),
            ProbeOutcome::OutputsPinned
        ));

        // A cheat on the forced `sum` pulls its events back in and is
        // rejected by the enforce, in both.
        let cheat = [(sum, Fp::from(99u64))];
        assert!(matches!(
            determinism_probe(&rec.events, &rec.values, &[input], &[output], &cheat),
            ProbeOutcome::Rejected
        ));
        assert!(matches!(prepared.probe(&cheat), ProbeOutcome::Rejected));
    }

    /// A tangent direction coordinates two advice wires so their committed
    /// sum stays fixed. Its linearized product is deliberately wrong at a
    /// finite step; exact repair must recompute the nonlinear product before
    /// the changed output can count as evidence.
    #[test]
    fn jacobian_direction_gets_nonlinear_exact_repair() {
        let mut rec = Recorder::<Fp>::new();
        let x = rec.push_wire(Fp::from(2));
        let y = rec.push_wire(Fp::from(3));
        let product = rec.push_wire(Fp::from(6));
        let sum = rec.add(|lc| lc.add(&x).add(&y));
        let expected_sum = rec.push_wire(Fp::from(5));
        rec.events.push(Event::Gate {
            a: x,
            b: y,
            c: product,
        });
        rec.enforce_zero(|lc| lc.add(&sum).sub(&expected_sum))
            .unwrap();
        assert!(constraints_hold(&rec.events, &rec.values));

        let basis = jacobian_kernel(&rec.events, &rec.values, &[x, y, product]);
        assert_eq!(basis.len(), 1);
        let direction = &basis[0];
        assert_eq!(
            direction.entries(),
            &[(x, Fp::ONE), (y, -Fp::ONE), (product, Fp::ONE)],
        );

        // At step two the tangent says (x, y, product) = (4, 1, 8), but
        // the exact product is 4. A tangent-only verdict would be unsound.
        let mut tangent = rec.values.clone();
        for &(wire, delta) in direction.entries() {
            tangent[wire] += delta.double();
        }
        assert_eq!(
            (tangent[x], tangent[y], tangent[product]),
            (Fp::from(4), Fp::ONE, Fp::from(8))
        );
        assert!(!constraints_hold(&rec.events, &tangent));

        match jacobian_probe(
            &rec.events,
            &rec.values,
            &[expected_sum],
            &[product],
            direction,
            Fp::from(2),
            &[x, y],
        ) {
            ProbeOutcome::OutputsMoved { witness, moved } => {
                assert_eq!(
                    (witness[x], witness[y], witness[product]),
                    (Fp::from(4), Fp::ONE, Fp::from(4))
                );
                assert_eq!(witness[sum], rec.values[sum]);
                assert_eq!(witness[expected_sum], rec.values[expected_sum]);
                assert_eq!(moved, vec![(product, Fp::from(6), Fp::from(4))]);
                assert!(constraints_hold(&rec.events, &witness));
            }
            other => panic!("exact nonlinear repair must find the coordinated witness: {other:?}"),
        }
    }

    /// The mandatory singular negative control: `x² = 0` has a zero
    /// derivative at zero, so the Jacobian proposes moving x, but exact
    /// finite-field evaluation rejects every nonzero step used here.
    #[test]
    fn singular_square_tangent_is_not_an_exploit() {
        let mut rec = Recorder::<Fp>::new();
        let x = rec.push_wire(Fp::ZERO);
        let square = rec.push_wire(Fp::ZERO);
        rec.events.push(Event::Gate {
            a: x,
            b: x,
            c: square,
        });
        rec.enforce_zero(|lc| lc.add(&square)).unwrap();
        assert!(constraints_hold(&rec.events, &rec.values));

        let basis = jacobian_kernel(&rec.events, &rec.values, &[x, square]);
        assert_eq!(basis.len(), 1);
        assert_eq!(basis[0].entries(), &[(x, Fp::ONE)]);
        assert!(matches!(
            jacobian_probe(
                &rec.events,
                &rec.values,
                &[],
                &[x],
                &basis[0],
                Fp::ONE,
                &[x],
            ),
            ProbeOutcome::Rejected,
        ));
    }
}

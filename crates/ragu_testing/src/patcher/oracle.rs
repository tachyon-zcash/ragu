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

use ragu_arithmetic::ff::Field;

use super::{
    discover::discover_free_advice,
    recorder::{Event, constraints_hold, repair},
};

/// The outcome of one [`determinism_probe`].
#[derive(Clone, Debug)]
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
#[derive(Clone, Debug)]
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
    debug_assert!(
        constraints_hold(events, honest),
        "the pinned-input oracle needs an honest, satisfying capture",
    );

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

/// Sweeps the pinned-input oracle over every cheatable wire: each wire
/// [`discover_free_advice`] reports outside `inputs` is nudged to
/// `honest + 1` and (when distinct from both) to `0`, one wire at a time,
/// and every resulting determinism violation is collected — at most one
/// per wire.
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
) -> Vec<Violation<F>> {
    let mut violations = Vec::new();
    for wire in discover_free_advice(events, honest) {
        if inputs.contains(&wire) {
            continue;
        }
        let nudged = honest[wire] + F::ONE;
        let mut tries = vec![nudged];
        if honest[wire] != F::ZERO && nudged != F::ZERO {
            tries.push(F::ZERO);
        }
        for value in tries {
            if let ProbeOutcome::OutputsMoved { witness, moved } =
                determinism_probe(events, honest, inputs, outputs, &[(wire, value)])
            {
                violations.push(Violation {
                    advice: wire,
                    value,
                    witness,
                    moved,
                });
                break;
            }
        }
    }
    violations
}

#[cfg(test)]
mod tests {
    use ragu_arithmetic::Coeff;
    use ragu_core::drivers::{Driver, LinearExpression};
    use ragu_pasta::Fp;

    use super::{super::recorder::Recorder, *};

    /// The planted under-constrained square, judged by the pinned-input
    /// oracle instead of an anchor: `root` is the declared input, `square`
    /// the output, and the missing `square = root²` gate means the prover
    /// can move the output with the input pinned. Adding the gate makes
    /// the sweep come back clean — including against the `root²`-zero
    /// probe values.
    #[test]
    fn sweep_finds_missing_square_gate() {
        let root_honest = Fp::from(7u64);

        // Buggy: `square` is free advice, no gate ties it to `root`.
        let mut rec = Recorder::<Fp>::new();
        let root = rec.push_wire(root_honest);
        let square = rec.push_wire(root_honest.square());

        let violations = determinism_sweep(&rec.events, &rec.values, &[root], &[square]);
        assert_eq!(violations.len(), 1, "exactly the square hint violates");
        assert_eq!(violations[0].advice, square);
        assert_eq!(
            violations[0].moved,
            vec![(square, root_honest.square(), root_honest.square() + Fp::ONE,)]
        );
        assert!(constraints_hold(&rec.events, &violations[0].witness));

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
        assert!(
            determinism_sweep(&rec.events, &rec.values, &[root], &[square]).is_empty(),
            "with the gate emitted, no cheat moves the output",
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

        assert!(determinism_sweep(&rec.events, &rec.values, &[p, q], &[sum]).is_empty());

        // Under-declaring: with only `p` pinned, `q` is (correctly, per the
        // caller's spec) reported as freedom that moves the output.
        let violations = determinism_sweep(&rec.events, &rec.values, &[p], &[sum]);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].advice, q);
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

        let violations = determinism_sweep(&rec.events, &rec.values, &[input], &[output]);
        assert!(
            violations.is_empty(),
            "cheating h1 forces h2 to compensate; the output cannot move: {violations:?}",
        );
    }
}

//! Running the engine against a [`Circuit`] through its public API.
//!
//! [`capture`] synthesizes a circuit's witness through the [`Recorder`] and
//! then serializes its public output, exactly as trace evaluation does — so
//! the result carries the constraint graph, the honest wire values, *and*
//! the wires of the public instance in $k(Y)$ order. [`playback`] re-runs the
//! same synthesis through [`Playback`] over an injected witness.
//!
//! Nothing about the circuit is assumed beyond the trait: it builds its own
//! allocators (the recorder's `Extra = usize` supports the pooling
//! [`Standard`](ragu_primitives::allocator::Standard) allocator circuits
//! normally use), may call routines, and may emit constraints while writing
//! its output.
//!
//! # Staged circuits
//!
//! A [`MultiStage`](ragu_circuits::staging::MultiStage)-wrapped circuit —
//! every internal recursion circuit is one — reserves its stage wires
//! through `configure_stage`, which allocates them holding `Coeff::Zero` in
//! the consuming driver; the real stage values live in the separately
//! committed stage polynomials `r(X) = trace + Σ rx`. So the raw recording
//! of such a circuit is *internally inconsistent*: a post-stage gadget
//! computed a gate from a stage output's honest value but copy-constrained
//! that gate to the stage wire, which reads zero. [`capture`] repairs this
//! with a [stage overlay](overlay_stages) before returning, so its result
//! satisfies [`constraints_hold`](super::constraints_hold) like any other.
//! For a plain (non-staged) circuit the overlay is a no-op.

use ragu_arithmetic::ff::Field;
use ragu_circuits::Circuit;
use ragu_core::{
    Result,
    maybe::{Always, MaybeKind},
};
use ragu_primitives::{Element, GadgetExt};

use super::{Playback, Recorder, discover::discover_free_advice, recorder::deduce};

/// A circuit synthesized through the [`Recorder`].
pub struct Capture<F> {
    /// The recording driver after synthesis: the captured constraint graph
    /// ([`Recorder::events`]), the honest wire values ([`Recorder::values`],
    /// stage-overlaid so they satisfy the graph) and the pooled $D$ wires
    /// ([`Recorder::extras`]).
    pub recorder: Recorder<F>,
    /// The wires of the circuit's public instance, in the order the
    /// circuit's output gadget writes them — the $k(Y)$ order.
    pub instance: Vec<usize>,
    /// Stage wires the [overlay](overlay_stages) recovered — reserved wires
    /// a `MultiStage` circuit leaves free by contract (constrained by the
    /// bonding masks and sibling circuits, not here). Empty for a plain
    /// circuit. A soundness oracle must treat these as *declared inputs*:
    /// their freedom is real but external, not a bug in this circuit.
    pub stage_wires: Vec<usize>,
}

/// Synthesizes `circuit` on `witness` through the [`Recorder`], then applies
/// the [stage overlay](overlay_stages).
///
/// Runs [`Circuit::witness`] and then writes the resulting output gadget
/// into an element buffer, as trace evaluation does (a `Write` impl may
/// itself emit constraints, so the write is part of the circuit). The
/// witness must be satisfying; after the overlay the captured values satisfy
/// every captured constraint, which the engine's oracles assume and
/// [`constraints_hold`](super::constraints_hold) can re-check.
///
/// # Errors
///
/// Propagates any error from the circuit's witness generation or from
/// serializing its output. Returns [`InvalidWitness`](ragu_core::Error::InvalidWitness)
/// if the overlay cannot make the capture consistent — a non-satisfying
/// witness, or a staging shape the overlay does not model — rather than
/// handing back a capture that silently violates its own constraints.
pub fn capture<'witness, F: Field, C: Circuit<F>>(
    circuit: &C,
    witness: C::Witness<'witness>,
) -> Result<Capture<F>> {
    let mut recorder = Recorder::<F>::new();
    let output = circuit
        .witness(&mut recorder, Always::maybe_just(|| witness))?
        .into_output();
    let mut buffer: Vec<Element<'_, Recorder<F>>> = Vec::new();
    output.write(&mut recorder, &mut buffer)?;
    let instance = buffer.iter().map(|e| *e.wire()).collect();

    let stage_wires = overlay_stages(&recorder.events, &mut recorder.values)?;
    Ok(Capture {
        recorder,
        instance,
        stage_wires,
    })
}

/// Repairs the stage wires of a raw capture in place, returning the wires it
/// overlaid.
///
/// `configure_stage` reserves each stage wire holding zero, but a post-stage
/// gadget builds its constraints from the stage output's *honest* value —
/// so a raw staged capture holds honest values on every determined wire
/// while its stage wires read zero, contradicting the copy-constraints that
/// pin them. This recovers the honest stage values without any knowledge of
/// the staging internals:
///
/// * The **determined** wires — everything [`discover_free_advice`] does not
///   report free — still hold the honest values the gadgets computed, so
///   they seed the known set.
/// * The engine's deduction pass then forces every wire the honest knowns
///   pin, which back-solves each *used* stage wire from the copy-constraint
///   tying it to a downstream wire (`stage := gate_input`). Deduction only —
///   never the repair solver's guessing tier — so nothing is invented.
/// * Free wires left unforced (genuine advice, allocator waste, and stage
///   wires no output depends on) keep their raw values, which for a stage
///   wire is the honest zero the reservation gave it.
///
/// The overlaid wires are exactly the stage wires some output depends on —
/// the ones a soundness oracle must pin as inputs (see
/// [`Capture::stage_wires`]). For a plain circuit no wire is forced from the
/// knowns beyond what already holds, so the result is empty and `values` is
/// unchanged.
///
/// # Errors
///
/// Returns [`InvalidWitness`](ragu_core::Error::InvalidWitness) if the
/// overlaid witness still violates a captured constraint — the capture is
/// unusable, so this fails closed rather than returning it.
pub fn overlay_stages<F: Field>(
    events: &[super::Event<F>],
    values: &mut [F],
) -> Result<Vec<usize>> {
    let free = discover_free_advice(events, values);
    let mut known = vec![true; values.len()];
    for &w in &free {
        known[w] = false;
    }

    let before = values.to_vec();
    deduce(events, values, &mut known);

    let overlaid: Vec<usize> = free
        .iter()
        .copied()
        .filter(|&w| values[w] != before[w])
        .collect();

    if !super::constraints_hold(events, values) {
        return Err(ragu_core::Error::InvalidWitness(
            "stage overlay could not make the capture consistent".into(),
        ));
    }
    Ok(overlaid)
}

/// Re-runs `circuit` on `witness` through [`Playback`] over the injected
/// `values` (indexed by recorder wire, as produced by [`capture`] and
/// possibly repaired) and reports whether every gate, `C · D = 0`, linear
/// definition and `enforce_zero` held — and that the synthesis consumed
/// exactly the injected wires.
///
/// # Errors
///
/// Propagates any error from the circuit's witness generation or from
/// serializing its output.
pub fn playback<'witness, F: Field, C: Circuit<F>>(
    circuit: &C,
    witness: C::Witness<'witness>,
    values: Vec<F>,
) -> Result<bool> {
    let mut playback = Playback::<F>::new(values);
    let output = circuit
        .witness(&mut playback, Always::maybe_just(|| witness))?
        .into_output();
    let mut buffer: Vec<Element<'_, Playback<F>>> = Vec::new();
    output.write(&mut playback, &mut buffer)?;
    Ok(playback.accepts())
}

#[cfg(test)]
mod tests {
    use ragu_circuits::WithAux;
    use ragu_core::{
        drivers::{Driver, DriverValue},
        gadgets::{Bound, Kind},
        maybe::Maybe,
    };
    use ragu_pasta::Fp;
    use ragu_primitives::allocator::Standard;

    use super::*;
    use crate::{
        circuits::{MySimpleCircuit, SquareCircuit},
        patcher::{
            allocation_waste, constraints_hold, determinism_sweep, discover_free_advice, repair,
        },
    };

    /// `MySimpleCircuit` proves `a⁵ = b²` and outputs `(a + b, a − b)`.
    /// Its two witness allocations share one pooled gate: `a` on the gate's
    /// `a` wire (1), `b` on its `d` wire (4), with `b`/`c` (2, 3) wasted.
    #[test]
    fn capture_my_simple_circuit() -> Result<()> {
        let (a, b) = (Fp::from(4u64), Fp::from(32u64)); // 4⁵ = 1024 = 32²
        let cap = capture(&MySimpleCircuit, (a, b))?;
        let rec = &cap.recorder;

        assert!(constraints_hold(&rec.events, &rec.values));
        assert!(
            cap.stage_wires.is_empty(),
            "plain circuit: no stage overlay"
        );
        assert_eq!(rec.extras, vec![4]);
        assert_eq!(cap.instance.len(), 2);
        assert_eq!(rec.values[cap.instance[0]], a + b);
        assert_eq!(rec.values[cap.instance[1]], a - b);
        assert!(playback(&MySimpleCircuit, (a, b), rec.values.clone())?);

        // Only the allocations are free: `a`, the wasted `b`, and `d`.
        // Everything else — the squaring chain, `b²`, both outputs — is
        // derived from them.
        assert_eq!(
            discover_free_advice(&rec.events, &rec.values),
            vec![1, 2, 4]
        );

        // The census over a *healthy* circuit is empty: every discovered
        // free wire is a declared input (`a` at 1, `b` at 4) or structural
        // allocator waste — nothing unexplained.
        assert_eq!(allocation_waste(&rec.events, &rec.values), vec![(2, 3)]);

        // Corrupting an output is caught live.
        let mut corrupted = rec.values.clone();
        corrupted[cap.instance[0]] += Fp::ONE;
        assert!(!playback(&MySimpleCircuit, (a, b), corrupted)?);

        Ok(())
    }

    /// A deliberately under-constrained circuit: `square` is allocated as
    /// free advice next to `root` — the `square = root²` gate is never
    /// emitted — and `square` is the public output.
    struct UnderconstrainedSquare;

    impl Circuit<Fp> for UnderconstrainedSquare {
        type Instance<'instance> = Fp;
        type Output = Kind![Fp; Element<'_, _>];
        type Witness<'witness> = Fp;
        type Aux<'witness> = ();

        fn instance<'dr, 'instance: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            instance: DriverValue<D, Self::Instance<'instance>>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            Element::alloc(dr, &mut Standard::new(), instance)
        }

        fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, Self::Witness<'witness>>,
        ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'witness>>>>
        {
            let allocator = &mut Standard::new();
            let _root = Element::alloc(dr, allocator, witness.as_ref().map(|w| *w))?;
            // BUG (deliberate): the square is prover-chosen advice; nothing
            // ties it to `root`.
            let square = Element::alloc(dr, allocator, witness.map(|w| w * w))?;
            Ok(WithAux::new(square, D::unit()))
        }
    }

    /// The whole workflow this module exists for, end to end through the
    /// public `Circuit` API: capture, discover the free wires, subtract the
    /// declared inputs and the structural waste — the *unexplained* survivor
    /// is exactly the unpinned hint. And the survivor is exploitable: cheat
    /// the input, repair, and every captured constraint still holds (both by
    /// the stored events and by live playback) while the public output
    /// stays at its stale value instead of the cheated input's square.
    #[test]
    fn census_flags_unpinned_hint() -> Result<()> {
        let root = Fp::from(7u64);
        let cap = capture(&UnderconstrainedSquare, root)?;
        let rec = &cap.recorder;
        assert!(constraints_hold(&rec.events, &rec.values));

        // One pooled gate: `root` on its `a` (1), waste (2, 3), `square`
        // redeemed onto the `d` wire (4) — the public output.
        assert_eq!(cap.instance, vec![4]);
        let declared = [1usize];

        let discovered = discover_free_advice(&rec.events, &rec.values);
        let waste = allocation_waste(&rec.events, &rec.values);
        let unexplained: Vec<usize> = discovered
            .iter()
            .copied()
            .filter(|w| !declared.contains(w) && !waste.iter().any(|&(b, _)| b == *w))
            .collect();
        assert_eq!(
            unexplained,
            vec![4],
            "the census must flag exactly the unpinned square hint"
        );

        // Exploit it: move the declared input, repair, and the constraints
        // are satisfied while the output ignores the change.
        let mut values = rec.values.clone();
        values[declared[0]] += Fp::ONE;
        repair(&rec.events, &mut values, &discovered);
        assert!(constraints_hold(&rec.events, &values));
        assert!(playback(&UnderconstrainedSquare, root, values.clone())?);
        assert_eq!(
            values[cap.instance[0]],
            root.square(),
            "the output kept its stale value — no constraint carries the cheat"
        );
        assert_ne!(values[cap.instance[0]], (root + Fp::ONE).square());

        Ok(())
    }

    /// The pinned-input soundness oracle over the same planted circuit,
    /// end to end through `capture`: with `root` declared as the input and
    /// the public instance as the outputs, the sweep finds **two** ways the
    /// prover can move the output with the input pinned, and each evidence
    /// witness is independently accepted by a live playback:
    ///
    /// * cheat the unpinned `square` hint directly (wire 4); or
    /// * cheat the allocation gate's waste `b` (wire 2) — the gate output
    ///   `c = a·b` goes nonzero, and the pooled gate's `C · D = 0` then
    ///   *forces the co-allocated `square` to zero*. A second genuine
    ///   lever on the same missing constraint, reachable only because the
    ///   engine records the pooled allocator's auxiliary constraint.
    ///
    /// The healthy `MySimpleCircuit`, with its two private witnesses
    /// declared, sweeps clean — there the same waste-`b` cheat is rejected,
    /// because `C · D = 0` collides with the pinned witness on the D wire.
    #[test]
    fn determinism_sweep_over_captures() -> Result<()> {
        let root = Fp::from(7u64);
        let cap = capture(&UnderconstrainedSquare, root)?;
        let rec = &cap.recorder;

        let report = determinism_sweep(&rec.events, &rec.values, &[1], &cap.instance);
        let square = cap.instance[0];
        let violations = &report.violations;
        assert_eq!(violations.len(), 2, "the waste lever and the hint itself");
        assert_eq!(violations[0].advice, 2, "allocation waste `b`");
        assert_eq!(violations[0].moved, vec![(square, root.square(), Fp::ZERO)]);
        assert_eq!(violations[1].advice, square, "the unpinned hint directly");
        for violation in violations {
            assert!(playback(
                &UnderconstrainedSquare,
                root,
                violation.witness.clone()
            )?);
        }

        let (a, b) = (Fp::from(4u64), Fp::from(32u64));
        let cap = capture(&MySimpleCircuit, (a, b))?;
        let report = determinism_sweep(
            &cap.recorder.events,
            &cap.recorder.values,
            &[1, 4],
            &cap.instance,
        );
        assert!(
            report.violations.is_empty(),
            "outputs are functions of the declared witnesses; waste moves nothing",
        );
        assert_eq!(
            (report.pinned, report.rejected),
            (0, 1),
            "the waste-`b` cheat is rejected outright here: `C · D = 0` \
             collides with the pinned witness on the co-allocated `d` wire",
        );

        Ok(())
    }

    /// Repairing a cheat on a captured circuit's witness wire: moving `a`
    /// propagates through every square to the output, which `playback`
    /// then accepts as a different-but-valid witness.
    #[test]
    fn repair_propagates_through_captured_circuit() -> Result<()> {
        let circuit = SquareCircuit { times: 3 };
        let cap = capture(&circuit, Fp::from(3u64))?;
        let rec = &cap.recorder;
        let free = discover_free_advice(&rec.events, &rec.values);
        assert_eq!(
            free,
            vec![1, 2],
            "one allocation gate: `a` plus the wasted `b` (`c = a·b` follows)"
        );

        let mut values = rec.values.clone();
        values[1] = Fp::from(5u64);
        repair(&rec.events, &mut values, &free);
        assert!(constraints_hold(&rec.events, &values));
        assert_eq!(values[cap.instance[0]], Fp::from(5u64).pow([8u64]));
        assert!(playback(&circuit, Fp::from(3u64), values)?);
        Ok(())
    }

    // Staged circuits (issue #793 bullet 4): a real `MultiStage` circuit —
    // the same shape every internal recursion circuit has — captured, made
    // consistent by the stage overlay, and run through the census and the
    // determinism oracle.

    use core::marker::PhantomData;

    use ragu_circuits::{
        polynomials::TestRank,
        staging::{MultiStage, MultiStageCircuit, Stage, StageBuilder},
    };
    use ragu_core::gadgets::Gadget;

    use crate::patcher::Capture;

    #[derive(Gadget, ragu_primitives::io::Write)]
    struct TwoWires<'dr, #[ragu(driver)] D: Driver<'dr>> {
        #[ragu(gadget)]
        a: Element<'dr, D>,
        #[ragu(gadget)]
        b: Element<'dr, D>,
    }

    /// A two-wire stage whose outputs are committed separately; in the
    /// consuming circuit its wires are reserved holding zero.
    #[derive(Default)]
    struct StageW2;

    impl Stage<Fp, TestRank> for StageW2 {
        type Parent = ();
        type Witness<'source> = (Fp, Fp);
        type OutputKind =
            <TwoWires<'static, PhantomData<Fp>> as Gadget<'static, PhantomData<Fp>>>::Kind;

        fn values() -> usize {
            2
        }

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, Self::Witness<'source>>,
        ) -> Result<Bound<'dr, D, Self::OutputKind>>
        where
            Self: 'dr,
        {
            let a = Element::alloc(dr, &mut (), witness.as_ref().map(|w| w.0))?;
            let b = Element::alloc(dr, &mut (), witness.as_ref().map(|w| w.1))?;
            Ok(TwoWires { a, b })
        }
    }

    /// Post-stage the circuit squares the stage's `a` and outputs it — so
    /// the output *is* a function of the stage wire. `SOUND` toggles whether
    /// the square is actually gated: `true` emits `a·a = out` (honest); with
    /// `false` the output is a free allocation never tied to `a` — the
    /// planted under-constraint the oracle must catch even through a stage.
    #[derive(Clone, Default)]
    struct StagedSquare<const SOUND: bool>;

    impl<const SOUND: bool> MultiStageCircuit<Fp, TestRank> for StagedSquare<SOUND> {
        type Last = StageW2;
        type Instance<'source> = ();
        type Witness<'source> = (Fp, Fp);
        type Output = Kind![Fp; Element<'_, _>];
        type Aux<'source> = ();

        fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            _dr: &mut D,
            _instance: DriverValue<D, ()>,
        ) -> Result<Bound<'dr, D, Self::Output>>
        where
            Self: 'dr,
        {
            unreachable!("instance is not exercised by the patcher")
        }

        fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            builder: StageBuilder<'a, 'dr, D, TestRank, (), StageW2>,
            witness: DriverValue<D, (Fp, Fp)>,
        ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, ()>>>
        where
            Self: 'dr,
        {
            let (guard, builder) = builder.configure_stage(StageW2)?;
            let dr = builder.finish();
            let TwoWires { a, b: _ } = guard.unenforced(dr, witness)?;
            let out = if SOUND {
                a.square(dr)?
            } else {
                // BUG: allocate the "square" as free advice, no gate to `a`.
                Element::alloc(dr, &mut Standard::new(), a.value().map(|v| *v * v))?
            };
            Ok(WithAux::new(out, D::unit()))
        }
    }

    /// The stage overlay makes a staged capture self-consistent: the raw
    /// recording reads zero on the stage wire the squared output depends on,
    /// and `capture` recovers the honest value so `constraints_hold` passes
    /// and `stage_wires` names the recovered wire. The healthy circuit then
    /// sweeps clean with that wire declared, and — the point — playback over
    /// the overlaid witness independently re-accepts it.
    #[test]
    fn staged_capture_overlays_and_sweeps_clean() -> Result<()> {
        let circuit = MultiStage::new(StagedSquare::<true>);
        let cap = capture(&circuit, (Fp::from(3u64), Fp::from(5u64)))?;
        let rec = &cap.recorder;

        assert!(
            constraints_hold(&rec.events, &rec.values),
            "the overlay must repair the zero-reserved stage wires",
        );
        assert_eq!(
            cap.stage_wires,
            vec![1],
            "the squared output depends on stage wire 1; it was overlaid",
        );
        assert_eq!(rec.values[1], Fp::from(3u64), "recovered honest stage `a`");
        assert_eq!(rec.values[cap.instance[0]], Fp::from(9u64));
        assert!(playback(
            &circuit,
            (Fp::from(3u64), Fp::from(5u64)),
            rec.values.clone()
        )?);

        // The stage wire is a declared input: its freedom is external
        // (committed and bonded elsewhere), not a bug in this circuit.
        let mut inputs = cap.stage_wires.clone();
        let report = determinism_sweep(&rec.events, &rec.values, &inputs, &cap.instance);
        assert!(report.violations.is_empty(), "{:?}", report.violations);

        // Under-declaring the stage wire is the documented false positive:
        // the output legitimately follows it.
        inputs.clear();
        let report = determinism_sweep(&rec.events, &rec.values, &inputs, &cap.instance);
        assert_eq!(
            report.violations.len(),
            1,
            "with the stage input undeclared, moving it moves the output",
        );
        Ok(())
    }

    /// The determinism oracle catches an under-constraint *through* a stage:
    /// with the stage input declared and pinned, the unpinned "square" hint
    /// still lets the prover move the output — exactly the bug class on the
    /// internal recursion circuits, on a real `MultiStage`.
    #[test]
    fn staged_determinism_oracle_catches_planted_bug() -> Result<()> {
        let circuit = MultiStage::new(StagedSquare::<false>);
        let cap: Capture<Fp> = capture(&circuit, (Fp::from(3u64), Fp::from(5u64)))?;
        let rec = &cap.recorder;
        assert!(constraints_hold(&rec.events, &rec.values));

        let report = determinism_sweep(&rec.events, &rec.values, &cap.stage_wires, &cap.instance);
        assert!(
            !report.violations.is_empty(),
            "the unpinned staged square must be caught",
        );
        for violation in &report.violations {
            assert!(
                playback(
                    &circuit,
                    (Fp::from(3u64), Fp::from(5u64)),
                    violation.witness.clone()
                )?,
                "each evidence witness must be independently accepted",
            );
        }
        Ok(())
    }
}

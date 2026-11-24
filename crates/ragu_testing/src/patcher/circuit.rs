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
//! that gate to the stage wire, which reads zero. [`capture_with_stage_values`]
//! takes the honest stage values from the caller — who has the stage
//! witnesses — writes them onto the reserved prefix and recomputes the
//! virtual wires, so its result satisfies
//! [`constraints_hold`](super::constraints_hold) like any other, and names
//! every reserved wire in [`Capture::stage_wires`] so an oracle can declare
//! each one. [`capture`] is the entry point for a plain circuit; on a staged
//! one it fails closed.

use ragu_circuits::Circuit;
use ragu_core::{
    Result,
    maybe::{Always, MaybeKind},
};
use ragu_primitives::{Element, GadgetExt};
use udon::field::Field;

use super::{Event, Playback, Recorder};

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
    /// The reserved stage wires of a `MultiStage` circuit, in reservation
    /// order: index `i` is the `i`-th wire of the whole stage chain, the same
    /// numbering `StageGuard` injects into the stage gadgets. Empty for a
    /// plain circuit.
    ///
    /// Reserved wires are free by contract — constrained by the stage masks
    /// and by whichever sibling circuit *checks* them, never by reservation —
    /// so a soundness oracle must declare every one: as an input it pins, or,
    /// for the stage values this circuit is responsible for checking, as an
    /// output it watches.
    pub stage_wires: Vec<usize>,
}

/// Synthesizes a plain `circuit` on `witness` through the [`Recorder`].
///
/// Runs [`Circuit::witness`] and then writes the resulting output gadget
/// into an element buffer, as trace evaluation does (a `Write` impl may
/// itself emit constraints, so the write is part of the circuit). The
/// witness must be satisfying: the engine's oracles assume the captured
/// values satisfy the captured constraints, which
/// [`constraints_hold`](super::constraints_hold) can re-check.
///
/// This is [`capture_with_stage_values`] with no stage values, so a staged
/// circuit — whose reserved wires read zero — fails closed here.
///
/// # Errors
///
/// Propagates any error from the circuit's witness generation or from
/// serializing its output, and returns
/// [`InvalidWitness`](ragu_core::Error::InvalidWitness) if the capture does
/// not satisfy its own constraints.
pub fn capture<'witness, F: Field, C: Circuit<F>>(
    circuit: &C,
    witness: C::Witness<'witness>,
) -> Result<Capture<F>> {
    capture_with_stage_values(circuit, witness, &[])
}

/// [`capture`] for a staged circuit, with the honest values of its reserved
/// stage wires supplied by the caller.
///
/// `stage_values[i]` is the value of the `i`-th reserved wire of the whole
/// stage chain, in the order `StageGuard` injects them — each stage's output
/// wires in traversal order, padded with zeros to the two wires per gate the
/// stage reserves; what the stage polynomials commit to, without the alpha.
/// A harness that holds the stage witnesses produces this by running each
/// `Stage::witness` on an extractor emulator, and then the overlay is exact
/// for any circuit shape — including one that reads a stage wire only
/// through a combination of several, such as the coordinate differences of
/// an incomplete point addition, which no deduction from the gadgets'
/// honest values could split.
///
/// # Errors
///
/// As [`capture`]; additionally fails if `stage_values` does not cover
/// exactly the reserved prefix, or if the capture does not satisfy its
/// constraints once the values are in — a non-satisfying witness, or stage
/// values that are not the witness's.
pub fn capture_with_stage_values<'witness, F: Field, C: Circuit<F>>(
    circuit: &C,
    witness: C::Witness<'witness>,
    stage_values: &[F],
) -> Result<Capture<F>> {
    let mut recorder = Recorder::<F>::new();
    let output = circuit
        .witness(&mut recorder, Always::maybe_just(|| witness))?
        .into_output();
    let mut buffer: Vec<Element<'_, Recorder<F>>> = Vec::new();
    output.write(&mut recorder, &mut buffer)?;
    let instance = buffer.iter().map(|e| *e.wire()).collect();

    let stage_wires = overlay_stage_values(&recorder.events, &mut recorder.values, stage_values)?;
    Ok(Capture {
        recorder,
        instance,
        stage_wires,
    })
}

/// Writes the honest stage values onto the reserved prefix of a raw capture
/// and recomputes every virtual wire from them, returning the stage wires
/// in reservation order.
///
/// Every `configure_stage` call happens before the circuit can touch the
/// driver (`StageBuilder` only releases it from `finish`), and each stage
/// reserves its wires through a fresh pooling allocator, so the recording
/// begins with one allocation gate `a · 0 = 0` per reserved gate, each
/// followed by the `assign_extra` of its $D$ wire: `a` and `d` are the two
/// stage wires it carries, and `b` and `c` stay zero. Virtual
/// [`Lin`](Event::Lin) wires are definitions, so they are re-evaluated in
/// emission order afterwards, which brings every value the recorder computed
/// from a zero stage wire up to date.
fn overlay_stage_values<F: Field>(
    events: &[Event<F>],
    values: &mut [F],
    stage_values: &[F],
) -> Result<Vec<usize>> {
    if !stage_values.len().is_multiple_of(2) {
        return Err(ragu_core::Error::InvalidWitness(
            "stage values come two per reserved gate".into(),
        ));
    }
    let mut stage_wires = Vec::with_capacity(stage_values.len());
    let mut prefix = events.iter();
    for gate in 0..stage_values.len() / 2 {
        match (prefix.next(), prefix.next()) {
            (Some(Event::Gate { a, b, c }), Some(Event::Extra { c: extra_c, d }))
                if c == extra_c && [*a, *b, *c, *d].iter().all(|&w| values[w] == F::ZERO) =>
            {
                values[*a] = stage_values[2 * gate];
                values[*d] = stage_values[2 * gate + 1];
                stage_wires.extend([*a, *d]);
            }
            _ => {
                return Err(ragu_core::Error::InvalidWitness(
                    "the recording does not begin with as many reserved gates as the stage \
                     values cover"
                        .into(),
                ));
            }
        }
    }

    for ev in events {
        if let Event::Lin { out, terms } = ev {
            values[*out] = terms.iter().map(|(w, c)| values[*w] * c).sum();
        }
    }

    if !super::constraints_hold(events, values) {
        return Err(ragu_core::Error::InvalidWitness(
            "the capture does not satisfy its constraints: a non-satisfying witness, stage \
             values that are not the witness's, or a staged circuit captured without them"
                .into(),
        ));
    }

    Ok(stage_wires)
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
        pasta::Fp,
    };
    use ragu_primitives::allocator::Standard;

    use super::*;
    use crate::{
        circuits::{MySimpleCircuit, SquareCircuit},
        patcher::{
            allocation_waste, constraints_hold, determinism_sweep, discover_free_advice, forced_by,
            repair,
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
    /// declared, reports no violation — but *vacuously*, by the rule
    /// `SweepReport` states for itself: its one cheatable wire, the waste
    /// `b`, is **rejected** rather than neutralized, because `C · D = 0`
    /// collides with the pinned witness on the D wire. Rejection is
    /// inconclusive, so this half pins down the counters, not a determinism
    /// guarantee for `MySimpleCircuit`.
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
            "no lever on the output was found: {:?}",
            report.violations,
        );
        assert_eq!(
            (report.pinned, report.rejected),
            (0, 1),
            "vacuous, not clean: the one cheatable wire (the waste `b`) is \
             rejected outright — `C · D = 0` collides with the pinned witness \
             on the co-allocated `d` wire — so the sweep demonstrated nothing \
             about determinism here",
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
        assert_eq!(values[cap.instance[0]], Fp::from(5u64).pow_u64(8u64));
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

    /// Squares the *sum* of the two stage outputs, so each stage wire is
    /// read only through a two-term combination: nothing in the recording
    /// pins either wire on its own, which is why the overlay takes the
    /// values from the caller rather than deducing them.
    #[derive(Clone, Default)]
    struct StagedSumSquare;

    impl MultiStageCircuit<Fp, TestRank> for StagedSumSquare {
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
            let TwoWires { a, b } = guard.unenforced(dr, witness)?;
            let sum = a.add(dr, &b);
            Ok(WithAux::new(sum.square(dr)?, D::unit()))
        }
    }

    const STAGE: (Fp, Fp) = (
        Fp::new(udon::fp_hex!(
            "0x0000000000000000000000000000000000000000000000000000000000000003",
        )),
        Fp::new(udon::fp_hex!(
            "0x0000000000000000000000000000000000000000000000000000000000000005",
        )),
    );

    /// The stage overlay makes a staged capture self-consistent: the raw
    /// recording reads zero on the stage wire the squared output depends on,
    /// and the supplied values put both reserved wires right — the unread
    /// `b` too — so `constraints_hold` passes and playback independently
    /// re-accepts the witness. The healthy circuit then sweeps clean with
    /// the stage wires declared; with nothing declared the output
    /// legitimately follows `a`, the documented false positive of an
    /// under-declared input set.
    #[test]
    fn staged_capture_overlays_and_sweeps_clean() -> Result<()> {
        let circuit = MultiStage::new(StagedSquare::<true>);
        let cap = capture_with_stage_values(&circuit, STAGE, &[STAGE.0, STAGE.1])?;
        let rec = &cap.recorder;

        assert!(constraints_hold(&rec.events, &rec.values));
        assert_eq!(
            cap.stage_wires,
            vec![1, 4],
            "StageW2's one reserved gate carries `a` on its `a` wire and `b` on its `d` wire",
        );
        assert_eq!(rec.values[1], STAGE.0);
        assert_eq!(rec.values[4], STAGE.1);
        assert_eq!(rec.values[cap.instance[0]], Fp::from(9u64));
        assert!(playback(&circuit, STAGE, rec.values.clone())?);

        let report = determinism_sweep(&rec.events, &rec.values, &cap.stage_wires, &cap.instance);
        assert!(report.violations.is_empty(), "{:?}", report.violations);

        let report = determinism_sweep(&rec.events, &rec.values, &[], &cap.instance);
        assert_eq!(report.violations.len(), 1);
        assert_eq!(report.violations[0].advice, 1);
        Ok(())
    }

    /// The determinism oracle catches an under-constraint *through* a stage:
    /// with the stage input declared and pinned, the unpinned "square" hint
    /// still lets the prover move the output — exactly the bug class on the
    /// internal recursion circuits, on a real `MultiStage`.
    #[test]
    fn staged_determinism_oracle_catches_planted_bug() -> Result<()> {
        let circuit = MultiStage::new(StagedSquare::<false>);
        let cap = capture_with_stage_values(&circuit, STAGE, &[STAGE.0, STAGE.1])?;
        let rec = &cap.recorder;
        assert!(constraints_hold(&rec.events, &rec.values));

        let report = determinism_sweep(&rec.events, &rec.values, &cap.stage_wires, &cap.instance);
        assert!(
            !report.violations.is_empty(),
            "the unpinned staged square must be caught",
        );
        for violation in &report.violations {
            assert!(
                playback(&circuit, STAGE, violation.witness.clone())?,
                "each evidence witness must be independently accepted",
            );
        }
        Ok(())
    }

    /// A stage value that is honestly zero is indistinguishable from its
    /// zero-holding reservation by value alone — which is why the overlay
    /// takes the values from the caller instead of guessing them from the
    /// recording. Declared, the healthy circuit sweeps clean; the same sweep
    /// with nothing declared shows the false positive that was at stake.
    #[test]
    fn honestly_zero_stage_value_is_still_declared() -> Result<()> {
        let circuit = MultiStage::new(StagedSquare::<true>);
        let witness = (Fp::ZERO, STAGE.1);
        let cap = capture_with_stage_values(&circuit, witness, &[witness.0, witness.1])?;
        let rec = &cap.recorder;
        assert!(constraints_hold(&rec.events, &rec.values));
        assert_eq!(cap.stage_wires, vec![1, 4]);
        assert_eq!(rec.values[cap.instance[0]], Fp::ZERO);

        let report = determinism_sweep(&rec.events, &rec.values, &cap.stage_wires, &cap.instance);
        assert!(report.violations.is_empty(), "{:?}", report.violations);

        let report = determinism_sweep(&rec.events, &rec.values, &[], &cap.instance);
        assert_eq!(
            report.violations.len(),
            1,
            "undeclared, the zero stage value moves the square: the false positive",
        );
        assert_eq!(report.violations[0].advice, 1);
        Ok(())
    }

    /// `forced_by` is the static pinned-input check: with the stage input
    /// declared, the honest square is forced; with the planted bug it is
    /// not, before any cheat is tried.
    #[test]
    fn forced_by_flags_the_planted_bug_statically() -> Result<()> {
        let sound = MultiStage::new(StagedSquare::<true>);
        let cap = capture_with_stage_values(&sound, STAGE, &[STAGE.0, STAGE.1])?;
        let forced = forced_by(&cap.recorder.events, &cap.recorder.values, &cap.stage_wires);
        assert!(
            forced.contains(&cap.instance[0]),
            "the square follows the stage input"
        );

        let buggy = MultiStage::new(StagedSquare::<false>);
        let cap = capture_with_stage_values(&buggy, STAGE, &[STAGE.0, STAGE.1])?;
        let forced = forced_by(&cap.recorder.events, &cap.recorder.values, &cap.stage_wires);
        assert!(
            !forced.contains(&cap.instance[0]),
            "the free \"square\" is not a function of the declared input",
        );
        Ok(())
    }

    /// The overlay is exact whatever the circuit reads: `StagedSumSquare`
    /// touches each stage wire only through `a + b`, and still captures,
    /// plays back and sweeps clean. And it fails closed: a staged circuit
    /// captured without its stage values, wrong values, or an odd number of
    /// them are all refused.
    #[test]
    fn stage_values_overlay_is_exact_and_fails_closed() -> Result<()> {
        let circuit = MultiStage::new(StagedSumSquare);
        let cap = capture_with_stage_values(&circuit, STAGE, &[STAGE.0, STAGE.1])?;
        assert_eq!(cap.stage_wires, vec![1, 4]);
        assert_eq!(cap.recorder.values[cap.instance[0]], Fp::from(64u64));
        assert!(playback(&circuit, STAGE, cap.recorder.values.clone())?);
        let report = determinism_sweep(
            &cap.recorder.events,
            &cap.recorder.values,
            &cap.stage_wires,
            &cap.instance,
        );
        assert!(report.violations.is_empty(), "{:?}", report.violations);

        assert!(
            capture(&circuit, STAGE).is_err(),
            "a staged circuit captured without its stage values reads zero on them",
        );
        assert!(capture_with_stage_values(&circuit, STAGE, &[Fp::from(4u64), STAGE.1]).is_err());
        assert!(capture_with_stage_values(&circuit, STAGE, &[STAGE.0]).is_err());
        assert!(
            capture_with_stage_values(&circuit, STAGE, &[STAGE.0, STAGE.1, Fp::ZERO, Fp::ZERO])
                .is_err()
        );
        Ok(())
    }
}

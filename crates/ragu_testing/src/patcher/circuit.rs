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

use ragu_arithmetic::ff::Field;
use ragu_circuits::Circuit;
use ragu_core::{
    Result,
    maybe::{Always, MaybeKind},
};
use ragu_primitives::{Element, GadgetExt};

use super::{Playback, Recorder};

/// A circuit synthesized through the [`Recorder`].
pub struct Capture<F> {
    /// The recording driver after synthesis: the captured constraint graph
    /// ([`Recorder::events`]), the honest wire values ([`Recorder::values`])
    /// and the pooled $D$ wires ([`Recorder::extras`]).
    pub recorder: Recorder<F>,
    /// The wires of the circuit's public instance, in the order the
    /// circuit's output gadget writes them — the $k(Y)$ order.
    pub instance: Vec<usize>,
}

/// Synthesizes `circuit` on `witness` through the [`Recorder`].
///
/// Runs [`Circuit::witness`] and then writes the resulting output gadget
/// into an element buffer, as trace evaluation does (a `Write` impl may
/// itself emit constraints, so the write is part of the circuit). The
/// witness should be satisfying: the engine's oracles assume the captured
/// values satisfy the captured constraints, which
/// [`constraints_hold`](super::constraints_hold) verifies.
///
/// # Errors
///
/// Propagates any error from the circuit's witness generation or from
/// serializing its output.
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
    Ok(Capture { recorder, instance })
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

        let violations = determinism_sweep(&rec.events, &rec.values, &[1], &cap.instance);
        let square = cap.instance[0];
        assert_eq!(violations.len(), 2, "the waste lever and the hint itself");
        assert_eq!(violations[0].advice, 2, "allocation waste `b`");
        assert_eq!(violations[0].moved, vec![(square, root.square(), Fp::ZERO)]);
        assert_eq!(violations[1].advice, square, "the unpinned hint directly");
        for violation in &violations {
            assert!(playback(
                &UnderconstrainedSquare,
                root,
                violation.witness.clone()
            )?);
        }

        let (a, b) = (Fp::from(4u64), Fp::from(32u64));
        let cap = capture(&MySimpleCircuit, (a, b))?;
        assert!(
            determinism_sweep(
                &cap.recorder.events,
                &cap.recorder.values,
                &[1, 4],
                &cap.instance,
            )
            .is_empty(),
            "outputs are functions of the declared witnesses; waste moves nothing",
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
}

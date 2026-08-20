//! Structural discovery of free advice from a recorded constraint graph.
//!
//! The engine's oracles need to know which wires the prover is free to
//! choose — the advice — and which are derived from them by the
//! constraints. A fuzz substrate that built the circuit can simply hand over
//! that list; a circuit captured through its public API cannot, because it
//! owns its allocators and the [`Recorder`] sees only gates, linear
//! combinations and enforces. [`discover_free_advice`] recovers the list
//! from the graph itself.
//!
//! # What "free" means here
//!
//! A wire is *derived* when the constraints determine it from wires created
//! before it, and *free* otherwise. Discovery walks the wires in creation
//! order, always taking the earliest wire the constraints have not yet
//! determined as the next free one, and then lets the solver deduce
//! everything that wire unlocks — so a `mul` gate's operands are derived
//! (they are copy-constrained to earlier wires), its output is derived
//! (`a·b`), an `invert`'s inverse is derived (back-solved from `x·x⁻¹ = 1`),
//! while an allocation's `a` wire, a pooled allocation's `d` wire, an
//! `alloc_square` root, a `Boolean::alloc` bit, and an allocation gate's
//! wasted `b` are free. Only *forced* deductions count ([`deduce`], never
//! the repair solver's guessing tier), so a wire reported *derived* is
//! genuinely determined by the wires before it.
//!
//! # What it does not tell you
//!
//! Discovery is structural: it cannot distinguish a genuine witness input
//! from an unconstrained hint, because both are wires nothing derives. That
//! is exactly why it is useful — every reported wire that is *not* a known
//! allocation is a wire a gadget left unpinned — but it also means the
//! caller, not discovery, decides which free wires are the inputs an oracle
//! pins and which are the advice it cheats.
//!
//! Three consequences of the earliest-first policy, of working at one
//! witness, and of the solver being bounded:
//!
//! * An under-determined system reports its *earliest* participant free and
//!   the rest derived — `p + q = 3` yields `p`, not `q`. The count of free
//!   wires is what is meaningful, not the particular representatives.
//! * Determination is judged at the supplied (satisfying) witness, so a
//!   wire that is pinned generically but not at a special point is reported
//!   free there: the inverse hint of an honestly-zero `is_zero` input, for
//!   instance. That is the truth at that witness, not a discovery error.
//! * "Free" means *the bounded solver could not derive it*: [`deduce`] sees
//!   no deduction from a gate with both operands unknown, and skips linear
//!   clusters wider than its cap — and since discovery starts with the
//!   whole graph unknown, the cluster pass only engages near the end. A
//!   wire pinned solely through such wide coupling is over-reported as
//!   free. So the result is a *candidate* list that errs toward reporting
//!   wires, never toward hiding them — the safe direction for a census
//!   whose job is flagging suspicious freedom. On ragu's actual emission
//!   patterns the over-approximation is empty: gadgets pin each hint with
//!   locally solvable constraints, which is pinned down for the whole fuzz
//!   substrate by an exactness proptest there (discovery must equal the
//!   substrate's own allocation list on anchorless programs).

use ragu_arithmetic::ff::Field;

use super::recorder::{Event, Recorder, deduce};

/// The `(b, c)` waste-wire pairs of the allocation gates in a recorded
/// graph, in emission order — recovered structurally, for callers that did
/// not build the circuit and so cannot ask the allocator
/// ([`TrackingAllocator::wasted`](super::TrackingAllocator) is the
/// synthesis-side ground truth this must match).
///
/// An allocation gate is `a · 0 = 0`: its `b` and `c` are honestly zero,
/// `b` appears in no other constraint, and `c` is referenced at most by the
/// gate's own [`Event::Extra`] (when a pooling allocator later hands out
/// the $D$ wire). The classification is sound for any gate matching that
/// shape regardless of which gadget emitted it: a zero, never-referenced
/// `b` genuinely is an unconstrained wasted wire. `values` must be the
/// honest capture — waste is zero by construction there, and a repaired
/// witness may legitimately move it.
///
/// The intended use is subtracting design freedom from a census: the free
/// wires [`discover_free_advice`] reports minus the circuit's declared
/// input wires minus these `b` wires are the *unexplained* freedom — hints
/// some gadget left unpinned.
pub fn allocation_waste<F: Field>(events: &[Event<F>], values: &[F]) -> Vec<(usize, usize)> {
    let mut occurrences = vec![0usize; values.len()];
    let mut extra_on_c = vec![false; values.len()];
    for ev in events {
        match ev {
            Event::Lin { out, terms } => {
                occurrences[*out] += 1;
                for (w, _) in terms {
                    occurrences[*w] += 1;
                }
            }
            Event::Gate { a, b, c } => {
                occurrences[*a] += 1;
                occurrences[*b] += 1;
                occurrences[*c] += 1;
            }
            Event::Enforce { terms } => {
                for (w, _) in terms {
                    occurrences[*w] += 1;
                }
            }
            Event::Extra { c, d } => {
                occurrences[*c] += 1;
                occurrences[*d] += 1;
                extra_on_c[*c] = true;
            }
        }
    }
    events
        .iter()
        .filter_map(|ev| match ev {
            Event::Gate { b, c, .. }
                if values[*b] == F::ZERO
                    && values[*c] == F::ZERO
                    && occurrences[*b] == 1
                    && (occurrences[*c] == 1 || (occurrences[*c] == 2 && extra_on_c[*c])) =>
            {
                Some((*b, *c))
            }
            _ => None,
        })
        .collect()
}

/// The free-advice wires of a recorded constraint graph, ascending.
///
/// `values` must be a satisfying assignment of `events` (an honest capture);
/// the result is the set of wires the constraints do not determine from
/// earlier wires, per the module documentation. `values` is not modified.
pub fn discover_free_advice<F: Field>(events: &[Event<F>], values: &[F]) -> Vec<usize> {
    let mut scratch = values.to_vec();
    let mut known = vec![false; scratch.len()];
    known[Recorder::<F>::ONE] = true;

    let mut free = Vec::new();
    // The earliest unknown wire only ever moves forward: `known` grows
    // monotonically and everything before `next` is already known.
    let mut next = 0;
    loop {
        deduce(events, &mut scratch, &mut known);
        match known[next..].iter().position(|k| !k) {
            None => break,
            Some(offset) => {
                let wire = next + offset;
                known[wire] = true;
                free.push(wire);
                next = wire + 1;
            }
        }
    }
    free
}

#[cfg(test)]
mod tests {
    use ragu_arithmetic::Coeff;
    use ragu_core::drivers::{Driver, LinearExpression};
    use ragu_pasta::Fp;
    use ragu_primitives::{Boolean, Element};

    use super::*;
    use crate::patcher::{TrackingAllocator, constraints_hold};

    /// The planted bug behind [`selftest`](super::super::selftest): `square`
    /// is allocated beside `root` without the `square = root²` gate, so
    /// both are free — and adding the gate (as `Element::square` emits it:
    /// a gate with both operands copy-constrained to `root`) makes `square`
    /// derived again.
    #[test]
    fn missing_gate_leaves_square_free() {
        let root_honest = Fp::from(7u64);
        let mut rec = Recorder::<Fp>::new();
        let root = rec.push_wire(root_honest);
        let square = rec.push_wire(root_honest.square());
        assert_eq!(
            discover_free_advice(&rec.events, &rec.values),
            vec![root, square]
        );

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
        assert_eq!(discover_free_advice(&rec.events, &rec.values), vec![root]);
    }

    /// An under-determined linear relation frees its earliest participant
    /// only; an anchored wire is derived even though it was allocated.
    #[test]
    fn earliest_first_and_anchors() {
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
        assert_eq!(discover_free_advice(&rec.events, &rec.values), vec![p]);

        // Anchor `p` to its honest value the way the fuzz substrate does: a
        // constant wire, a difference Lin, and a 1-term enforce.
        let pin = rec.add(|lc| lc.add_term(&one, Coeff::One));
        let diff = rec.add(|lc| lc.add(&p).add_term(&pin, Coeff::NegativeOne));
        rec.enforce_zero(|lc| lc.add(&diff)).unwrap();
        assert!(constraints_hold(&rec.events, &rec.values));
        assert!(discover_free_advice(&rec.events, &rec.values).is_empty());
    }

    /// Allocation patterns through the pooling allocator: the `a` wire and
    /// the wasted `b` of a fresh gate are free, its `c` is derived, and the
    /// `d` handed out as the next allocation is free; a `Boolean::alloc`'s
    /// bit is free with its complement and output derived. The structural
    /// waste classifier recovers exactly what the allocator recorded —
    /// including *not* classifying the boolean gate (whose `b` is the
    /// referenced complement) as an allocation.
    #[test]
    fn allocation_patterns() -> ragu_core::Result<()> {
        let mut rec = Recorder::<Fp>::new();
        let mut alloc = TrackingAllocator::default();
        let x = *Element::alloc(
            &mut rec,
            &mut alloc,
            Recorder::<Fp>::just(|| Fp::from(5u64)),
        )?
        .wire();
        let y = *Element::alloc(
            &mut rec,
            &mut alloc,
            Recorder::<Fp>::just(|| Fp::from(9u64)),
        )?
        .wire();
        let bit = *Boolean::alloc(&mut rec, &mut alloc, Recorder::<Fp>::just(|| true))?.wire();
        let (b, _c) = alloc.wasted[0];
        assert_eq!(
            discover_free_advice(&rec.events, &rec.values),
            vec![x, b, y, bit]
        );
        assert_eq!(allocation_waste(&rec.events, &rec.values), alloc.wasted);
        Ok(())
    }

    /// Determination is value-dependent: `is_zero`'s hints are derived when
    /// the input is nonzero, but the inverse hint is genuinely free when the
    /// input is zero (the bit is still pinned, via `x·inv = 1 − bit`).
    #[test]
    fn is_zero_hints() -> ragu_core::Result<()> {
        for (input, expect_inverse_free) in [(Fp::from(7u64), false), (Fp::ZERO, true)] {
            let mut rec = Recorder::<Fp>::new();
            let mut alloc = TrackingAllocator::default();
            let x = Element::alloc(&mut rec, &mut alloc, Recorder::<Fp>::just(|| input))?;
            x.is_zero(&mut rec, &mut alloc)?;
            assert!(constraints_hold(&rec.events, &rec.values));

            let (b, _c) = alloc.wasted[0];
            let mut expected = vec![*x.wire(), b];
            if expect_inverse_free {
                // The inverse hint is the `b` wire of the second `is_zero`
                // gate, `x · inv = 1 − bit`.
                let inverse = rec
                    .events
                    .iter()
                    .filter_map(|ev| match ev {
                        Event::Gate { b, .. } => Some(*b),
                        _ => None,
                    })
                    .nth(2)
                    .expect("is_zero emits two gates after the allocation gate");
                expected.push(inverse);
            }
            assert_eq!(
                discover_free_advice(&rec.events, &rec.values),
                expected,
                "input = {input:?}"
            );
        }
        Ok(())
    }
}

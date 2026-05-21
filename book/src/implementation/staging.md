# Staging Implementation

The [protocol chapter on staging](../protocol/extensions/staging.md) defines
the math: a trace polynomial $r(X)$ is decomposed into stage polynomials
$a(X), b(X), \ldots$ plus a final trace $r'(X)$, each independently
committable and each guaranteed well-formed by a [stage mask][stagemask].
This chapter walks through how that decomposition is realized in the
[`ragu_circuits`][ragu-circuits] crate — specifically the
[`Stage`][stage-trait], [`MultiStageCircuit`][multistage-trait],
[`StageBuilder`][stagebuilder-type], and [`StageGuard`][stageguard-type]
types in `crates/ragu_circuits/src/staging/`.

## Stages on the Rust side

A [`Stage`][stage-trait] declares a slice of the trace polynomial. Its
associated `OutputKind` names the gadget type the slice's wires populate;
its `witness` method produces an instance of that gadget. Stages define
no gate constraints of their own — the trace each commits to carries
only wire assignments, with well-formedness checked separately by a
bonding polynomial obtained via [`StageExt::mask`][stagemask].

A [`MultiStageCircuit`][multistage-trait] composes a sequence of stages
plus a final-trace body. Its `witness` method receives a
[`StageBuilder`][stagebuilder-type] together with the circuit's witness
value; stages are consumed from the builder one at a time. The trace
polynomial $r(X)$ is the sum of the stage polynomials plus the final
trace polynomial $r'(X)$ produced by the body.

## Two-phase builder pattern

[`StageBuilder`][stagebuilder-type] separates witness computation into two
phases so that all callers — prover, witness extractor, well-formedness
checker — agree on wire layout before any wire values are computed.

1. **Wire reservation.** Each call to [`configure_stage`][configure-stage]
   (or [`add_stage`][add-stage] for stages implementing `Default`) runs
   the stage's `witness` method on a wireless emulator only to count
   wires, then reserves that many non-overlapping wire positions at the
   correct offsets on the underlying driver. It returns a
   [`StageGuard`][stageguard-type] holding the reserved positions; no
   values are computed yet.

2. **Witness computation.** Once all stages are reserved,
   [`finish`][finish] yields the real driver, and each
   [`StageGuard`][stageguard-type] is consumed via
   [`enforced`][enforced-method] or [`unenforced`][unenforced-method]. The
   guard re-runs the stage's `witness` on a wireless emulator to obtain
   the gadget structure, then maps each emulator wire onto its reserved
   position via a stateful [`WireMap`][wiremap-trait].

## Gadget invariants

Even if gadgets are fungible (see the [fungibility section][fungibility]
of the gadget chapter), any driver that modifies the wires of a gadget
risks breaking one of their invariants. [`Stage::witness`][stage-witness]
only guarantees to produce a gadget with the correct shape, but the prover
could lie and produce one that does not satisfy the invariants.
When using [`unenforced`][unenforced-method], the caller takes the
prover at their word, possibly relying on a separate
[`enforced`][enforced-method] call elsewhere to enforce those invariants.
[`enforced`][enforced-method] provides only the guarantee that the gadget
is [`Consistent`][consistent-trait], which is only implemented for gadgets
that are capable of emitting constraints to re-express all of their
invariants.

The framework invokes [`Stage::witness`][stage-witness] only on stub
drivers. When called through [`StageBuilder`][stagebuilder-type] (wire
reservation and witness computation), the driver is a wireless
[`Emulator`][emulator] whose `gate`, `add`, and `enforce_zero` are all
no-ops, so anything the body writes to the supplied driver is
discarded. During polynomial extraction in
[`StageExt::rx`][stagemask-rx], `witness` runs on a wired
[`Emulator`][emulator] where `gate` and `add` execute to collect
values; `enforce_zero` remains a no-op, so any constraints the body
emits are still discarded.

## Worked example

A small example from `crates/ragu_circuits/src/staging/bonding.rs`
demonstrates the [`unenforced`][unenforced-method] case. `TwoWireStage` is
a stage that allocates two [`Element`][element-gadget]s with zero value:

```rust,ignore
impl Stage<Fp, R> for TwoWireStage {
    type OutputKind = /* ... two Elements ... */;
    fn values() -> usize { 2 }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self, dr: &mut D, _: DriverValue<D, ()>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>> {
        let w0 = Element::alloc(dr, &mut (), D::just(|| Fp::ZERO))?;
        let w1 = Element::alloc(dr, &mut (), D::just(|| Fp::ZERO))?;
        Ok(TwoWires { w0, w1 })
    }
}
```

When this runs inside the staging machinery, `Element::alloc` is invoked
on the wireless emulator. Whatever gate allocations or constraints
`alloc` would normally write are discarded. The returned `TwoWires`
gadget has wires mapped to the stage's reserved positions, but those
wires hold whatever the prover committed to the stage polynomial — not
necessarily zero.

[`Element`][element-gadget] conveys no wire invariants (any field value
is a valid `Element`), so its [`Consistent`][consistent-trait] impl is a
no-op anyway. The enclosing `MultiStageCircuit` therefore uses
[`unenforced`][unenforced-method] (skipping the no-op call) and emits the
actual constraint it cares about — `w0 == w1` — on the real driver from
[`finish`][finish]:

```rust,ignore
let dr = builder.finish();
let TwoWires { w0, w1 } = guard.unenforced(dr, D::unit())?;
dr.enforce_zero(|lc| lc.add(w0.wire()).sub(w1.wire()))?;
```

If the stage had returned, say, a [`Point`][point-gadget] instead of
[`Element`][element-gadget]s, [`enforced`][enforced-method] would have
been the correct choice: `Point`'s [`Consistent`][consistent-trait] impl
re-emits the curve equation on the real driver, restoring the type's
invariants on the prover-supplied wires. A custom `dr.enforce_zero(...)`
inside `TwoWireStage::witness` itself, however, would have been silently
dropped — only the post-stage real-driver work counts.

[ragu-circuits]: https://docs.rs/ragu_circuits/latest/ragu_circuits/
[stage-trait]: https://docs.rs/ragu_circuits/latest/ragu_circuits/staging/trait.Stage.html
[stage-witness]: https://docs.rs/ragu_circuits/latest/ragu_circuits/staging/trait.Stage.html#tymethod.witness
[multistage-trait]: https://docs.rs/ragu_circuits/latest/ragu_circuits/staging/trait.MultiStageCircuit.html
[stagebuilder-type]: https://docs.rs/ragu_circuits/latest/ragu_circuits/staging/struct.StageBuilder.html
[stageguard-type]: https://docs.rs/ragu_circuits/latest/ragu_circuits/staging/struct.StageGuard.html
[enforced-method]: https://docs.rs/ragu_circuits/latest/ragu_circuits/staging/struct.StageGuard.html#method.enforced
[unenforced-method]: https://docs.rs/ragu_circuits/latest/ragu_circuits/staging/struct.StageGuard.html#method.unenforced
[add-stage]: https://docs.rs/ragu_circuits/latest/ragu_circuits/staging/struct.StageBuilder.html#method.add_stage
[configure-stage]: https://docs.rs/ragu_circuits/latest/ragu_circuits/staging/struct.StageBuilder.html#method.configure_stage
[finish]: https://docs.rs/ragu_circuits/latest/ragu_circuits/staging/struct.StageBuilder.html#method.finish
[stagemask]: https://docs.rs/ragu_circuits/latest/ragu_circuits/staging/trait.StageExt.html#method.mask
[stagemask-rx]: https://docs.rs/ragu_circuits/latest/ragu_circuits/staging/trait.StageExt.html#method.rx
[wiremap-trait]: ragu_core::convert::WireMap
[emulator]: ragu_core::drivers::emulator::Emulator
[consistent-trait]: ragu_primitives::consistent::Consistent
[element-gadget]: ragu_primitives::Element
[point-gadget]: ragu_primitives::point::Point
[gadget-trait]: ragu_core::gadgets::Gadget
[fungibility]: ../guide/gadgets/index.md#fungibility

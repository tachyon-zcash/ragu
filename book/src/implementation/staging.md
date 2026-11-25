# Staging Implementation

The [protocol chapter on staging](../protocol/construction/staging.md) defines
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
mask obtained via [`StageExt::stage_mask`][stagemask].

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

The nested recursion circuits in `crates/ragu_pcd/src/internal/nested/`
load every one of their stages [`unenforced`][unenforced-method]. Two
circuits, `collapse` and `compute_v`, read the same twelve stages, and
both load them through one function. It reserves every stage, finishes
the builder, and injects each stage's gadget:

```rust,ignore
let (endoscalar, dr) = dr.add_stage::<EndoscalarStage>()?;
let (bridge_hash, dr) = dr.add_stage::<stages::bridge_hash::Stage<C>>()?;
let (points, dr) = dr.add_stage::<PointsStage<C, P>>()?;
// ... nine more stages ...
let dr = dr.finish();

let loaded = Loaded {
    endoscalar: endoscalar.unenforced(dr, witness.as_ref().map(|w| w.endoscalar))?,
    bridge_hash: bridge_hash.unenforced(dr, witness.as_ref().map(|w| w.bridge_hash))?,
    points: points.unenforced(dr, witness.as_ref().map(|w| w.points))?,
    // ...
};
```

The points stage's gadget holds [`Point`][point-gadget]s. When
`PointsStage::witness` runs inside the staging machinery it runs on the
wireless emulator, so whatever constraints allocating a point would
normally write are discarded. The returned gadget has wires mapped to
the stage's reserved positions, but those wires hold whatever the prover
committed to the stage polynomial, which need not be points of the
curve.

Loading the stage [`enforced`][enforced-method] would restore the
invariant: `Point`'s [`Consistent`][consistent-trait] impl re-emits the
curve equation on the real driver. Both circuits would then pay for it.
Instead `collapse` emits the contracts once, for the two stages that
have any, and `compute_v` relies on them:

```rust,ignore
let (dr, stages) = common::load_all(dr, &witness)?;

stages.points.enforce_consistent(dr)?;
stages.endoscalar.enforce_consistent(dr)?;
```

A relation between two stages is emitted the same way, on the real
driver from [`finish`][finish]. `collapse` holds each input of the points
stage equal to the copy a bridge stage carries:

```rust,ignore
for (input, held) in points.inputs.iter().zip(held) {
    input.enforce_equal(dr, held)?;
}
```

A `dr.enforce_zero(...)` inside a stage's own `witness`, however, would
have been silently dropped: only the post-stage real-driver work counts.

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
[stagemask]: https://docs.rs/ragu_circuits/latest/ragu_circuits/staging/trait.StageExt.html#method.stage_mask
[stagemask-rx]: https://docs.rs/ragu_circuits/latest/ragu_circuits/staging/trait.StageExt.html#method.rx
[wiremap-trait]: ragu_core::convert::WireMap
[emulator]: ragu_core::drivers::emulator::Emulator
[consistent-trait]: ragu_primitives::consistent::Consistent
[point-gadget]: ragu_primitives::point::Point
[gadget-trait]: ragu_core::gadgets::Gadget
[fungibility]: ../guide/gadgets/index.md#fungibility

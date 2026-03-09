# Conversion

Ragu often needs to substitute wires in a gadget, inspect its internal layout,
or move it from one [driver](../drivers/index.md) context to another. All of
these operations rely on a single visitor pattern.

Gadgets enable this with a provided [`map_gadget`][map-gadget-method] method
that traverses the gadget's own fields with the assistance of a (possibly
stateful) transformation. This produces a new gadget parameterized by a
different concrete driver, and [fungibility](index.md#fungibility) guarantees
that the result is a valid gadget of the same kind, with structure and semantics
preserved.

## [`WireMap`][wiremap-trait] {#wiremap}

The [`WireMap`][wiremap-trait] trait provides a pluggable strategy for these
conversions. Implementors fix a source and destination driver via associated
types and define a method for transforming wires between them one at a
time.[^drivertypes]

```rust,ignore
pub trait WireMap<F: Field> {
    type Src: DriverTypes<ImplField = F>;
    type Dst: DriverTypes<ImplField = F>;

    fn convert_wire(
        &mut self,
        wire: &<Self::Src as DriverTypes>::ImplWire,
    ) -> Result<<Self::Dst as DriverTypes>::ImplWire>;
}
```

The only type-level constraint is that source and destination drivers share the
same field `F`. [`GadgetKind::map_gadget`][map-gadget-method] performs the
actual traversal, walking the gadget's fields and dispatching each one according
to its kind. `Wire` fields go through [`convert_wire`][convert-wire],
`DriverValue` fields are reconstructed via [`Maybe::just`][maybe-just]
(preserving or discarding witness data according to the destination driver's
[`MaybeKind`][maybekind-trait]), and nested gadget fields recurse.

```admonish tip
The [`Gadget::map`][gadget-map] method is a convenience proxy for
[`map_gadget`][map-gadget-method]. [`WireMap`][wiremap-trait] also provides a
[`remap`][remap-method] shorthand for wire maps that implement [`Default`].
```

## Statefulness {#statefulness}

Some wire maps need only the wire itself, but others must remember where they
are in the traversal or accumulate results across calls. The mutable receiver
makes both cases possible without any external bookkeeping.

A concrete illustration is [`Gadget::num_wires`][num-wires-method], which
internally counts a gadget's wires by defining a single-purpose
[`WireMap`][wiremap-trait] whose [`convert_wire`][convert-wire] increments a
counter:

```rust,ignore
struct WireCounter<Src: DriverTypes> {
    count: usize,
    _marker: PhantomData<Src>,
}

impl<F: Field, Src: DriverTypes<ImplField = F>> WireMap<F>
    for WireCounter<Src>
{
    type Src = Src;
    type Dst = PhantomData<F>;

    fn convert_wire(&mut self, _: &Src::ImplWire) -> Result<()> {
        self.count += 1;
        Ok(())
    }
}
```

The counter's `Dst` is `PhantomData<F>`, whose wire type is `()`. The counter
discards every wire and keeps only the tally, and the resulting gadget is
discarded.

In contrast, wire injection during [staging](../../implementation/staging.md)
(another process internal to Ragu) feeds pre-allocated wires into specific
positions in the constraint trace, populating a gadget with those wires. The
[`WireMap`][wiremap-trait] for this operation is stateful so that it will yield
the next wire on each `convert_wire` call.

## [`CloneWires`][clonewires-type] {#clonewires}

[`CloneWires`][clonewires-type] is a pass-through conversion for drivers that
share the same wire type. Each wire is cloned unchanged, moving the gadget into
the destination driver's context:

```rust,ignore
let output: Bound<'dst, DstDriver, _> = CloneWires::remap(&gadget)?;
```

```admonish tip
This strategy is useful for [demotion][gadgetext-demote]. Internally, a demoted
gadget uses [`CloneWires`][clonewires-type] to preserve wires and strip witness
data. The corresponding [`promote`][demoted-promote] method allows the original
gadget to be restored.

<!-- TODO: When a demotion page is added to the book, let's rework this block. -->
```

## [`StripWires`][stripwires-type] {#stripwires}

[`StripWires`][stripwires-type] maps any driver's wires to `()`, producing a
gadget bound to a wireless [`Emulator`] with the same
[`MaybeKind`][maybekind-trait] as the source driver. This preserves witness
availability while stripping wire structure.

The primary use case is [routine prediction](../routines.md): routines receive
their input on a wireless emulator so they can compute predicted outputs
without a real synthesis context. [`StripWires`][stripwires-type] handles the
conversion from the caller's driver to that emulator automatically.

[^drivertypes]: `Src` and `Dst` are bounded by [`DriverTypes`][drivertypes-trait],
    not `Driver<'dr>`, so `WireMap` itself carries no lifetime parameter. The
    full `Driver<'dr>` bound is introduced on individual methods where the
    lifetime is actually needed. See
    [`DriverTypes`](../drivers/index.md#drivertypes) for more on this split.

[drivertypes-trait]: ragu_core::drivers::DriverTypes
[wiremap-trait]: ragu_core::convert::WireMap
[convert-wire]: ragu_core::convert::WireMap::convert_wire
[clonewires-type]: ragu_core::convert::CloneWires
[stripwires-type]: ragu_core::convert::StripWires
[remap-method]: ragu_core::convert::WireMap::remap
[map-gadget-method]: ragu_core::gadgets::GadgetKind::map_gadget
[gadget-map]: ragu_core::gadgets::Gadget::map
[num-wires-method]: ragu_core::gadgets::Gadget::num_wires
[maybe-just]: ragu_core::maybe::Maybe::just
[maybekind-trait]: ragu_core::maybe::MaybeKind
[`Default`]: core::default::Default
[`Emulator`]: ragu_core::drivers::emulator::Emulator
[gadgetext-demote]: ragu_primitives::GadgetExt::demote
[demoted-promote]: ragu_primitives::promotion::Demoted::promote

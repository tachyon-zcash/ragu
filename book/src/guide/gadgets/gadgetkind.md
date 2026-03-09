# [`GadgetKind`][gadgetkind-trait]

The [`Gadget`][gadget-trait] trait is defined as

```rust
pub trait Gadget<'dr, D: Driver<'dr>>: Clone {
    // ...
}
```

so that any concrete [`Gadget`][gadget-trait] must be parameterized by a
concrete [`Driver`][driver-trait]. But because gadgets can be transformed
between drivers, a higher-kinded interface is used to describe the
driver-agnostic type information and behavior of a gadget. This is done
through the [`GadgetKind<F>`][gadgetkind-trait] trait, which is defined as

```rust
pub unsafe trait GadgetKind<F: Field>: core::any::Any {
    type Rebind<'dr, D: Driver<'dr, F = F>>: Gadget<'dr, D, Kind = Self>;

    // ...
}
```

where the generic associated type `Rebind<'dr, D>` allows an implementation
of [`GadgetKind`][gadgetkind-trait] to specify how a concrete
[`Gadget`][gadget-trait] type can be obtained from a concrete
[`Driver`][driver-trait]. The [`Gadget`][gadget-trait] trait, in turn, has an
associated type `Kind` that relates back to its corresponding
[`GadgetKind`][gadgetkind-trait] implementation.

## The `Bound` Type Alias

The [`Bound<'dr, D, K>`][bound-alias] type alias is shorthand for
`<K as GadgetKind<F>>::Rebind<'dr, D>`.

## `map_gadget`

[`GadgetKind::map_gadget`](ragu_core::gadgets::GadgetKind::map_gadget)
translates a gadget from one driver to another, walking its fields and
converting wires and witness data to the destination driver. See
[Conversion](conversion.md) for details.

## `enforce_equal_gadget`

Gadgets offer the [`GadgetKind::enforce_equal_gadget`][enforce-equal] method to
specify how two instances are enforced to be equivalent. A gadget may provide a
specialized implementation that is more efficient than constraining
corresponding wires individually.

## Safety

Notice that the [`Gadget`][gadget-trait] trait is safe to implement, but the
[`GadgetKind`][gadgetkind-trait] trait is not. All gadgets must implement both
traits, but it is the [`GadgetKind`][gadgetkind-trait] trait that imposes a
memory-safety requirement on the types that implement it: gadgets must implement
`Send` if their wires are `Send` as well. This is impossible to express in
today's Rust type system, which is why the trait is `unsafe`.

```admonish warning
The `Send` requirement is the **only** safety invariant that
[`GadgetKind`][gadgetkind-trait] imposes.
[Fungibility](index.md#fungibility) — the requirement that gadget behavior
be fully determined by its type — is a separate correctness contract
documented on the [`Gadget`][gadget-trait] trait. Violating fungibility may
produce incorrect circuits but does not cause undefined behavior.
```

However, due to the complexity of the API contract we generally need to
[automatically derive](index.md#automatic-derivation) the
[`Gadget`][gadget-trait] and [`GadgetKind`][gadgetkind-trait] traits anyway.
The [`GadgetKind`][gadgetkind-trait] trait gives us the ability to stuff the
scary `unsafe` keyword into a corner of the API where users don't need to
see it.

[gadget-trait]: ragu_core::gadgets::Gadget
[gadgetkind-trait]: ragu_core::gadgets::GadgetKind
[bound-alias]: ragu_core::gadgets::Bound
[driver-trait]: ragu_core::drivers::Driver
[enforce-equal]: ragu_core::gadgets::GadgetKind::enforce_equal_gadget


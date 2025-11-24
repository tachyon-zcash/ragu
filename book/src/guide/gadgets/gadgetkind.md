# [`GadgetKind`][gadgetkind-trait]

The [`Gadget`][gadget-trait] trait is defined as

```rust
pub trait Gadget<'dr, D: Driver<'dr>>: Clone {
    // ...
}
```

so that any concrete [`Gadget`][gadget-trait] must be parameterized by a concrete [`Driver`][driver-trait]. But because gadgets can be transformed between drivers, a higher-kinded interface is used to describe the driver-agnostic type information and behavior of a gadget. This is done through the [`GadgetKind<F>`][gadgetkind-trait] trait, which is defined as

```rust
pub unsafe trait GadgetKind<F: Field>: core::any::Any {
    type Rebind<'dr, D: Driver<'dr, F = F>>: Gadget<'dr, D, Kind = Self>;

    // ...
}
```

where the generic associated type `Rebind<'dr, D>` allows an implementation of [`GadgetKind`][gadgetkind-trait] to specify how a concrete [`Gadget`][gadget-trait] type can be obtained from a concrete [`Driver`][driver-trait]. The [`Gadget`][gadget-trait] trait, in turn, has an associated type `Kind` that relates back to its corresponding [`GadgetKind`][gadgetkind-trait] implementation.

## `map_gadget`

Thanks to the strict requirements on implementations of [`Gadget`][gadget-trait], it is possible to [transform gadgets](index.md#transformations) between drivers. This is handled by the [`GadgetKind::map_gadget`](ragu_core::gadgets::GadgetKind::map_gadget) method implementation for every gadget, which simply translates the gadget's wires and witness information from one driver to another using the [`FromDriver`][fromdriver-trait] trait.

The [`Gadget::map`](ragu_core::gadgets::Gadget::map) is a proxy for its corresponding [`GadgetKind::map_gadget`](ragu_core::gadgets::GadgetKind::map_gadget) method.

## `enforce_equal_gadget`

Gadgets offer the [`GadgetKind::enforce_equal_gadget`](ragu_core::gadgets::GadgetKind::enforce_equal_gadget) method to specify how two instances can be enforced to be equivalent. In theory, a gadget can provide a more efficient implementation of this comparison than a generic method that simply creates linear constraints between two gadgets' wires.

## Safety

Notice that the [`Gadget`][gadget-trait] trait is safe to implement, but the [`GadgetKind`][gadgetkind-trait] trait is not. All gadgets must implement both traits, but it is the [`GadgetKind`][gadgetkind-trait] trait that imposes a memory-safety requirement on the types that implement it: gadgets should implement `Send` if their wires are `Send` as well. This is impossible to express in today's Rust type system, justifying the type.

However, due to the complexity of the API contract we generally need to [automatically derive](index.md#automatic-derivation) the [`Gadget`][gadget-trait] and [`GadgetKind`][gadgetkind-trait] traits anyway. The [`GadgetKind`][gadgetkind-trait] trait gives us the ability to stuff the scary `unsafe` keyword into a corner of the API where users don't need to see it. 🙂

[gadget-trait]: ragu_core::gadgets::Gadget
[gadgetkind-trait]: ragu_core::gadgets::GadgetKind
[driver-trait]: ragu_core::drivers::Driver
[fromdriver-trait]: ragu_core::drivers::FromDriver

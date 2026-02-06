# Gadgets

The [`Gadget`][gadget-trait] trait imposes a set of requirements supporting efficient circuit synthesis, to establish consistent expectations for [`Driver`][driver-trait]s.

Drivers may need to perform deep analysis of a gadget's constituent wires for various kinds of optimizations.
The primary boundary where these optimizations are applied involves the inputs and outputs of [routines](./routines.md).

Developers implementing a gadget will typically `#[derive(Gadget)]`.

## Gadgets must be fungible

A gadget's behavior during circuit synthesis must be stable. Drivers rely upon this expectation, and it is enforced by constraints at compile time.

**Gadgets containing only wires and driver values will automatically satisfy gadget fungibility.**

Wires within a gadget will use the driver's implementation of `Wire`, and witness values within a gadget will use the driver's implementaton of `DriverValue`. Other constraints are the responsibility of the gadget.

### Gadgets must be structurally invariant

A gadget's behavior during circuit synthesis must be fully determined by its type, not by any particular instance's state. This ensures deterministic synthesis and allows drivers to substitute or transform gadgets.

From this principle, three constraints follow:

1. **No dynamic-length collections.** The number of wires must be type-determined. Use [`FixedVec`][fixedvec-gadget] instead of `Vec`.

2. **No enum discriminants.** Which variant is active constitutes instance state that affects synthesis. Use `struct` to implement gadgets.

3. **No non-witness runtime state.** Any runtime data must be stable (identical across all instances of that type).

Wires are fungible by definition, and witness data cannot affect synthesis, so **gadgets containing only wires and driver values automatically satisfy these constraints**.

### Gadgets must be `Clone` and `Send`

Driver implementations may clone gadgets generically or send gadgets accross threads, so fields within a gadget must implement `Clone` and `Send`.

### Gadgets must satisfy `'static` lifetimes

Driver lifetime `'dr` may be `'static`, so fields within a gadget may be not be external references.

## Automatic Derivation

Due to the above constraints, gadgets can be derived automatically.

```rust
#[derive(Gadget)]
pub struct Boolean<'dr, D: Driver<'dr>> {
    #[ragu(wire)]
    wire: D::Wire,
    #[ragu(value)]
    value: DriverValue<D, bool>,
}
```

Use annotations to identify field types:

* **`#[ragu(wire)]`** - for wires of type `D::Wire`
* **`#[ragu(value)]`** - for witness values `T` of type `DriverValue<D, T>`
* **`#[ragu(phantom)]`** - for zero-sized markers like `PhantomData`
* **`#[ragu(gadget)]`** - for fields that are themselves gadgets _(default)_

**Fields without any annotation default to gadget fields.** If you mistakenly omit an annotation on another field, the compiler will produce a helpful error because those types don't implement `Gadget`.

## Transformations

Due to the above constraints, types that implement [`Gadget`][gadget-trait] can be transformed between drivers.

In order to transform a gadget from one driver to another, gadgets provide a [`map_gadget`][map-gadget-method] method implementation which uses [`FromDriver`][fromdriver-trait] to map a gadget's constituent wires and witness data to a new [`Driver`][driver-trait].

[fixedvec-gadget]: ragu_primitives::vec::FixedVec
[gadget-trait]: ragu_core::gadgets::Gadget
[driver-trait]: ragu_core::drivers::Driver
[map-gadget-method]: ragu_core::gadgets::GadgetKind::map_gadget
[fromdriver-trait]: ragu_core::drivers::FromDriver

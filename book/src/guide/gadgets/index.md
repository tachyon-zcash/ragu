# Gadgets

A **gadget** is the fundamental unit of all algorithms expressed as arithmetic circuits. It consists of a collection of _wires_, the _witness_ information required to reason about their possible assignments, and the _constraints_ that impose invariants over these assignments. Gadgets consolidate these components into an opaque type that guards how the underlying wires are manipulated and optimizes how their witness information is represented.

As an example, one of the simplest gadgets is the [`Boolean`][boolean-gadget] gadget which internally represents a wire that is constrained to be $0$ or $1$ together with the witness information (a `bool`) that describes its assignment. Wires always take the form of an associated type `D::Wire` based on the [driver](drivers.md) `D`, and so the `Boolean` gadget could be represented by the Rust structure:

```rust
pub struct Boolean<'dr, D: Driver<'dr>> {
    wire: D::Wire,
    value: DriverValue<D, bool>,
}
```

This structure acts as a guard type that ensures the underlying wire has been so-constrained, perhaps by a constructor function or another operation between `Boolean`s.

More sophisticated gadgets can exist which collect many wires together, preserve more complicated invariants between them and use a richer structure to encode their contents. One such gadget could be a `SpongeState`, which contains the far more complicated type:

```rust
pub struct SpongeState<'dr, D: Driver<'dr>, P: PoseidonPermutation<D::F>> {
    values: FixedVec<Element<'dr, D>, T<D::F, P>>,
}
```

This gadget is a _compositional_ gadget: it contains another gadget (a [`FixedVec`][fixedvec-gadget]) which is also _parameterized_ by another gadget (an [`Element`][element-gadget]).

## [`Gadget`][gadget-trait] trait

Gadgets usually can (and should) implement the [`Gadget`][gadget-trait] trait, which imposes a set of expectations and API requirements on the structure that is useful for efficient circuit synthesis. All implementations of this trait must satisfy a set of requirements:

* **They must be parameterized by a [`Driver`][driver-trait].** This is necessary for all gadgets, because gadgets contain wires and the wire type `D::Wire` depends on the driver `D`. It is also necessary because drivers vary in whether they expect witness information to be available, and so gadgets will contain types like `DriverValue<D, T>` to encode this optional information.
* **They must be fungible.** Gadgets must be interchangeable from one another from the perspective of circuit synthesis. In other words, two gadgets of the same type should not be discernable from one another, meaning they cannot be stateful. A gadget's wires are already fungible in this sense, as drivers do not guarantee that they can be distinguished. This fungibility property allows generic code that operates over a gadget to have a stable expectation of how gadgets can be manipulated and transformed between drivers.
    * One consequence of this requirement is that gadget types cannot contain a dynamic number of wires, and _generally_ cannot be `enum`s.
* **They must be thread-safe.** In particular, as described in the [documentation][gadget-thread-guarantees], everything within a gadget that is not a `D::Wire` should implement `Send`, so that when `D::Wire: Send` the entire gadget can cross thread boundaries safely. Because gadgets usually do not contain anything besides wires and witness data (which must be `Send` by the definition of [`Maybe<T: Send>`][maybe-trait]), this property almost always holds.
* **They must be `'static`.** Specifically, when the driver's lifetime `'dr` is the static lifetime `'static` the gadget itself must be `'static`. This property is guaranteed by the Rust type system, and so gadget implementations do not need to carefully reason about it. In general, this limitation also means that gadgets cannot contain references to anything else.
* **They must be `Clone`.** All gadgets should be cloneable. This is commonly necessary anyway, but drivers may need to clone gadgets generically when performing various transformations.

### Transformations

Due to the above guarantees, types that implement [`Gadget`][gadget-trait] can be transformed between drivers. This is very useful for implementations of drivers themselves, which may need to perform deep analysis of a gadget's constituent wires for various kinds of optimizations. The primary boundary where these optimizations are applied involves the inputs and outputs of [routines](routines.md).

In order to transform a gadget from one driver to another, gadgets provide a [`map_gadget`][map-gadget-method] method implementation which uses the [`FromDriver`][fromdriver-trait] to map a gadget's constituent wires and witness data to a new [`Driver`][driver-trait].

## Automatic Derivation

The above API contract is relatively complicated, but also very constraining over the possible types that can implement [`Gadget`][gadget-trait] safely and correctly. As a result, it is possible to automatically derive nearly all implementations of the [`Gadget`][gadget-trait] trait using a [procedural macro](macro@ragu_core::gadgets::GadgetKind).

The above example of `Boolean` can be rewritten as

```rust
#[derive(Gadget)]
pub struct Boolean<'dr, D: Driver<'dr>> {
    #[ragu(wire)]
    wire: D::Wire,
    #[ragu(value)]
    value: DriverValue<D, bool>,
}
```

where `#[ragu(...)]` annotations are used on fields to indicate whether the field is a `wire`, a `value` (witness data), a `gadget`, or a `phantom` ([marker type](core::marker::PhantomData)). The procedural macro provided by Ragu will automatically implement `Gadget` and `GadgetKind` as necessary.

[boolean-gadget]: ragu_primitives::Boolean
[spongestate-gadget]: ragu_primitives::SpongeState
[fixedvec-gadget]: ragu_primitives::vec::FixedVec
[element-gadget]: ragu_primitives::Element
[gadget-trait]: ragu_core::gadgets::Gadget
[gadgetkind-trait]: ragu_core::gadgets::GadgetKind
[driver-trait]: ragu_core::drivers::Driver
[gadget-thread-guarantees]: ragu_core::gadgets::GadgetKind#safety
[maybe-trait]: ragu_core::maybe::Maybe
[map-gadget-method]: ragu_core::gadgets::GadgetKind::map_gadget
[fromdriver-trait]: ragu_core::drivers::FromDriver

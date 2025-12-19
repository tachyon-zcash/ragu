# Gadgets

A **gadget** is the structural unit of all algorithms expressed as arithmetic
circuits. They usually consist of _wires_, the _witness_ information required to
reason about their possible assignments, and represent the _constraints_ that
impose invariants over these assignments. Gadgets consolidate these components
into an opaque type that guards how the underlying wires are manipulated and
optimizes how their witness information is represented.

As an example, one of the simplest gadgets is the [`Boolean`][boolean-gadget]
gadget which internally represents a wire that is constrained to be $0$ or $1$
together with the witness information (a `bool`) that describes its assignment.
Wires always take the form of an associated type `D::Wire` based on the
[driver](../drivers.md) `D`, and so the `Boolean` gadget could be represented by
the Rust structure:

```rust
pub struct Boolean<'dr, D: Driver<'dr>> {
    wire: D::Wire,
    value: DriverValue<D, bool>,
}
```

This structure acts as a guard type that ensures the underlying wire has been
so-constrained, perhaps by a constructor function or another operation between
`Boolean`s.

More sophisticated gadgets can exist which collect many wires together, preserve
more complicated invariants between them and use a richer structure to encode
their contents. One such gadget could be a `SpongeState`, which contains the far
more complicated type:

```rust
pub struct SpongeState<'dr, D: Driver<'dr>, P: PoseidonPermutation<D::F>> {
    values: FixedVec<Element<'dr, D>, T<D::F, P>>,
}
```

This gadget is a _compositional_ gadget: it contains another gadget (a
[`FixedVec`][fixedvec-gadget]) which is also _parameterized_ by another gadget
(an [`Element`][element-gadget]).

## [`Gadget`][gadget-trait] trait

Gadgets usually can (and should) implement the [`Gadget`][gadget-trait] trait,
which imposes a set of expectations and API requirements on the structure that
is useful for efficient circuit synthesis. All implementations of this trait
must satisfy a set of requirements:

* **They must be fungible.** A gadget's behavior during circuit synthesis must
  be fully determined by its type, not by any particular instance's state. This
  ensures that generic code operating on gadgets has stable expectations about
  how they can be manipulated and transformed between drivers.
    * From this principle follow three consequences:
        1. Gadgets cannot contain dynamic-length collections (use
           [`FixedVec`][fixedvec-gadget] with a compile-time [`Len`][len-trait]
           bound instead).
        2. Gadgets generally cannot be `enum`s (discriminants are instance
           state).
        3. Any non-witness runtime data must be _stable_ (identical across all
           instances).
    * Wires are fungible by definition, and witness data cannot affect
      synthesis, so gadgets containing only these automatically satisfy
      fungibility.
* **They must be thread-safe.** In particular, as described in the
  [documentation][gadget-thread-guarantees], everything within a gadget that is
  not a `D::Wire` should implement `Send`, so that when `D::Wire: Send` the
  entire gadget can cross thread boundaries safely. Because gadgets usually do
  not contain anything besides wires and witness data (which must be `Send` by
  the definition of [`Maybe<T: Send>`][maybe-trait]), this property almost
  always holds.
* **They must be `'static`.** Specifically, when the driver's lifetime `'dr` is
  the static lifetime `'static` the gadget itself must be `'static`. This
  property is guaranteed by the Rust type system, and so gadget implementations
  do not need to carefully reason about it. In general, this limitation also
  means that gadgets cannot contain references to anything else.
* **They must be `Clone`.** All gadgets should be cloneable. This is commonly
  necessary anyway, but drivers may need to clone gadgets generically when
  performing various transformations.

### Automatic Derivation

The above API contract is relatively complicated, but also very constraining
over the possible types that can implement [`Gadget`][gadget-trait] safely and
correctly. As a result, it is possible to automatically derive nearly all
implementations of the [`Gadget`][gadget-trait] trait using a [procedural
macro](macro@ragu_core::gadgets::GadgetKind).

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

The `#[derive(Gadget)]` macro uses `#[ragu(...)]` annotations to identify field
types:

* **`#[ragu(wire)]`** - for raw wires of type `D::Wire`
* **`#[ragu(value)]`** - for witness data of type `DriverValue<D, T>`
* **`#[ragu(phantom)]`** - for marker types like `PhantomData`
* **`#[ragu(gadget)]`** - for fields that are themselves gadgets _(optional)_

**Fields without any annotation default to gadget fields.** You only need explicit annotations when mixing gadgets with wires, values, or phantom types. If you mistakenly omit an annotation on a wire or value field, the compiler will produce a helpful error because those types don't implement `Gadget`.

[boolean-gadget]: ragu_primitives::Boolean
[spongestate-gadget]: ragu_primitives::poseidon::SpongeState
[fixedvec-gadget]: ragu_primitives::vec::FixedVec
[len-trait]: ragu_primitives::vec::Len
[element-gadget]: ragu_primitives::Element
[gadget-trait]: ragu_core::gadgets::Gadget
[gadgetkind-trait]: ragu_core::gadgets::GadgetKind
[driver-trait]: ragu_core::drivers::Driver
[gadget-thread-guarantees]: ragu_core::gadgets::GadgetKind#safety
[maybe-trait]: ragu_core::maybe::Maybe
[map-gadget-method]: ragu_core::gadgets::GadgetKind::map_gadget
[fromdriver-trait]: ragu_core::drivers::FromDriver

### Transformations

Due to the above guarantees, types that implement [`Gadget`][gadget-trait] can
be transformed between drivers. This is very useful for implementations of
drivers themselves, which may need to perform deep analysis of a gadget's
constituent wires for various kinds of optimizations. The primary boundary where
these optimizations are applied involves the inputs and outputs of
[routines](../routines.md).

In order to transform a gadget from one driver to another, gadgets provide a
[`map_gadget`][map-gadget-method] method implementation which uses the
[`FromDriver`][fromdriver-trait] to map a gadget's constituent wires and witness
data to a new [`Driver`][driver-trait].

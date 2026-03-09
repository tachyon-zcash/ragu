# Gadgets

Circuit code operates on wires and witness data, but working directly with them
leaves invariants implicit and spread across call sites. The structural units
that bundle these primitives and their constraints into self-contained types are
called **gadgets**.

As an example, one of the simplest gadgets is the [`Boolean`][boolean-gadget]
gadget which internally represents a wire that is constrained to be $0$ or $1$
together with the witness information (a `bool`) that describes its assignment.
Wires always take the form of an associated type `D::Wire` based on the
[driver](../drivers/index.md) `D`, and so the `Boolean` gadget could be
represented by the Rust structure:

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
more complicated invariants between them, or use a richer structure to encode
their contents. One such gadget could be a `SpongeState`, which contains the far
more complicated type:

```rust
pub struct SpongeState<'dr, D: Driver<'dr>, P: PoseidonPermutation<D::F>> {
    values: FixedVec<Element<'dr, D>, PoseidonStateLen<D::F, P>>,
}
```

This gadget is a _compositional_ gadget: it contains another gadget (a
[`FixedVec`][fixedvec-gadget]) which is also _parameterized_ by another gadget
(an [`Element`][element-gadget]).

## [`Gadget`][gadget-trait] trait {#fungibility}

The [`Gadget`][gadget-trait] trait captures the structural guarantees that
drivers rely on to [convert](conversion.md) gadgets between driver contexts
and optimize circuit synthesis. All implementations must satisfy the following
requirements:

* **They must be fungible.** A gadget's behavior during circuit synthesis must
  be fully determined by its type, not by any particular instance's state.
    * Among the consequences of this principle:
        1. Gadgets cannot contain dynamic-length collections (use
           [`FixedVec`][fixedvec-gadget] with a static [`Len`][len-trait]
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
  do not need to carefully reason about it. In practice, any references a gadget
  contains must be `'static`.
* **They must be `Clone`.** All gadgets should be cloneable. This is commonly
  necessary anyway, but drivers may need to clone gadgets generically when
  performing various transformations.

### `num_wires`

The [`Gadget`][gadget-trait] trait provides a [`num_wires`][num-wires-method]
method that returns the number of wires contained in a gadget instance. Because
gadgets are [fungible](#fungibility), this count is determined entirely by the
type—it is the same for every instance.

### Automatic Derivation {#automatic-derivation}

The requirements above constrain the space of valid implementations tightly
enough that nearly all [`Gadget`][gadget-trait] implementations can be
automatically derived using a
[procedural macro](macro@ragu_core::gadgets::GadgetKind).

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

Fields without any annotation default to gadget fields, so `#[ragu(gadget)]`
is only needed for clarity.

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
[num-wires-method]: ragu_core::gadgets::Gadget::num_wires

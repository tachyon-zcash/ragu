# Gadgets

Circuit code operates on wires, but working directly with them leaves invariants
implicit and spread across call sites. Gadgets are types that encapsulate wires
and the [witness data](../drivers/witness.md) used to compute their assignments.
Because the underlying types ([`Wire`], [`DriverValue`]) are defined by drivers,
gadget types are necessarily parameterized by a [`Driver`][driver-trait]. As
with all circuit code, gadgets must synthesize *deterministically*,
independently of the concrete driver.

Since witness types are driver-defined and their contents can only be extracted
by the driver, no gadget can convey invariants about witness information. In
contrast, while [`Wire`] types are also opaque handles defined by the driver,
gadgets *can* convey invariants about the constraints placed over their wires.

As an example, one of the simplest gadgets is the [`Boolean`][boolean-gadget]
gadget which internally represents a wire that is constrained to be $0$ or $1$
together with the witness data (a `bool`) that describes its assignment:

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

[`Gadget`][gadget-trait] is a trait for gadgets with a stricter property called
**fungibility**: for any two instances `a` and `b` of the same concrete gadget
type, substituting all of `a`’s wires into `b` must yield an instance
indistinguishable in all subsequent synthesis from `a`, carrying identical
invariants over their wires.

One of the direct consequences of fungibility is that a [`Gadget`][gadget-trait]
impl must always contain the same number of wires in every instance, and cannot
carry any additional state that would influence synthesis behavior. For example,
`Gadget`s usually cannot be `enum`s, and you must use `[G; N]` or
[`FixedVec`][fixedvec-gadget] for length-typed collections.

Fungibility permits drivers to [manipulate gadgets](conversion.md) for
optimization and analysis without disturbing the gadget's API contract.
Fortunately, most gadgets only contain wires, witness data and other gadgets,
and so they easily satisfy fungibility; [`Gadget`][gadget-trait] can be [automatically
derived](#automatic-derivation) for nearly all gadgets.

### Thread Safety

[`Gadget`][gadget-trait]s must also be thread-safe, as described in the
[documentation][gadget-thread-guarantees]: everything within a gadget that is
not a `D::Wire` should implement `Send`, so that when `D::Wire: Send` the entire
gadget can cross thread boundaries safely. This almost always holds because
gadgets usually contain only wires and witness data (which must be `Send` by
the definition of [`Maybe<T: Send>`][maybe-trait]).

When the driver's lifetime `'dr` is `'static`, the Rust type system also
guarantees that the gadget itself is `'static`.

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
[`Wire`]: ragu_core::drivers::Driver::Wire
[`DriverValue`]: ragu_core::drivers::DriverValue

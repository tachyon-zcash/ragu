# The [`Consistent`][consistent-trait] Trait

Gadgets act as guard types: they encapsulate wires and guarantee that certain
constraints hold over them. [`Boolean`] guarantees its wire is in $\{0, 1\}$;
[`Point`] guarantees the curve equation over its coordinate wires. These
invariants are what give the gadget its meaning—a [`Boolean`] _is_ the promise
that its wire is binary.

But some operations can undermine this guarantee.
[Conversion](conversion.md) can substitute a gadget's wires, replacing them
with new ones that may not carry the original constraints. After substitution,
the gadget still _looks_ like a [`Boolean`] or a [`Point`], but the constraint
that made it one may no longer apply to the new wires.

The [`Consistent`][consistent-trait] trait fills this gap. For drivers that
perform wire substitution, it lets a gadget reimpose its invariants on
whatever wires it currently holds.

## The Trait

```rust,ignore
pub trait Consistent<'dr, D: Driver<'dr>>: Gadget<'dr, D> {
    fn enforce_consistent(&self, dr: &mut D) -> Result<()>;
}
```

[`enforce_consistent`][enforce-consistent] reimposes the gadget's invariants
on its current wires.

Primitive gadgets—those that contain only wires and witness data, like
[`Element`]—have no internal invariants beyond their wire assignments.
Their [`enforce_consistent`][enforce-consistent] is a no-op: they are
consistent by construction.

Gadgets with structural invariants—like [`Boolean`]'s binary constraint or
[`Point`]'s curve equation—need to actually do work here. The typical strategy
is to allocate a fresh gadget from its witness values (allowing the constructor
to impose the invariant on the new wires) and then constrain the new wires to
equal the originals via `enforce_equal_gadget`. The invariant reaches the
original wires through this equality.

## `#[derive(Consistent)]`

Composite gadgets can derive [`Consistent`][consistent-trait] automatically.
The derive macro calls [`enforce_consistent`][enforce-consistent] on each
nested gadget field (those annotated with `#[ragu(gadget)]` or unannotated,
which default to gadget), and skips wire, value, and phantom fields:

```rust,ignore
#[derive(Gadget, Consistent)]
pub struct Element<'dr, D: Driver<'dr>> {
    #[ragu(wire)]
    wire: D::Wire,
    #[ragu(value)]
    value: DriverValue<D, D::F>,
}
```

Here, `Element` has no gadget fields, so the derived
[`enforce_consistent`][enforce-consistent] does nothing—it is a primitive
gadget that is consistent by default. A composite gadget like
[`SpongeState`]—which contains a [`FixedVec`] of [`Element`]s—would
recursively call [`enforce_consistent`][enforce-consistent] on that vector,
which in turn calls it on each element.

[consistent-trait]: ragu_core::gadgets::Consistent
[enforce-consistent]: ragu_core::gadgets::Consistent::enforce_consistent
[`Boolean`]: ragu_primitives::Boolean
[`Point`]: ragu_primitives::point::Point
[`Element`]: ragu_primitives::Element
[`SpongeState`]: ragu_primitives::poseidon::SpongeState
[`FixedVec`]: ragu_primitives::vec::FixedVec

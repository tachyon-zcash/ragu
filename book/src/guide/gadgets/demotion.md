# Demotion

Gadgets encapsulate wires and protect the invariants (constraints) that
govern them. Witness data is [`Driver`][driver-trait]-dependent, so a
gadget's wires and constraints must be the same whether witness data is
present or not; existing witness data is needed only when computing
assignment values for new wires.

It follows that every gadget can have its witness data stripped,
producing a [`Demoted`][demoted-type] gadget. Internally, demotion
uses [`CloneWires`][clonewires-type] to carry the wires into a
different driver context while discarding witness data. Composite
gadgets can sometimes store witness data more efficiently than their
individual constituents, so they can hold demoted versions of those
constituents and recover the original gadgets only when necessary to
create new wires.

Once demoted, some of the gadget's APIs are no longer available —
especially those that need to create new gates or constraints. To
use them, the gadget must be restored to its original form.
Restoration requires assistance from the gadget itself, since only
the gadget type knows how to reconstruct its fields from a demoted
handle and fresh witness data. Gadgets can opt into a shared
convention by implementing the [`Promotion`][promotion-trait]
trait, which declares the witness data needed to
[`promote`][demoted-promote] the gadget back into its original
form.

## Example: Endoscalar

The [`Endoscalar`][endoscalar-type] gadget represents a 128-bit binary
challenge string used in elliptic curve scalar multiplication. The
witness is a `u128`, but the individual bits must each be a
[`Boolean`][boolean-gadget] gadget so they can be referenced individually
in constraints. Storing 128 separate `Boolean`s — each carrying its own
bit-valued witness — would duplicate the data; the endoscalar holds them
demoted instead and reconstructs the per-bit witness from the `u128` on
demand.

Each bit is allocated, immediately demoted, and stored:

```rust,ignore
let bits = (0..u128::BITS as usize)
    .map(|i| {
        let bit_value = value.as_ref().map(|v| (*v >> i) & 1u128 == 1u128);
        let bit = Boolean::alloc(dr, &mut (), bit_value)?;
        bit.demote()
    })
    .try_collect_fixed()?;
```

When a consumer asks for an iterator over the bits, each demoted
handle is promoted back into a [`Boolean`][boolean-gadget] using the
corresponding bit extracted from the stored `u128`:

```rust,ignore
pub fn bits(&self) -> impl Iterator<Item = Boolean<'dr, D>> {
    let mut bits = self.value.as_ref().map(|v| {
        (0..(u128::BITS as usize)).map(move |i| (*v >> i) & 1u128 == 1u128)
    });

    self.bits.iter().map(move |demoted_bit| {
        demoted_bit.promote(bits.as_mut().map(|bits| bits.next().unwrap()))
    })
}
```

[`Boolean`][boolean-gadget] participates in this pattern by
implementing the [`Promotion`][promotion-trait] trait, declaring
`Value = bool` and the recipe for rebuilding the full gadget from a
demoted handle and a fresh `bool`. Any gadget can opt in the same
way.

[demoted-type]: ragu_primitives::promotion::Demoted
[promotion-trait]: ragu_primitives::promotion::Promotion
[demoted-promote]: ragu_primitives::promotion::Demoted::promote
[boolean-gadget]: ragu_primitives::Boolean
[endoscalar-type]: ragu_primitives::Endoscalar
[driver-trait]: ragu_core::drivers::Driver
[clonewires-type]: ragu_core::convert::CloneWires

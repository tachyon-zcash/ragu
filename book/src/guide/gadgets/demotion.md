# Demotion

Gadgets carry both wires and witness data, but sometimes only the
wires matter. Storing full witness data wastes memory and couples the
gadget to a specific [`MaybeKind`][maybekind-trait]. A gadget can
shed its witness data through **demotion**, retaining only its wire
structure. When witness data is needed again, the gadget is
**promoted** back to its full form on demand.

The key types are [`Demoted<G>`][demoted-type],
[`DemotedDriver`][demoteddriver-type],
[`GadgetExt::demote`][gadgetext-demote], and the
[`Promotion`][promotion-trait] trait.

## [`DemotedDriver`][demoteddriver-type] {#demoteddriver}

The type-level trick at the core of demotion is
[`DemotedDriver<D>`][demoteddriver-type]. It shares `D`'s wire type
([`ImplWire`][drivertypes-trait]) but sets
[`MaybeKind = Empty`][empty-type]. Because
[`Empty`][empty-type] discards all witness closures, a gadget bound
to `DemotedDriver<D>` retains its wires but carries no witness data.

`DemotedDriver` is never instantiated, all [`Driver`][driver-trait]
methods are `unreachable!()`. It exists purely as a type-level
adapter so that `Bound<'dr, DemotedDriver<D>, G::Kind>` type-checks
with wires intact but witness data erased:

```rust,ignore
impl<D: DriverTypes> DriverTypes for DemotedDriver<D> {
    type MaybeKind = Empty;
    type LCadd = ();
    type LCenforce = ();
    type ImplField = D::ImplField;
    type ImplWire = D::ImplWire;  // same wire type as D
}
```

## [`GadgetExt::demote`][gadgetext-demote] {#demote}

[`demote()`][gadgetext-demote] is a blanket method on all
[`Gadget`][gadget-trait] implementations, provided by the
[`GadgetExt`][gadgetext-trait] extension trait:

```rust,ignore
pub trait GadgetExt<'dr, D: Driver<'dr>>: Gadget<'dr, D> {
    fn demote(&self) -> Result<Demoted<'dr, D, Self>> {
        Demoted::new(self)
    }
}
```

Internally, [`Demoted::new`][demoted-type] uses
[`CloneWires`][clonewires-type] to clone wires from `D` into
`DemotedDriver<D>`. Because `DemotedDriver<D>` has `MaybeKind =
Empty`, the [`Maybe::just`][maybe-just] calls during
[conversion](conversion.md) discard all witness data automatically.

The returned [`Demoted<'dr, D, G>`][demoted-type] wraps a
`Bound<'dr, DemotedDriver<D>, G::Kind>` and implements
[`Deref`][deref-trait], so callers can read the inner gadget's
wire fields directly through the demoted wrapper.

```admonish warning
[`Demoted`][demoted-type] intentionally does not implement
[`Consistent`][consistent-trait]. A demoted gadget has no witness
data, so it cannot meaningfully enforce consistency. Promote the
gadget first, then call `enforce_consistent` on the result.
```

## The [`Promotion`][promotion-trait] Trait {#promotion}

Promotion is opt-in per [`GadgetKind`][gadgetkind-trait]. A kind
that implements [`Promotion<F>`][promotion-trait] declares the
witness data type needed to restore a demoted gadget:

```rust,ignore
pub trait Promotion<F: Field>: GadgetKind<F> {
    type Value: Send;

    fn promote<'dr, D: Driver<'dr, F = F>>(
        demoted: &Demoted<'dr, D, Bound<'dr, D, Self>>,
        witness: DriverValue<D, Self::Value>,
    ) -> Bound<'dr, D, Self>;
}
```

[`Demoted::promote`][demoted-promote] delegates to the trait
implementation. For example, [`Boolean`][boolean-gadget]'s
`Promotion` impl takes a `bool` as its `Value` and reconstructs
the gadget by cloning the existing wire and pairing it with
fresh witness data:

```rust,ignore
impl<F: Field> Promotion<F> for Kind![F; @Boolean<'_, _>] {
    type Value = bool;

    fn promote<'dr, D: Driver<'dr, F = F>>(
        demoted: &Demoted<'dr, D, Boolean<'dr, D>>,
        witness: DriverValue<D, bool>,
    ) -> Boolean<'dr, D> {
        Boolean {
            wire: demoted.wire.clone(),
            value: witness,
        }
    }
}
```

## Example: [`Endoscalar`][endoscalar-type] {#endoscalar-example}

The [`Endoscalar`][endoscalar-type] gadget demonstrates the full
demotion lifecycle. An endoscalar represents a binary challenge string
used for efficient elliptic curve scalar multiplication. Its bits are
[`Boolean`][boolean-gadget] gadgets, but they only need witness data
at the moment they are consumed, not while they are stored.

During allocation, each bit is demoted immediately after construction
and stored compactly in a
[`FixedVec<Demoted<Boolean>>`][fixedvec-gadget]:

```rust,ignore
let bits = (0..Uendo::BITS as usize)
    .map(|i| {
        let bit = Boolean::alloc(dr, /* witness */ )?;
        Demoted::new(&bit)  // strip witness, keep wire
    })
    .try_collect_fixed()?;
```

Later, when the bits are actually needed (e.g. during
[`group_scale`][endoscalar-type]), each demoted bit is promoted with
fresh witness data on demand:

```rust,ignore
pub fn bits(&self) -> impl Iterator<Item = Boolean<'dr, D>> {
    self.bits.iter().map(move |demoted_bit| {
        demoted_bit.promote(/* fresh witness */)
    })
}
```

This is **lazy witness restoration**: the gadget pays for witness data
only when it is consumed. Between allocation and consumption, the bits
exist as lightweight wire-only handles.

## `Demoter` Wire Map {#demoter}

Demoted gadgets can also cross driver boundaries, for example,
when a circuit moves wires from one driver context to another.
When [`Demoted`][demoted-type] gadgets cross driver boundaries via
[`DemotedKind::map_gadget`][demotedkind-type], the inner
[`WireMap`][wiremap-trait] must operate in demoted-driver space.
`Demoter` wraps an existing [`WireMap`][wiremap-trait]
and delegates [`convert_wire`][convert-wire] to it, presenting
`DemotedDriver<Src>` and `DemotedDriver<Dst>` as the source and
destination types. See the [Conversion](conversion.md) page for
background on wire maps.

## When to Demote {#when-to-demote}

Demotion is useful when you need a gadget's wire structure but not its
witness data:

- **Compact storage**: store gadgets without witness overhead, as
  [`Endoscalar`][endoscalar-type] does with its bits.
- **Cross-driver transfer**: move gadgets across driver boundaries
  without coupling to a specific [`MaybeKind`][maybekind-trait].
- **Wire-only routines**: pass gadgets to code that inspects wire
  layout but never evaluates witness closures.

```admonish info
Demotion preserves wires and discards witness data.
[`StripWires`][stripwires-type] does the opposite: it discards wires
(mapping them to `()`) and preserves witness availability. Choose
based on which half of the gadget you need to keep.
```

[Routines](../routines.md) rely on demotion when they need to
store or transfer gadgets without carrying witness data.

[demoted-type]: ragu_primitives::promotion::Demoted
[demoteddriver-type]: ragu_primitives::promotion::DemotedDriver
[demotedkind-type]: ragu_primitives::promotion::DemotedKind
[promotion-trait]: ragu_primitives::promotion::Promotion
[demoted-promote]: ragu_primitives::promotion::Demoted::promote
[gadgetext-trait]: ragu_primitives::GadgetExt
[gadgetext-demote]: ragu_primitives::GadgetExt::demote
[boolean-gadget]: ragu_primitives::Boolean
[endoscalar-type]: ragu_primitives::Endoscalar
[fixedvec-gadget]: ragu_primitives::vec::FixedVec
[gadget-trait]: ragu_core::gadgets::Gadget
[gadgetkind-trait]: ragu_core::gadgets::GadgetKind
[consistent-trait]: ragu_primitives::consistent::Consistent
[driver-trait]: ragu_core::drivers::Driver
[drivertypes-trait]: ragu_core::drivers::DriverTypes
[clonewires-type]: ragu_core::convert::CloneWires
[stripwires-type]: ragu_core::convert::StripWires
[wiremap-trait]: ragu_core::convert::WireMap
[convert-wire]: ragu_core::convert::WireMap::convert_wire
[maybekind-trait]: ragu_core::maybe::MaybeKind
[empty-type]: ragu_core::maybe::Empty
[maybe-just]: ragu_core::maybe::Maybe::just
[deref-trait]: core::ops::Deref

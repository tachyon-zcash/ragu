# Gadgets

[`Gadget`][gadget-trait]s are Ragu's internal abstraction for some circuits composed to represent a meaningful purpose.

**Users of Ragu won't typically write gadgets.** Users should prefer to import [available gadgets](./available-gadgets.md) and refer to them with `Kind!` when implementing `Header` and `Step`.

A few examples are:

- [`Element`][element-gadget] representing an unconstrained value
- [`Boolean`][boolean-gadget] representing a value constrained to 0 or 1
- [`FixedVec`][fixedvec-gadget] implementing a collection
- [`SpongeState`][spongestate-gadget] implementing a Poseidon hash

See [Gadget Implementation](../implementation/gadgets.md) for more details on gadget internals.

## Gadget, Kind, and GadgetKind

Each `Gadget` has an associated `Gadget::Kind` implementing `GadgetKind`.

The `Gadget::Kind` associated type is used when referring to the gadget in a `Header` or `Step` implementation.

Writing out the fully-qualified type is verbose, so the `Kind!` macro is provided.

### Use the `Kind!` macro

Use placeholder parameters of `'_` and `_` to satisfy the gadget lifetime and driver type.

```rust
impl Header<F> for MyHeader {
    type Output = Kind![F; Element<'_, _>]; 
    /* ... */
}
```

#### More `Kind!` Examples

```rust
Kind![F; Boolean<'_, _>]                      // boolean gadget
Kind![F; (Element<'_, _>, Boolean<'_, _>)]    // tuple of two gadgets
Kind![F; FixedVec<Element<'_, _>, N>]         // fixed-length vector gadget
```

#### Unqualified `Kind!`

In some contexts (like the `Self` type of an impl) the expanded macro may refuse to compile, even though no actual constraints are violated.

**If your `Kind!` fails to compile**, you may prefix with `@` to instruct the macro to expand without qualification:

```rust
Kind![F; @Element<'_, _>]
```

[gadget-trait]: ragu_core::gadgets::Gadget
[boolean-gadget]: ragu_primitives::Boolean
[element-gadget]: ragu_primitives::Element
[spongestate-gadget]: ragu_primitives::SpongeState
[fixedvec-gadget]: ragu_primitives::FixedVec

# Gadgets

[`Gadget`][gadget-trait]s are Ragu's abstraction for data types that contain wires and witness values, representing meaningful circuit components.

**Users implementing applications will typically define their own gadgets** using `#[derive(Gadget)]` to compose primitive gadgets into domain-specific types. For example, an RSA signature verification might define `PublicKey` and `Signature` gadgets built on [`Element`][element-gadget].

Ragu provides several primitive gadgets:

- [`Element`][element-gadget] - an unconstrained field element
- [`Boolean`][boolean-gadget] - a value constrained to 0 or 1
- [`FixedVec`][fixedvec-gadget] - a fixed-length collection
- [`SpongeState`][spongestate-gadget] - Poseidon hash state

See the [rustdoc for `Gadget`][gadget-trait] for comprehensive trait documentation, and [Gadget Implementation](../implementation/gadgets.md) for implementation details.

## Gadget, Kind, and GadgetKind

Each `Gadget` has an associated `Gadget::Kind` implementing `GadgetKind`.

**Why GadgetKind?** The `GadgetKind` trait is driver-agnostic, allowing the same gadget structure to be transformed between different drivers. This enables transforming `Gadget<DriverA>` into `Gadget<DriverB>` while preserving the same structure—critical for Ragu's multi-driver architecture where circuits are processed by different drivers (e.g., `SXY` for synthesis, `RX` for witness generation).

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

# `Kind!` Macro

It is sometimes necessary to specify a gadget's type in the form of its [`GadgetKind`][gadgetkind-trait] implementation, rather than its [`Gadget`][gadget-trait] implementation. However, the `Gadget` signature is the more natural and ergonomic form of a gadget's type. The [`Kind!`][kind-macro] macro simplifies describing the `GadgetKind` type by allowing the `Gadget` form to be written instead, using a procedural macro to perform the substitution.

## Example

The [`Boolean`][boolean-gadget] gadget implements `Gadget<'dr, D: Driver<'dr>>` for `Boolean<'dr, D>`. Thanks to the fact that `PhantomData<F: Field>` implements `Driver<'_>`, we thus have that `<Boolean<'static, PhantomData<F>> as Gadget<'static, PhantomData<F>>>::Kind` is the fully qualified syntax for describing the `GadgetKind` of `Boolean` given some concrete field type `F`. This generalizes to all `Gadget` implementations.

The [`Kind!`][kind-macro] macro simplifies this, allowing you to write `Kind![F; Boolean<'_, _>]`. The first argument `F` is used to denote the field type and the second argument denotes the type for substitution of the above fully qualified expansion. The `'_` symbol denotes the driver's lifetime (substituted with `'static`) and the `'_` symbol denotes the driver (substituted with `PhantomData<F>`).

### Unqualified Expansion

In some cases, this fully qualified syntax can cause bizarre coherence violations in the Rust compiler due to annoying limitations of the language's type system. Because types that automatically derive [`Gadget`][gadget-trait] also implement `GadgetKind<F>` by implementing it for e.g. `Boolean<'static, PhantomData<F>>`, the syntax `Kind![F; @Boolean<'_, _>]` can be used to perform this substitution without the fully qualified syntax, while still refering to the exact same type.

[boolean-gadget]: ragu_primitives::Boolean
[gadget-trait]: ragu_core::gadgets::Gadget
[gadgetkind-trait]: ragu_core::gadgets::GadgetKind
[driver-trait]: ragu_core::drivers::Driver
[fromdriver-trait]: ragu_core::drivers::FromDriver
[kind-macro]: ragu_core::gadgets::Kind

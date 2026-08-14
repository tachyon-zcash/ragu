//! # `ragu_macros`
//!
//! This crate contains some procedural macros for the Ragu project. These
//! macros are re-exported in other crates and so this crate is only intended to
//! be used internally by Ragu.

#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![doc(html_favicon_url = "https://tachyon.z.cash/assets/ragu/v1/favicon-32x32.png")]
#![doc(html_logo_url = "https://tachyon.z.cash/assets/ragu/v1/rustdoc-128x128.png")]

mod derive;
mod helpers;
mod path_resolution;
mod proc;
mod substitution;

use helpers::macro_body;
use proc_macro::TokenStream;
#[cfg(test)]
#[allow(unused_imports)]
use ragu_arithmetic::repr256 as _;
use syn::{DeriveInput, ItemEnum, ItemStruct, LitInt, parse_macro_input};

// Documentation for the `repr256` macro is in `macro@ragu_arithmetic::repr256`.
#[allow(missing_docs)]
#[proc_macro]
pub fn repr256(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as LitInt);
    macro_body(|| proc::repr::evaluate(input))
}

#[cfg(test)]
#[allow(unused_imports)]
use ragu_core::gadgets::Kind as _;

// Documentation for the `gadget_kind` macro is in `macro@ragu_core::gadgets::Kind`.
#[allow(missing_docs)]
#[proc_macro]
pub fn gadget_kind(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as proc::kind::Input);
    macro_body(|| {
        let ragu_core_path = path_resolution::RaguCorePath::resolve()?;
        proc::kind::evaluate(input, ragu_core_path)
    })
}

#[cfg(test)]
#[allow(unused_imports)]
use ragu_core::gadgets::Gadget as _;

// Documentation for the `Gadget` derive macro is in `derive@ragu_core::gadgets::Gadget`.
#[allow(missing_docs)]
#[proc_macro_derive(Gadget, attributes(ragu))]
pub fn derive_gadget(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    macro_body(|| {
        let ragu_arithmetic_path = path_resolution::RaguArithmeticPath::resolve()?;
        let ragu_core_path = path_resolution::RaguCorePath::resolve()?;
        derive::gadget::derive(input, ragu_arithmetic_path, ragu_core_path)
    })
}

#[cfg(test)]
#[allow(unused_imports)]
use ragu_primitives::io::Write as _;

// Documentation for the `Write` derive macro is in `derive@ragu_primitives::io::Write`.
#[allow(missing_docs)]
#[proc_macro_derive(Write, attributes(ragu))]
pub fn derive_write(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    macro_body(|| {
        let ragu_arithmetic_path = path_resolution::RaguArithmeticPath::resolve()?;
        let ragu_core_path = path_resolution::RaguCorePath::resolve()?;
        let ragu_primitives_path = path_resolution::RaguPrimitivesPath::resolve()?;
        derive::gadgetwrite::derive(
            input,
            ragu_arithmetic_path,
            ragu_core_path,
            ragu_primitives_path,
        )
    })
}

#[cfg(test)]
#[allow(unused_imports)]
use ragu_primitives::consistent::Consistent as _;

// Documentation for the `Consistent` derive macro is in `derive@ragu_primitives::consistent::Consistent`.
#[allow(missing_docs)]
#[proc_macro_derive(Consistent, attributes(ragu))]
pub fn derive_consistent(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    macro_body(|| {
        let ragu_core_path = path_resolution::RaguCorePath::resolve()?;
        let ragu_primitives_path = path_resolution::RaguPrimitivesPath::resolve()?;
        derive::consistent::derive(input, ragu_core_path, ragu_primitives_path)
    })
}

#[cfg(test)]
#[allow(unused_imports)]
use ragu_primitives::comparison::GadgetEquals as _;

// Documentation for the `GadgetEquals` derive macro is in `derive@ragu_primitives::comparison::GadgetEquals`.
#[allow(missing_docs)]
#[proc_macro_derive(GadgetEquals, attributes(ragu))]
pub fn derive_gadget_equals(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    macro_body(|| {
        let ragu_arithmetic_path = path_resolution::RaguArithmeticPath::resolve()?;
        let ragu_core_path = path_resolution::RaguCorePath::resolve()?;
        let ragu_primitives_path = path_resolution::RaguPrimitivesPath::resolve()?;
        derive::gadgetequals::derive(
            input,
            ragu_arithmetic_path,
            ragu_core_path,
            ragu_primitives_path,
        )
    })
}

#[cfg(test)]
#[allow(unused_imports)]
use ragu_pcd as _;

/// Attribute macro for defining a PCD application.
///
/// Generates `ragu_pcd::Header` impls (with `const SUFFIX`),
/// `ragu_pcd::Step` impls (with `const INDEX`), and a wrapper struct
/// with `build()`/`seed()`/`fuse()`/`verify()`/`rerandomize()` methods.
///
/// The enum carries no generics — the macro supplies `<'params, C: Cycle>`
/// itself. Each variant is a unit variant naming a step type (which must
/// take `<'params, C: Cycle>` generics), annotated with
/// `#[produces(OutputHeader)]`.
/// The generated wrapper's proof methods are sealed to those declared steps
/// and their headers, so a step or PCD from another application cannot be used
/// merely because its numeric index or suffix collides.
/// The trivial header `()` is the one deliberate exception to the seal: every
/// application accepts trivial PCDs as placeholder inputs, so a trivial PCD
/// minted by a different application type-checks and is instead rejected at
/// runtime, by verification against this application's circuit registry.
///
/// # Attributes
///
/// `header_size` fixes the application's encoded header width. Optional cycle
/// and rank defaults let applications be used without turbofish:
///
/// - `header_size` (required): fixed encoded width for every header, including
///   one suffix element. It must be at least 1 and large enough for every
///   header encoding.
/// - `cycle`: default for the `C: Cycle` parameter.
/// - `rank`: default for the `__R: Rank` parameter.
///
/// If repeated outputs name one header through aliases or different paths,
/// choose one spelling with
/// `#[produces(OutputAlias, canonical = CanonicalOutput)]`. The macro uses the
/// canonical spelling for suffix deduplication and asks rustc to prove that it
/// is exactly the same type as `OutputAlias`.
///
/// Defaulted generic parameters must be trailing, so `cycle` requires `rank`.
///
/// Doc comments, lint attributes, `#[must_use]`, and `#[deprecated]` on the
/// enum are forwarded to the generated wrapper. Other enum attributes are
/// rejected because they cannot be applied consistently to the complete macro
/// expansion; to configure an application with `#[cfg]`, place it in a
/// cfg-gated module. Variants accept only `#[produces(...)]` and cannot have
/// explicit discriminants because their indices come from declaration order.
/// Variant names must also produce unique, non-keyword snake_case `build()`
/// parameter names and cannot produce the reserved name `params`.
///
/// # Headers belong to one application
///
/// The macro writes the `Header` impl for every type named by
/// `#[produces(...)]`, so a header type can be claimed by only one
/// `#[application]` in a crate. Naming one from two applications produces a
/// conflicting-implementation error (`E0119`) pointing at the generated impls
/// rather than at the declarations; give each application its own header types,
/// or move the shared one behind a single application that both depend on.
///
/// `()` cannot be produced at all: it is the framework's trivial header, whose
/// suffix marks a proof as a recursion base case. A step that produces no
/// meaningful state should declare its own empty header, which is assigned an
/// ordinary suffix.
///
/// # Declaration order is significant
///
/// Suffixes are assigned to headers in order of first appearance across
/// `#[produces(...)]`, and step indices follow variant order. Both are baked
/// into the circuits, so reordering variants — or introducing a new header
/// ahead of existing ones — renumbers them. Proofs are not portable across such
/// a change, and today are not portable across builds at all, so this matters
/// when proofs begin to be persisted or exchanged between peers.
///
/// # Example
///
/// ```ignore
/// #[application(cycle = Pasta, rank = ProductionRank, header_size = 4)]
/// pub enum MerkleTree {
///     #[produces(LeafNode)]
///     WitnessLeaf,
///
///     #[produces(InternalNode)]
///     Hash2,
/// }
///
/// // The defaults fill in the wrapper's generics — no turbofish needed:
/// let app: MerkleTree = MerkleTree::build(params, witness_leaf, hash2)?;
/// ```
#[proc_macro_attribute]
pub fn application(attr: TokenStream, input: TokenStream) -> TokenStream {
    let attr = parse_macro_input!(attr as proc::application::ApplicationAttr);
    let input = parse_macro_input!(input as ItemEnum);
    macro_body(|| proc::application::evaluate(attr, input))
}

/// Attribute macro for generating single-gadget `HeaderContent` implementations.
///
/// For headers where `encode()` allocates a single gadget directly from
/// witness data, this macro generates the full `HeaderContent` implementation.
///
/// # Attributes
///
/// - `data`: The witness data type (required). When `field` is omitted, this
///   must be a bare type-parameter name such as `F`.
/// - `gadget`: The gadget type to allocate (required).
/// - `field`: The field type for a concrete impl (optional; when omitted,
///   `data` is used as a generic field type parameter).
/// - `alloc`: Set to `direct` when the gadget's `alloc` constructor takes no
///   allocator (optional; by default the generated `encode()` passes its
///   allocator through to `alloc`).
///
/// The gadget type must follow Ragu's `Gadget<'dr, D, ...>` parameter order;
/// write only any additional parameters in the attribute.
///
/// # Example
///
/// ```ignore
/// // Generic: F is both the field type and the witness data type
/// #[header(data = F, gadget = Element)]
/// pub struct LeafNode;
///
/// // Concrete: data is a curve point, field is explicit, and Point::alloc
/// // takes no allocator
/// #[header(data = EpAffine, gadget = Point<EpAffine>, field = Fp, alloc = direct)]
/// pub struct ScaledPoint;
/// ```
#[proc_macro_attribute]
pub fn header(attr: TokenStream, input: TokenStream) -> TokenStream {
    let attr = parse_macro_input!(attr as proc::header::HeaderAttr);
    let input = parse_macro_input!(input as ItemStruct);
    macro_body(|| proc::header::evaluate(attr, input))
}

#[cfg(test)]
#[allow(unused_imports)]
use ragu_core::maybe::MaybeCast as _;

/// Generate `ragu_core::maybe::MaybeCast` implementations for tuples of sizes 2
/// through a given maximum size (inclusive).
///
/// # Example
/// `ragu_macros::impl_maybe_cast_tuple!(4);` generates implementations for
/// tuples of sizes 2, 3, and 4.
#[proc_macro]
pub fn impl_maybe_cast_tuple(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as LitInt);
    macro_body(|| proc::maybe_cast::evaluate(input))
}

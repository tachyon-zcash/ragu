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

use proc_macro::TokenStream;
use syn::{DeriveInput, ItemMod, LitInt, parse_macro_input};

use helpers::macro_body;

#[cfg(test)]
#[allow(unused_imports)]
use ragu_arithmetic::repr256 as _;

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
        let ragu_core_path = path_resolution::RaguCorePath::resolve()?;
        derive::gadget::derive(input, ragu_core_path)
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
        let ragu_core_path = path_resolution::RaguCorePath::resolve()?;
        let ragu_primitives_path = path_resolution::RaguPrimitivesPath::resolve()?;
        derive::gadgetwrite::derive(input, ragu_core_path, ragu_primitives_path)
    })
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

/// Define a PCD application with declarative step and header definitions.
///
/// This attribute macro transforms a module containing `#[step]` and `#[header]`
/// annotated structs into a complete application definition with:
/// - Generated `Header<F>` trait implementations for headers
/// - Generated `Step<C>` trait implementations for steps
/// - A `build()` function that registers all steps with `ApplicationBuilder`
///
/// # Example
///
/// ```ignore
/// #[define_application]
/// pub mod my_app {
///     use super::*;
///
///     #[header(data = F, output = Element<'_, _>)]
///     pub struct LeafNode;
///
///     #[step(witness = C::CircuitField, aux = C::CircuitField, left = (), right = (), output = LeafNode)]
///     pub struct WitnessLeaf<'params, C: Cycle> {
///         poseidon_params: &'params C::CircuitPoseidon,
///     }
/// }
/// ```
///
/// Users must implement:
/// - `Header::encode(dr, witness)` as an inherent method on header structs
/// - `Step::witness((dr, witness, left, right))` as an inherent method on step structs
/// - `Step::new(params)` constructor for each step
#[proc_macro_attribute]
pub fn define_application(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as ItemMod);
    macro_body(|| {
        let ragu_arithmetic_path = path_resolution::RaguArithmeticPath::resolve()?;
        let ragu_circuits_path = path_resolution::RaguCircuitsPath::resolve()?;
        let ragu_core_path = path_resolution::RaguCorePath::resolve()?;
        let ragu_pcd_path = path_resolution::RaguPcdPath::resolve()?;
        proc::application::evaluate(
            input,
            ragu_arithmetic_path,
            ragu_circuits_path,
            ragu_core_path,
            ragu_pcd_path,
        )
    })
}

//! # `ragu_macros`
//!
//! This crate contains some procedural macros for the Ragu project. These
//! macros are re-exported in other crates and so this crate is only intended to
//! be used internally by Ragu.

#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![doc(html_favicon_url = "https://seanbowe.com/ragu_assets/icons/v1_favicon32.png")]
#![doc(html_logo_url = "https://seanbowe.com/ragu_assets/icons/v1_rustdoc128.png")]

use proc_macro::TokenStream;
use syn::{DeriveInput, Error, LitInt, parse_macro_input};

mod gadget;
mod gadget_serialize;
mod helpers;
mod kind;
mod repr;

// Documentation for the `repr256` macro is in `macro@ragu_arithmetic::repr256`.
#[allow(missing_docs)]
#[proc_macro]
pub fn repr256(input: TokenStream) -> TokenStream {
    repr::evaluate(parse_macro_input!(input as LitInt))
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

// Documentation for the `gadget_kind` macro is in `macro@ragu_core::gadgets::Kind`.
#[allow(missing_docs)]
#[proc_macro]
pub fn gadget_kind(input: TokenStream) -> TokenStream {
    let ragu_core_path = helpers::ragu_core_path();
    let ragu_core_path = if let Err(e) = ragu_core_path {
        return e.into_compile_error().into();
    } else {
        ragu_core_path.unwrap()
    };

    kind::evaluate(parse_macro_input!(input as kind::Input), ragu_core_path)
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

// Documentation for the `Gadget` derive macro is in `derive@ragu_core::Gadget`.
#[allow(missing_docs)]
#[proc_macro_derive(Gadget, attributes(ragu))]
pub fn derive_gadget(input: TokenStream) -> TokenStream {
    let ragu_core_path = helpers::ragu_core_path();
    let ragu_core_path = if let Err(e) = ragu_core_path {
        return e.into_compile_error().into();
    } else {
        ragu_core_path.unwrap()
    };
    gadget::derive(parse_macro_input!(input as DeriveInput), ragu_core_path)
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

// Documentation for the `GadgetSerialize` derive macro is in `derive@ragu_primitives::serialize::GadgetSerialize`.
#[allow(missing_docs)]
#[proc_macro_derive(GadgetSerialize, attributes(ragu))]
pub fn derive_gadget_serialize(input: TokenStream) -> TokenStream {
    let ragu_core_path = helpers::ragu_core_path();
    let ragu_core_path = if let Err(e) = ragu_core_path {
        return e.into_compile_error().into();
    } else {
        ragu_core_path.unwrap()
    };
    let ragu_primitives_path = helpers::ragu_primitives_path();
    let ragu_primitives_path = if let Err(e) = ragu_primitives_path {
        return e.into_compile_error().into();
    } else {
        ragu_primitives_path.unwrap()
    };

    gadget_serialize::derive(
        parse_macro_input!(input as DeriveInput),
        ragu_core_path,
        ragu_primitives_path,
    )
    .unwrap_or_else(Error::into_compile_error)
    .into()
}

//! Resolving paths for `udon`, `ragu_core`, and `ragu_primitives`.
//!
//! If the end-user invoking the procedural macro is using the `ragu` crate and
//! not importing `ragu_core`, we need to identify the path inside `ragu` that
//! corresponds to where `ragu_core` traits are re-exported. Also, the end-user
//! might have renamed the crates, so we must use `proc-macro-crate`.
//!
//! `udon`, whose field vocabulary the generated bounds name, resolves to the
//! caller's direct dependency when there is one, possibly renamed, and
//! otherwise to the `udon` that `ragu_core` re-exports, through `ragu` or
//! `ragu_core`.

use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::Span;
use quote::{ToTokens, format_ident};
use syn::{Error, Ident, Path, Result, parse_quote};

#[derive(Clone)]
pub struct UdonPath(Path);

#[derive(Clone)]
pub struct RaguCorePath(Path);

#[derive(Clone)]
pub struct RaguPrimitivesPath(Path);

impl ToTokens for UdonPath {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        self.0.to_tokens(tokens)
    }
}

impl ToTokens for RaguCorePath {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        self.0.to_tokens(tokens)
    }
}

impl ToTokens for RaguPrimitivesPath {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        self.0.to_tokens(tokens)
    }
}

impl Default for UdonPath {
    fn default() -> Self {
        Self(parse_quote! { ::udon })
    }
}

impl Default for RaguCorePath {
    fn default() -> Self {
        Self(parse_quote! { ::ragu_core })
    }
}

impl Default for RaguPrimitivesPath {
    fn default() -> Self {
        Self(parse_quote! { ::ragu_primitives })
    }
}

fn udon_path() -> Result<Path> {
    Ok(match crate_name("zakura-udon") {
        Ok(FoundCrate::Itself) => parse_quote! { ::zakura_udon },
        Ok(FoundCrate::Name(name)) => {
            let name: Ident = format_ident!("{}", name);
            parse_quote! { ::#name }
        }
        Err(_) => {
            let ragu_core = ragu_core_path().map_err(|_| {
                Error::new(
                    Span::call_site(),
                    "Failed to find zakura-udon, ragu or ragu_core crate. Ensure one is included in your Cargo.toml.",
                )
            })?;
            parse_quote! { #ragu_core::udon }
        }
    })
}

fn ragu_core_path() -> Result<Path> {
    Ok(match (crate_name("ragu_core"), crate_name("ragu")) {
        (Ok(FoundCrate::Itself), _) => parse_quote! { ::ragu_core },
        (_, Ok(FoundCrate::Itself)) => parse_quote! { ::ragu },
        (Ok(FoundCrate::Name(name)), _) | (Err(_), Ok(FoundCrate::Name(name))) => {
            let name: Ident = format_ident!("{}", name);
            parse_quote! { ::#name }
        }
        _ => {
            return Err(Error::new(
                Span::call_site(),
                "Failed to find ragu/ragu_core crate. Ensure it is included in your Cargo.toml.",
            ));
        }
    })
}

fn ragu_primitives_path() -> Result<Path> {
    Ok(match (crate_name("ragu_primitives"), crate_name("ragu")) {
        (Ok(FoundCrate::Itself), _) => parse_quote! { ::ragu_primitives },
        (_, Ok(FoundCrate::Itself)) => parse_quote! { ::ragu::primitives },
        (Ok(FoundCrate::Name(name)), _) => {
            let name: Ident = format_ident!("{}", name);
            parse_quote! { ::#name }
        }
        (_, Ok(FoundCrate::Name(name))) => {
            let name: Ident = format_ident!("{}", name);
            parse_quote! { ::#name::primitives }
        }
        _ => {
            return Err(Error::new(
                Span::call_site(),
                "Failed to find ragu/ragu_primitives crate. Ensure it is included in your Cargo.toml.",
            ));
        }
    })
}

impl UdonPath {
    pub fn resolve() -> Result<Self> {
        udon_path().map(Self)
    }
}

impl RaguCorePath {
    pub fn resolve() -> Result<Self> {
        ragu_core_path().map(Self)
    }
}

impl RaguPrimitivesPath {
    pub fn resolve() -> Result<Self> {
        ragu_primitives_path().map(Self)
    }
}

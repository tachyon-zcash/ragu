//! Resolving paths for `ragu_core` and `ragu_primitives`.
//!
//! If the end-user invoking the procedural macro is using the `ragu` crate and
//! not importing `ragu_core`, we need to identify the path inside `ragu` that
//! corresponds to where `ragu_core` traits are re-exported. Also, the end-user
//! might have renamed the crates, so we must use `proc-macro-crate`.

use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::Span;
use quote::{ToTokens, format_ident};
use syn::{Error, Ident, Path, Result, parse_quote};

#[derive(Clone)]
pub struct RaguArithmeticPath(Path);

#[derive(Clone)]
pub struct RaguCircuitsPath(Path);

#[derive(Clone)]
pub struct RaguCorePath(Path);

#[derive(Clone)]
pub struct RaguPcdPath(Path);

#[derive(Clone)]
pub struct RaguPrimitivesPath(Path);

impl ToTokens for RaguArithmeticPath {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        self.0.to_tokens(tokens)
    }
}

impl ToTokens for RaguCircuitsPath {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        self.0.to_tokens(tokens)
    }
}

impl ToTokens for RaguCorePath {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        self.0.to_tokens(tokens)
    }
}

impl ToTokens for RaguPcdPath {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        self.0.to_tokens(tokens)
    }
}

impl ToTokens for RaguPrimitivesPath {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        self.0.to_tokens(tokens)
    }
}

impl Default for RaguArithmeticPath {
    fn default() -> Self {
        Self(parse_quote! { ::ragu_arithmetic })
    }
}

impl Default for RaguCircuitsPath {
    fn default() -> Self {
        Self(parse_quote! { ::ragu_circuits })
    }
}

impl Default for RaguCorePath {
    fn default() -> Self {
        Self(parse_quote! { ::ragu_core })
    }
}

impl Default for RaguPcdPath {
    fn default() -> Self {
        Self(parse_quote! { ::ragu_pcd })
    }
}

impl Default for RaguPrimitivesPath {
    fn default() -> Self {
        Self(parse_quote! { ::ragu_primitives })
    }
}

fn ragu_arithmetic_path() -> Result<Path> {
    Ok(match (crate_name("ragu_arithmetic"), crate_name("ragu")) {
        (Ok(FoundCrate::Itself), _) => parse_quote! { ::ragu_arithmetic },
        (_, Ok(FoundCrate::Itself)) => parse_quote! { ::ragu::arithmetic },
        (Ok(FoundCrate::Name(name)), _) => {
            let name: Ident = format_ident!("{}", name);
            parse_quote! { ::#name }
        }
        (_, Ok(FoundCrate::Name(name))) => {
            let name: Ident = format_ident!("{}", name);
            parse_quote! { ::#name::arithmetic }
        }
        _ => {
            return Err(Error::new(
                Span::call_site(),
                "Failed to find ragu_arithmetic crate. Ensure it is included in your Cargo.toml.",
            ));
        }
    })
}

fn ragu_circuits_path() -> Result<Path> {
    // ragu_circuits is not re-exported from the umbrella `ragu` crate
    Ok(match crate_name("ragu_circuits") {
        Ok(FoundCrate::Itself) => parse_quote! { ::ragu_circuits },
        Ok(FoundCrate::Name(name)) => {
            let name: Ident = format_ident!("{}", name);
            parse_quote! { ::#name }
        }
        Err(_) => {
            return Err(Error::new(
                Span::call_site(),
                "Failed to find ragu_circuits crate. Ensure it is included in your Cargo.toml.",
            ));
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

fn ragu_pcd_path() -> Result<Path> {
    Ok(match (crate_name("ragu_pcd"), crate_name("ragu")) {
        (Ok(FoundCrate::Itself), _) => parse_quote! { ::ragu_pcd },
        (_, Ok(FoundCrate::Itself)) => parse_quote! { ::ragu::pcd },
        (Ok(FoundCrate::Name(name)), _) => {
            let name: Ident = format_ident!("{}", name);
            parse_quote! { ::#name }
        }
        (_, Ok(FoundCrate::Name(name))) => {
            let name: Ident = format_ident!("{}", name);
            parse_quote! { ::#name::pcd }
        }
        _ => {
            return Err(Error::new(
                Span::call_site(),
                "Failed to find ragu/ragu_pcd crate. Ensure it is included in your Cargo.toml.",
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

impl RaguArithmeticPath {
    pub fn resolve() -> Result<Self> {
        ragu_arithmetic_path().map(Self)
    }
}

impl RaguCircuitsPath {
    pub fn resolve() -> Result<Self> {
        ragu_circuits_path().map(Self)
    }
}

impl RaguCorePath {
    pub fn resolve() -> Result<Self> {
        ragu_core_path().map(Self)
    }
}

impl RaguPcdPath {
    pub fn resolve() -> Result<Self> {
        ragu_pcd_path().map(Self)
    }
}

impl RaguPrimitivesPath {
    pub fn resolve() -> Result<Self> {
        ragu_primitives_path().map(Self)
    }
}

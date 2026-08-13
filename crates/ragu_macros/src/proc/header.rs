//! Implementation of the `#[header]` proc-macro.
//!
//! Generates a `HeaderContent` implementation for single-gadget headers where
//! `encode()` calls the gadget's `alloc` constructor.
//!
//! # Modes
//!
//! - **Generic** (`#[header(data = F, gadget = Element)]`): `data` doubles as
//!   the field type parameter, producing `impl<F: Field> HeaderContent<F>`.
//! - **Concrete** (`#[header(data = EpAffine, gadget = Point<EpAffine>, field = Fp)]`):
//!   an explicit `field` pins the impl to a specific field type.
//! - **Direct allocation** (`alloc = direct`): by default the generated
//!   `encode()` passes its allocator through to
//!   `Gadget::alloc(dr, allocator, witness)`. For gadgets whose `alloc`
//!   produces constrained wires directly and takes no allocator (e.g.
//!   `Point`), `alloc = direct` generates `Gadget::alloc(dr, witness)`
//!   instead.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{
    Error, Ident, ItemStruct, Result, Token, Type,
    parse::{Parse, ParseStream},
};

use crate::path_resolution::RaguAppPath;

/// Generates the `HeaderContent` impl for a `#[header]`-annotated struct.
pub fn evaluate(attr: HeaderAttr, item: ItemStruct) -> Result<TokenStream> {
    let app = RaguAppPath::resolve()?;

    if !item.generics.params.is_empty() || item.generics.where_clause.is_some() {
        return Err(Error::new_spanned(
            &item.generics,
            "#[header] structs must not have generic parameters or where clauses",
        ));
    }

    if !matches!(item.fields, syn::Fields::Unit) {
        return Err(Error::new_spanned(
            &item.fields,
            "#[header] structs must be unit structs (no fields)",
        ));
    }

    let struct_vis = &item.vis;
    let struct_ident = &item.ident;
    let struct_attrs = &item.attrs;
    let data_ty = &attr.data;
    let prelude = quote!(#app::__macro_internal);
    let kind_expr = make_kind_expr(&attr.gadget)?;
    let gadget_base = extract_base_path(&attr.gadget)?;

    // When `field` is absent, `data` is both the field parameter and the data
    // type, yielding a generic impl. When present, the impl is concrete.
    let field_ty = attr.field.as_ref().unwrap_or(data_ty);
    let impl_generics = if attr.field.is_some() {
        quote!()
    } else {
        quote!(<#data_ty: #prelude::Field>)
    };

    let (allocator_param, alloc_call) = if attr.alloc_direct {
        (
            quote!(_allocator: &mut __A),
            quote!(#gadget_base::alloc(dr, witness)),
        )
    } else {
        (
            quote!(allocator: &mut __A),
            quote!(#gadget_base::alloc(dr, allocator, witness)),
        )
    };

    Ok(quote! {
        #(#struct_attrs)*
        #struct_vis struct #struct_ident;

        impl #impl_generics #app::HeaderContent<#field_ty> for #struct_ident {
            type Data = #data_ty;
            type Output = #prelude::Kind![#field_ty; #kind_expr];

            fn encode<'dr, __D: #prelude::Driver<'dr, F = #field_ty>, __A: #prelude::Allocator<'dr, __D>>(
                dr: &mut __D,
                #allocator_param,
                witness: #prelude::DriverValue<__D, Self::Data>,
            ) -> #prelude::Result<#prelude::Bound<'dr, __D, Self::Output>> {
                #alloc_call
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// The parsed `#[header(...)]` attribute arguments.
///
/// Required: `data` and `gadget`.
/// Optional: `field` (when absent, `data` is used as both the field type
/// parameter and the data type, producing a generic `impl<F: Field>`) and
/// `alloc = direct` (for gadgets whose `alloc` takes no allocator).
pub struct HeaderAttr {
    data: Type,
    gadget: Type,
    field: Option<Type>,
    alloc_direct: bool,
}

impl Parse for HeaderAttr {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let mut data = None;
        let mut gadget = None;
        let mut field = None;
        let mut alloc = None;

        while !input.is_empty() {
            let ident: Ident = input.parse()?;
            input.parse::<Token![=]>()?;
            let ty: Type = input.parse()?;

            match ident.to_string().as_str() {
                "data" => {
                    if data.is_some() {
                        return Err(Error::new(
                            ident.span(),
                            "duplicate `data` key in #[header(...)]",
                        ));
                    }
                    data = Some(ty);
                }
                "gadget" => {
                    if gadget.is_some() {
                        return Err(Error::new(
                            ident.span(),
                            "duplicate `gadget` key in #[header(...)]",
                        ));
                    }
                    gadget = Some(ty);
                }
                "field" => {
                    if field.is_some() {
                        return Err(Error::new(
                            ident.span(),
                            "duplicate `field` key in #[header(...)]",
                        ));
                    }
                    field = Some(ty);
                }
                "alloc" => {
                    if alloc.is_some() {
                        return Err(Error::new(
                            ident.span(),
                            "duplicate `alloc` key in #[header(...)]",
                        ));
                    }
                    alloc = Some(ty);
                }
                other => {
                    return Err(Error::new(
                        ident.span(),
                        format!(
                            "unknown attribute `{other}`, expected `data`, `gadget`, `field`, or `alloc`"
                        ),
                    ));
                }
            }

            // Consume optional trailing comma.
            let _ = input.parse::<Token![,]>();
        }

        let alloc_direct = match alloc {
            None => false,
            Some(ty) if matches!(&ty, Type::Path(p) if p.path.is_ident("direct")) => true,
            Some(ty) => {
                return Err(Error::new_spanned(
                    ty,
                    "unknown `alloc` mode in #[header(...)], expected `direct`",
                ));
            }
        };

        Ok(HeaderAttr {
            data: data
                .ok_or_else(|| Error::new(input.span(), "missing `data` in #[header(...)]"))?,
            gadget: gadget
                .ok_or_else(|| Error::new(input.span(), "missing `gadget` in #[header(...)]"))?,
            field,
            alloc_direct,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns the inner [`syn::TypePath`], or an error if `ty` is not a path type.
fn as_type_path(ty: &Type) -> Result<&syn::TypePath> {
    match ty {
        Type::Path(p) => Ok(p),
        _ => Err(Error::new_spanned(ty, "expected a path type for gadget")),
    }
}

/// Builds the `Kind!` gadget expression by prepending `'_, _` (the lifetime
/// and driver placeholders) to any existing type arguments.
///
/// Assumes all gadgets follow the convention `Gadget<'dr, D: Driver, ...extra>`.
/// The lifetime and driver slots are filled with `'_, _`; extra user-supplied
/// type arguments (from the `gadget` attribute) are appended after them.
///
/// - `Element`          → `Element<'_, _>`
/// - `Point<EpAffine>`  → `Point<'_, _, EpAffine>`
fn make_kind_expr(gadget_ty: &Type) -> Result<TokenStream> {
    let type_path = as_type_path(gadget_ty)?;
    let segments = &type_path.path.segments;
    let last = segments
        .last()
        .ok_or_else(|| Error::new_spanned(gadget_ty, "empty path for gadget type"))?;

    let prefix: Vec<_> = segments.iter().take(segments.len() - 1).collect();
    let base_ident = &last.ident;

    let extra_args: Vec<TokenStream> = match &last.arguments {
        syn::PathArguments::None => vec![],
        syn::PathArguments::AngleBracketed(args) => args.args.iter().map(|a| quote!(#a)).collect(),
        _ => {
            return Err(Error::new_spanned(
                gadget_ty,
                "unexpected parenthesized arguments on gadget type",
            ));
        }
    };

    let prefix_tokens = if prefix.is_empty() {
        quote!()
    } else {
        quote!(#(#prefix)::* ::)
    };

    if extra_args.is_empty() {
        Ok(quote!(#prefix_tokens #base_ident<'_, _>))
    } else {
        Ok(quote!(#prefix_tokens #base_ident<'_, _, #(#extra_args),*>))
    }
}

/// Strips generic arguments from a gadget path for the `::alloc()` call,
/// preserving the leading `::` and any path qualifiers.
///
/// - `Element`         → `Element`
/// - `Point<EpAffine>` → `Point`
fn extract_base_path(gadget_ty: &Type) -> Result<TokenStream> {
    let type_path = as_type_path(gadget_ty)?;
    let mut path = type_path.path.clone();
    if let Some(last) = path.segments.last_mut() {
        last.arguments = syn::PathArguments::None;
    }
    Ok(quote!(#path))
}

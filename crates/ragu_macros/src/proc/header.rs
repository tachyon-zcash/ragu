//! Implementation of the `#[header]` proc-macro.
//!
//! Generates a `HeaderContent` implementation for single-gadget headers: the
//! generated `encode()` allocates the gadget through its kind's `Allocatable`
//! impl, which supplies the witness (`Data`) type, the constructor, and any
//! field constraint. `Element` headers are therefore generic over every
//! field, while a point kind is allocatable only over its curve's base field,
//! pinning the impl accordingly.
//!
//! Gadget types follow the `Gadget<'dr, D, ...>` convention. The macro
//! injects the lifetime and driver arguments; callers write only any extra
//! arguments (`Element`, `Point<EpAffine>`).

use std::collections::BTreeSet;

use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::{
    Error, GenericArgument, Ident, ItemStruct, PathArguments, Result, Token, Type,
    ext::IdentExt,
    parse::{Parse, ParseStream},
    parse_quote,
};

use crate::{
    helpers::{collect_idents, fresh_ident},
    path_resolution::RaguAppPath,
    substitution::replace_inferences,
};

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
    let prelude = quote!(#app::__macro_internal);

    // Generated generic-parameter names must not capture any identifier the
    // caller wrote in the gadget type or as the struct name, both of which
    // are interpolated into scopes where these parameters are live.
    let mut occupied = BTreeSet::new();
    occupied.insert(struct_ident.unraw().to_string());
    let gadget_ty = &attr.gadget;
    collect_idents(quote!(#gadget_ty), &mut occupied);
    let field_ident = fresh_ident("F", &occupied, Span::mixed_site());
    let driver_ident = fresh_ident("__RaguHeaderDriver", &occupied, Span::mixed_site());
    let allocator_ident = fresh_ident("__RaguHeaderAllocator", &occupied, Span::mixed_site());

    let field_ty: Type = parse_quote!(#field_ident);
    let gadget_phantom = phantom_gadget(&attr.gadget, &field_ty)?;
    let kind = make_output_kind(&attr.gadget, &field_ty, &prelude)?;

    // The bounds do the inference a token-level macro cannot: `Gadget`
    // legitimizes the kind projection for every field parameter (a gadget
    // that exists only over some fields makes the impl unsatisfiable
    // elsewhere), and `Allocatable` supplies the witness type and
    // constructor.
    Ok(quote! {
        #(#struct_attrs)*
        #struct_vis struct #struct_ident;

        impl<#field_ident: #prelude::Field> #app::HeaderContent<#field_ident> for #struct_ident
        where
            #gadget_phantom: #prelude::Gadget<'static, ::core::marker::PhantomData<#field_ident>>,
            #kind: #prelude::Allocatable<#field_ident>,
        {
            type Data = <#kind as #prelude::Allocatable<#field_ident>>::Witness;
            type Output = #kind;

            fn encode<'dr, #driver_ident: #prelude::Driver<'dr, F = #field_ident>, #allocator_ident: #prelude::Allocator<'dr, #driver_ident>>(
                dr: &mut #driver_ident,
                allocator: &mut #allocator_ident,
                witness: #prelude::DriverValue<#driver_ident, Self::Data>,
            ) -> #prelude::Result<#prelude::Bound<'dr, #driver_ident, Self::Output>> {
                <#kind as #prelude::Allocatable<#field_ident>>::alloc(dr, allocator, witness)
            }
        }
    })
}

/// The parsed `#[header(...)]` attribute arguments.
///
/// `gadget` is the only key: the gadget kind's `Allocatable` impl supplies
/// everything else.
pub struct HeaderAttr {
    gadget: Type,
}

impl Parse for HeaderAttr {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let mut gadget = None;

        while !input.is_empty() {
            let ident: Ident = input.parse()?;
            input.parse::<Token![=]>()?;

            match ident.to_string().as_str() {
                "gadget" => {
                    if gadget.is_some() {
                        return Err(Error::new(
                            ident.span(),
                            "duplicate `gadget` key in #[header(...)]",
                        ));
                    }
                    gadget = Some(input.parse::<Type>()?);
                }
                removed @ ("data" | "field" | "alloc") => {
                    return Err(Error::new(
                        ident.span(),
                        format!(
                            "`{removed}` is no longer accepted: the gadget kind's `Allocatable` \
                             impl supplies the witness type, field constraint, and constructor"
                        ),
                    ));
                }
                other => {
                    return Err(Error::new(
                        ident.span(),
                        format!("unknown attribute `{other}`, expected `gadget`"),
                    ));
                }
            }

            // Entries are comma-separated; a trailing comma is permitted.
            if !input.is_empty() {
                input.parse::<Token![,]>()?;
            }
        }

        Ok(HeaderAttr {
            gadget: gadget
                .ok_or_else(|| Error::new(input.span(), "missing `gadget` in #[header(...)]"))?,
        })
    }
}

/// Returns the inner [`syn::TypePath`], or an error if `ty` is not a path type.
fn as_type_path(ty: &Type) -> Result<&syn::TypePath> {
    match ty {
        Type::Path(p) => Ok(p),
        _ => Err(Error::new_spanned(ty, "expected a path type for gadget")),
    }
}

/// Builds the concrete gadget type expected by [`make_output_kind`] by
/// prepending `'_, _` (the lifetime and driver placeholders) to any existing
/// type arguments.
///
/// Assumes all gadgets follow the convention `Gadget<'dr, D: Driver, ...extra>`.
/// The lifetime and driver slots are filled with `'_, _`; extra user-supplied
/// type arguments (from the `gadget` attribute) are appended after them.
///
/// - `Element`          → `Element<'_, _>`
/// - `Point<EpAffine>`  → `Point<'_, _, EpAffine>`
fn make_gadget_type(gadget_ty: &Type) -> Result<Type> {
    let mut type_path = as_type_path(gadget_ty)?.clone();
    let last = type_path
        .path
        .segments
        .last_mut()
        .ok_or_else(|| Error::new_spanned(gadget_ty, "empty path for gadget type"))?;

    match &mut last.arguments {
        PathArguments::None => {
            last.arguments = PathArguments::AngleBracketed(parse_quote!(<'_, _>));
        }
        PathArguments::AngleBracketed(args) => {
            let previous = core::mem::take(&mut args.args);
            let mut with_driver = syn::punctuated::Punctuated::new();
            with_driver.push(GenericArgument::Lifetime(parse_quote!('_)));
            with_driver.push(GenericArgument::Type(parse_quote!(_)));
            with_driver.extend(previous);
            args.args = with_driver;
        }
        PathArguments::Parenthesized(_) => {
            return Err(Error::new_spanned(
                gadget_ty,
                "unexpected parenthesized arguments on gadget type",
            ));
        }
    }

    Ok(Type::Path(type_path))
}

/// Builds the gadget type instantiated at the phantom driver
/// `PhantomData<field_ty>`, the form the generated impl's bounds and kind
/// projection are written against.
fn phantom_gadget(gadget_ty: &Type, field_ty: &Type) -> Result<Type> {
    let mut gadget = make_gadget_type(gadget_ty)?;
    replace_inferences(&mut gadget, field_ty);
    Ok(gadget)
}

/// Computes the gadget kind directly through the app prelude. Avoiding a
/// nested `Kind!` invocation is important: a nested proc macro would resolve
/// `ragu_core` from the downstream crate's manifest and incorrectly require it
/// as a direct dependency.
fn make_output_kind(
    gadget_ty: &Type,
    field_ty: &Type,
    prelude: &TokenStream,
) -> Result<TokenStream> {
    let gadget = phantom_gadget(gadget_ty, field_ty)?;
    Ok(quote!(
        <#gadget as #prelude::Gadget<'static, ::core::marker::PhantomData<#field_ty>>>::Kind
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_attr(tokens: TokenStream) -> Result<HeaderAttr> {
        syn::parse2(tokens)
    }

    fn parse_attr_err(tokens: TokenStream) -> String {
        match parse_attr(tokens) {
            Ok(_) => panic!("expected a parse error"),
            Err(err) => err.to_string(),
        }
    }

    #[test]
    fn attr_requires_gadget() {
        assert!(parse_attr(quote!(gadget = Element)).is_ok());
        assert!(parse_attr(quote!(gadget = Point<EpAffine>)).is_ok());

        let err = parse_attr_err(quote!());
        assert!(err.contains("missing `gadget`"));
    }

    #[test]
    fn attr_rejects_duplicate_and_unknown_keys() {
        let err = parse_attr_err(quote!(gadget = Element, gadget = Boolean));
        assert!(err.contains("duplicate `gadget` key"));

        let err = parse_attr_err(quote!(kind = X));
        assert!(err.contains("unknown attribute `kind`"));
    }

    #[test]
    fn attr_rejects_removed_keys_with_migration_help() {
        for removed in ["data", "field", "alloc"] {
            let ident = Ident::new(removed, Span::call_site());
            let err = parse_attr_err(quote!(#ident = X, gadget = Element));
            assert!(err.contains("no longer accepted"), "{removed}: {err}");
        }
    }

    #[test]
    fn attr_requires_commas_between_entries() {
        assert!(parse_attr(quote!(gadget = Element,)).is_ok());

        let err = parse_attr_err(quote!(gadget = Element gadget = Boolean));
        assert!(err.contains("expected `,`"));
    }

    #[test]
    fn gadget_type_preserves_absolute_paths_and_existing_arguments() {
        let gadget = make_gadget_type(&syn::parse_quote!(::some_crate::Point<Curve>)).unwrap();
        assert_eq!(
            quote!(#gadget).to_string(),
            quote!(::some_crate::Point<'_, _, Curve>).to_string()
        );
    }

    #[test]
    fn output_kind_does_not_invoke_a_nested_proc_macro() {
        let output = make_output_kind(
            &syn::parse_quote!(::some_crate::Element),
            &syn::parse_quote!(F),
            &quote!(::ragu_pcd::app::__macro_internal),
        )
        .unwrap()
        .to_string();

        assert!(output.contains("Gadget"));
        assert!(!output.contains("Kind !"));
        assert!(output.contains(":: some_crate :: Element"));
    }
}

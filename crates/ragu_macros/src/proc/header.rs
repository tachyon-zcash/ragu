//! Implementation of the `#[header]` proc-macro.
//!
//! Generates a `HeaderContent` implementation for single-gadget headers where
//! `encode()` calls the gadget's `alloc` constructor.
//!
//! # Modes
//!
//! - **Generic** (`#[header(data = F, gadget = Element)]`): `data` doubles as
//!   the field type parameter, producing `impl<F: Field> HeaderContent<F>`;
//!   it must therefore be a bare type-parameter identifier.
//! - **Concrete** (`#[header(data = EpAffine, gadget = Point<EpAffine>, field = Fp)]`):
//!   an explicit `field` pins the impl to a specific field type.
//! - **Direct allocation** (`alloc = direct`): by default the generated
//!   `encode()` passes its allocator through to
//!   `Gadget::alloc(dr, allocator, witness)`. For gadgets whose `alloc`
//!   produces constrained wires directly and takes no allocator (e.g.
//!   `Point`), `alloc = direct` generates `Gadget::alloc(dr, witness)`
//!   instead.
//!
//! Gadget types follow the `Gadget<'dr, D, ...>` convention. The macro injects
//! the lifetime and driver arguments before any extra arguments supplied by
//! the caller.

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
    let data_ty = &attr.data;
    let prelude = quote!(#app::__macro_internal);
    let output_kind = make_output_kind(
        &attr.gadget,
        attr.field.as_ref().unwrap_or(data_ty),
        &prelude,
    )?;
    let gadget_base = extract_base_path(&attr.gadget)?;

    // When `field` is absent, `data` is both the field parameter and the data
    // type, yielding a generic impl. When present, the impl is concrete.
    let field_ty = attr.field.as_ref().unwrap_or(data_ty);
    let generic_field = if attr.field.is_none() {
        Some(generic_field_ident(data_ty)?)
    } else {
        None
    };
    let impl_generics = match generic_field {
        Some(field) => quote!(<#field: #prelude::Field>),
        None => quote!(),
    };

    if let Some(field) = generic_field {
        validate_generic_field(field, struct_ident, &attr.gadget)?;
    }

    // Generated generic-parameter names must not capture any identifier the
    // caller wrote in `data`, `gadget`, or `field`, all of which are
    // interpolated into scopes where these parameters are live.
    let mut occupied = BTreeSet::new();
    let gadget_ty = &attr.gadget;
    collect_idents(quote!(#data_ty), &mut occupied);
    collect_idents(quote!(#gadget_ty), &mut occupied);
    if let Some(field) = &attr.field {
        collect_idents(quote!(#field), &mut occupied);
    }
    let driver_ident = fresh_ident("__RaguHeaderDriver", &occupied, Span::mixed_site());
    let allocator_ident = fresh_ident("__RaguHeaderAllocator", &occupied, Span::mixed_site());

    let (allocator_param, alloc_call) = if attr.alloc_direct {
        (
            quote!(_allocator: &mut #allocator_ident),
            quote!(#gadget_base::alloc(dr, witness)),
        )
    } else {
        (
            quote!(allocator: &mut #allocator_ident),
            quote!(#gadget_base::alloc(dr, allocator, witness)),
        )
    };

    Ok(quote! {
        #(#struct_attrs)*
        #struct_vis struct #struct_ident;

        impl #impl_generics #app::HeaderContent<#field_ty> for #struct_ident {
            type Data = #data_ty;
            type Output = #output_kind;

            fn encode<'dr, #driver_ident: #prelude::Driver<'dr, F = #field_ty>, #allocator_ident: #prelude::Allocator<'dr, #driver_ident>>(
                dr: &mut #driver_ident,
                #allocator_param,
                witness: #prelude::DriverValue<#driver_ident, Self::Data>,
            ) -> #prelude::Result<#prelude::Bound<'dr, #driver_ident, Self::Output>> {
                #alloc_call
            }
        }
    })
}

/// Rejects generic-mode `data` parameter names that would shadow another name
/// the generated impl must resolve.
///
/// The parameter is declared on the generated impl, so it shadows same-named
/// relative paths everywhere inside: the self type (the struct) and the gadget
/// path resolved by `encode()` and the output kind. Only the caller can rename
/// the parameter, so both collisions are rejected rather than freshened.
/// Absolute paths are immune to shadowing, so an absolute gadget path is
/// accepted.
fn validate_generic_field(field: &Ident, struct_ident: &Ident, gadget: &Type) -> Result<()> {
    if *field == struct_ident.unraw() {
        return Err(Error::new(
            field.span(),
            "the `data` type parameter collides with the struct name; rename one of them",
        ));
    }

    if let Type::Path(path) = gadget
        && path.qself.is_none()
        && path.path.leading_colon.is_none()
        && path
            .path
            .segments
            .first()
            .is_some_and(|segment| segment.ident == *field)
    {
        return Err(Error::new(
            field.span(),
            "the `data` type parameter shadows the gadget path inside the generated impl; \
             rename the parameter (for example, `F`), refer to the gadget by an absolute path, \
             or add `field = ...` if the data type is concrete",
        ));
    }

    Ok(())
}

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

            // Entries are comma-separated; a trailing comma is permitted.
            if !input.is_empty() {
                input.parse::<Token![,]>()?;
            }
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

        let data =
            data.ok_or_else(|| Error::new(input.span(), "missing `data` in #[header(...)]"))?;
        if field.is_none() {
            generic_field_ident(&data)?;
        }

        Ok(HeaderAttr {
            data,
            gadget: gadget
                .ok_or_else(|| Error::new(input.span(), "missing `gadget` in #[header(...)]"))?,
            field,
            alloc_direct,
        })
    }
}

/// Returns the bare type-parameter identifier used by generic header mode.
fn generic_field_ident(data: &Type) -> Result<&Ident> {
    let Type::Path(type_path) = data else {
        return Err(generic_field_error(data));
    };
    if type_path.qself.is_some()
        || type_path.path.leading_colon.is_some()
        || type_path.path.segments.len() != 1
    {
        return Err(generic_field_error(data));
    }

    let segment = type_path.path.segments.first().expect("length checked");
    if !matches!(segment.arguments, PathArguments::None)
        || syn::parse2::<syn::TypeParam>(quote!(#segment)).is_err()
    {
        return Err(generic_field_error(data));
    }

    Ok(&segment.ident)
}

fn generic_field_error(data: &Type) -> Error {
    Error::new_spanned(
        data,
        "when `field` is not specified, `data` must be a type parameter name (for example, `F`); add `field = YourField` for concrete data types",
    )
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

/// Computes the gadget kind directly through the app prelude. Avoiding a
/// nested `Kind!` invocation is important: a nested proc macro would resolve
/// `ragu_core` from the downstream crate's manifest and incorrectly require it
/// as a direct dependency.
fn make_output_kind(
    gadget_ty: &Type,
    field_ty: &Type,
    prelude: &TokenStream,
) -> Result<TokenStream> {
    let mut gadget = make_gadget_type(gadget_ty)?;
    replace_inferences(&mut gadget, field_ty);
    Ok(quote!(
        <#gadget as #prelude::Gadget<'static, ::core::marker::PhantomData<#field_ty>>>::Kind
    ))
}

/// Strips generic arguments from a gadget path for the `::alloc()` call,
/// preserving the leading `::` and any path qualifiers.
///
/// - `Element`         → `Element`
/// - `Point<EpAffine>` → `Point`
fn extract_base_path(gadget_ty: &Type) -> Result<TokenStream> {
    let mut type_path = as_type_path(gadget_ty)?.clone();
    if let Some(last) = type_path.path.segments.last_mut() {
        last.arguments = syn::PathArguments::None;
    }
    Ok(quote!(#type_path))
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
    fn attr_requires_data_and_gadget() {
        assert!(parse_attr(quote!(data = F, gadget = Element)).is_ok());

        let err = parse_attr_err(quote!(gadget = Element));
        assert!(err.contains("missing `data`"));

        let err = parse_attr_err(quote!(data = F));
        assert!(err.contains("missing `gadget`"));
    }

    #[test]
    fn attr_rejects_duplicate_and_unknown_keys() {
        let err = parse_attr_err(quote!(data = F, data = G, gadget = Element));
        assert!(err.contains("duplicate `data` key"));

        let err = parse_attr_err(quote!(data = F, gadget = Element, kind = X));
        assert!(err.contains("unknown attribute `kind`"));
    }

    #[test]
    fn attr_requires_commas_between_entries() {
        assert!(parse_attr(quote!(data = F, gadget = Element,)).is_ok());

        let err = parse_attr_err(quote!(data = F gadget = Element));
        assert!(err.contains("expected `,`"));
    }

    #[test]
    fn attr_accepts_direct_alloc_mode_only() {
        let attr = parse_attr(quote!(data = F, gadget = Element, alloc = direct)).unwrap();
        assert!(attr.alloc_direct);

        let err = parse_attr_err(quote!(data = F, gadget = Element, alloc = indirect));
        assert!(err.contains("unknown `alloc` mode"));
    }

    #[test]
    fn generic_field_shadowing_is_rejected() {
        let strukt: Ident = parse_quote!(LeafNode);

        let field: Ident = parse_quote!(F);
        assert!(validate_generic_field(&field, &strukt, &parse_quote!(Element)).is_ok());
        // Intentional field-parameter references inside gadget arguments stay
        // allowed.
        assert!(validate_generic_field(&field, &strukt, &parse_quote!(Point<F>)).is_ok());

        let field: Ident = parse_quote!(Element);
        let err = validate_generic_field(&field, &strukt, &parse_quote!(Element))
            .unwrap_err()
            .to_string();
        assert!(err.contains("shadows the gadget path"));

        // Absolute paths cannot be shadowed by a generic parameter.
        assert!(
            validate_generic_field(&field, &strukt, &parse_quote!(::ragu_primitives::Element))
                .is_ok()
        );

        let field: Ident = parse_quote!(LeafNode);
        let err = validate_generic_field(&field, &strukt, &parse_quote!(Element))
            .unwrap_err()
            .to_string();
        assert!(err.contains("collides with the struct name"));
    }

    #[test]
    fn generic_mode_requires_a_bare_type_parameter() {
        assert!(parse_attr(quote!(data = F, gadget = Element)).is_ok());
        assert!(parse_attr(quote!(data = Vec<F>, gadget = Element, field = F)).is_ok());

        let err = parse_attr_err(quote!(data = Vec<F>, gadget = Element));
        assert!(err.contains("`data` must be a type parameter name"));

        let err = parse_attr_err(quote!(data = Self, gadget = Element));
        assert!(err.contains("`data` must be a type parameter name"));
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

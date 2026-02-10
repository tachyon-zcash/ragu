//! Function-like macro for generating unified instance types.
//!
//! This module implements the `unified_instance!` macro, which generates three
//! related types from a field specification list:
//!
//! - `Output<'dr, D, C>` - Circuit gadget for public inputs
//! - `Instance<C>` - Native value representation
//! - `OutputBuilder<'a, 'dr, D, C>` - Lazy builder with slot-based allocation
//!
//! Fields are annotated with `#[point]` or `#[element]` to indicate whether
//! they represent curve points or field elements. The macro preserves field
//! order and documentation.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{
    Error, Ident, Result, Token, Type, Visibility,
    parse::{Parse, ParseStream},
    punctuated::Punctuated,
};

use crate::path_resolution::{RaguCorePath, RaguPrimitivesPath};

/// Field type for unified instance macro.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FieldKind {
    Point,
    Element,
}

/// Parsed field information.
struct FieldInfo {
    ident: Ident,
    kind: FieldKind,
    doc_attrs: Vec<syn::Attribute>,
}

/// A single field specification in the macro invocation.
///
/// Parses `#[attr] pub ident: Type` syntax. The visibility and type are
/// parsed but unused; they're consumed to advance the token stream and
/// reserved for future enhancements like visibility preservation or type
/// validation.
struct FieldSpec {
    attrs: Vec<syn::Attribute>,
    _vis: Visibility,
    ident: Ident,
    _colon_token: Token![:],
    _ty: Type,
}

impl Parse for FieldSpec {
    fn parse(input: ParseStream) -> Result<Self> {
        Ok(FieldSpec {
            attrs: input.call(syn::Attribute::parse_outer)?,
            _vis: input.parse()?,
            ident: input.parse()?,
            _colon_token: input.parse()?,
            _ty: input.parse()?,
        })
    }
}

/// The input to the unified_instance macro.
pub struct Input {
    fields: Punctuated<FieldSpec, Token![,]>,
}

impl Parse for Input {
    fn parse(input: ParseStream) -> Result<Self> {
        Ok(Input {
            fields: input.parse_terminated(FieldSpec::parse, Token![,])?,
        })
    }
}

pub fn evaluate(
    input: Input,
    ragu_core_path: RaguCorePath,
    ragu_primitives_path: RaguPrimitivesPath,
    arithmetic_path: syn::Path,
) -> Result<TokenStream> {
    // Parse fields
    let field_infos = parse_fields(&input.fields)?;

    // Generic parameter name (hardcoded as C for consistency)
    let cycle_param: Ident = syn::parse_quote!(C);

    // Generate the three structs and impl
    let output_struct = generate_output_struct(
        &field_infos,
        &cycle_param,
        &ragu_core_path,
        &ragu_primitives_path,
        &arithmetic_path,
    )?;
    let instance_struct = generate_instance_struct(&field_infos, &cycle_param, &arithmetic_path)?;
    let builder_struct = generate_builder_struct(
        &field_infos,
        &cycle_param,
        &ragu_core_path,
        &ragu_primitives_path,
        &arithmetic_path,
    )?;
    let builder_impl = generate_builder_impl(
        &field_infos,
        &cycle_param,
        &ragu_core_path,
        &ragu_primitives_path,
        &arithmetic_path,
    )?;

    Ok(quote! {
        #output_struct

        #instance_struct

        #builder_struct

        #builder_impl
    })
}

/// Parse field specifications into FieldInfo.
fn parse_fields(fields: &Punctuated<FieldSpec, Token![,]>) -> Result<Vec<FieldInfo>> {
    let mut field_infos = Vec::new();

    for field in fields {
        let ident = field.ident.clone();

        // Extract doc comments
        let doc_attrs: Vec<_> = field
            .attrs
            .iter()
            .filter(|a| a.path().is_ident("doc"))
            .cloned()
            .collect();

        // Parse field kind from #[point] or #[element]
        let kind = parse_field_kind(&field.attrs)?;

        field_infos.push(FieldInfo {
            ident,
            kind,
            doc_attrs,
        });
    }

    Ok(field_infos)
}

/// Parse the `#[point]` or `#[element]` attribute from a field.
fn parse_field_kind(attrs: &[syn::Attribute]) -> Result<FieldKind> {
    let kind_attrs: Vec<_> = attrs
        .iter()
        .filter(|a| a.path().is_ident("point") || a.path().is_ident("element"))
        .collect();

    match kind_attrs.len() {
        0 => Err(Error::new(
            proc_macro2::Span::call_site(),
            "field must have #[point] or #[element] attribute",
        )),
        1 => {
            if kind_attrs[0].path().is_ident("point") {
                Ok(FieldKind::Point)
            } else {
                Ok(FieldKind::Element)
            }
        }
        _ => Err(Error::new(
            proc_macro2::Span::call_site(),
            "field can only have one kind attribute",
        )),
    }
}

/// Generate the gadget type token stream for a field kind.
///
/// Returns `Point<'dr, D, C::NestedCurve>` for points or `Element<'dr, D>`
/// for elements.
fn gadget_type_tokens(
    kind: FieldKind,
    cycle_param: &Ident,
    ragu_primitives_path: &RaguPrimitivesPath,
) -> TokenStream {
    match kind {
        FieldKind::Point => {
            quote! { #ragu_primitives_path::Point<'dr, D, #cycle_param::NestedCurve> }
        }
        FieldKind::Element => quote! { #ragu_primitives_path::Element<'dr, D> },
    }
}

/// Generate the Output struct with Gadget, Write, Consistent derives.
fn generate_output_struct(
    fields: &[FieldInfo],
    cycle_param: &Ident,
    ragu_core_path: &RaguCorePath,
    ragu_primitives_path: &RaguPrimitivesPath,
    arithmetic_path: &syn::Path,
) -> Result<TokenStream> {
    let field_defs = fields.iter().map(|f| {
        let ident = &f.ident;
        let doc_attrs = &f.doc_attrs;
        let gadget_type = gadget_type_tokens(f.kind, cycle_param, ragu_primitives_path);
        quote! {
            #(#doc_attrs)*
            #[ragu(gadget)]
            pub #ident: #gadget_type
        }
    });

    Ok(quote! {
        #[derive(Gadget, Write, Consistent)]
        pub struct Output<'dr, D: #ragu_core_path::drivers::Driver<'dr>, #cycle_param: #arithmetic_path::Cycle<CircuitField = D::F>> {
            #(#field_defs,)*
        }
    })
}

/// Generate the Instance struct.
fn generate_instance_struct(
    fields: &[FieldInfo],
    cycle_param: &Ident,
    arithmetic_path: &syn::Path,
) -> Result<TokenStream> {
    let field_defs = fields.iter().map(|f| {
        let ident = &f.ident;
        let doc_attrs = &f.doc_attrs;
        let native_type = match f.kind {
            FieldKind::Point => quote! { #cycle_param::NestedCurve },
            FieldKind::Element => quote! { #cycle_param::CircuitField },
        };
        quote! {
            #(#doc_attrs)*
            pub #ident: #native_type
        }
    });

    Ok(quote! {
        pub struct Instance<#cycle_param: #arithmetic_path::Cycle> {
            #(#field_defs,)*
        }
    })
}

/// Generate the OutputBuilder struct.
fn generate_builder_struct(
    fields: &[FieldInfo],
    cycle_param: &Ident,
    ragu_core_path: &RaguCorePath,
    ragu_primitives_path: &RaguPrimitivesPath,
    arithmetic_path: &syn::Path,
) -> Result<TokenStream> {
    let field_defs = fields.iter().map(|f| {
        let ident = &f.ident;
        let doc_attrs = &f.doc_attrs;
        let gadget_type = gadget_type_tokens(f.kind, cycle_param, ragu_primitives_path);
        quote! {
            #(#doc_attrs)*
            pub #ident: Slot<'a, 'dr, D, #gadget_type, #cycle_param>
        }
    });

    Ok(quote! {
        pub struct OutputBuilder<'a, 'dr, D: #ragu_core_path::drivers::Driver<'dr>, #cycle_param: #arithmetic_path::Cycle<CircuitField = D::F>> {
            #(#field_defs,)*
        }
    })
}

/// Generate the OutputBuilder impl with new, finish_no_suffix, and finish methods.
fn generate_builder_impl(
    fields: &[FieldInfo],
    cycle_param: &Ident,
    ragu_core_path: &RaguCorePath,
    ragu_primitives_path: &RaguPrimitivesPath,
    arithmetic_path: &syn::Path,
) -> Result<TokenStream> {
    // Generate new() method field initializers
    let new_inits = fields.iter().map(|f| {
        let ident = &f.ident;
        let alloc_fn = match f.kind {
            FieldKind::Point => quote! {
                Slot::new(|dr, i: &#ragu_core_path::drivers::DriverValue<D, &'a Instance<#cycle_param>>| {
                    #ragu_primitives_path::Point::alloc(dr, i.view().map(|i| i.#ident))
                })
            },
            FieldKind::Element => quote! {
                Slot::new(|dr, i: &#ragu_core_path::drivers::DriverValue<D, &'a Instance<#cycle_param>>| {
                    #ragu_primitives_path::Element::alloc(dr, i.view().map(|i| i.#ident))
                })
            },
        };
        quote! { #ident: #alloc_fn }
    });

    // Generate finish_no_suffix() field assignments
    let finish_fields = fields.iter().map(|f| {
        let ident = &f.ident;
        quote! { #ident: self.#ident.take(dr, instance)? }
    });

    Ok(quote! {
        impl<'a, 'dr, D: #ragu_core_path::drivers::Driver<'dr>, #cycle_param: #arithmetic_path::Cycle<CircuitField = D::F>> OutputBuilder<'a, 'dr, D, #cycle_param> {
            pub fn new() -> Self {
                OutputBuilder {
                    #(#new_inits,)*
                }
            }

            pub fn finish_no_suffix(
                self,
                dr: &mut D,
                instance: &#ragu_core_path::drivers::DriverValue<D, &'a Instance<#cycle_param>>,
            ) -> #ragu_core_path::Result<Output<'dr, D, #cycle_param>> {
                Ok(Output {
                    #(#finish_fields,)*
                })
            }

            pub fn finish(
                self,
                dr: &mut D,
                instance: &#ragu_core_path::drivers::DriverValue<D, &'a Instance<#cycle_param>>,
            ) -> #ragu_core_path::Result<<InternalOutputKind<#cycle_param> as #ragu_core_path::gadgets::GadgetKind<D::F>>::Rebind<'dr, D>> {
                let zero = #ragu_primitives_path::Element::zero(dr);
                Ok(WithSuffix::new(self.finish_no_suffix(dr, instance)?, zero))
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    #[test]
    fn test_basic_invocation() {
        let input: Input = parse_quote! {
            #[point]
            pub field1: C::NestedCurve,

            #[element]
            pub field2: C::CircuitField,
        };

        let result = evaluate(
            input,
            RaguCorePath::default(),
            RaguPrimitivesPath::default(),
            parse_quote!(::arithmetic),
        )
        .unwrap();

        let result_str = result.to_string();

        assert!(
            result_str.contains("pub struct Output"),
            "Should generate Output struct"
        );
        assert!(
            result_str.contains("pub struct Instance"),
            "Should generate Instance struct"
        );
        assert!(
            result_str.contains("pub struct OutputBuilder"),
            "Should generate OutputBuilder struct"
        );
    }

    #[test]
    fn test_missing_kind_attribute() {
        let input: Input = parse_quote! {
            pub field_without_attr: C::CircuitField,
        };

        let result = evaluate(
            input,
            RaguCorePath::default(),
            RaguPrimitivesPath::default(),
            parse_quote!(::arithmetic),
        );

        assert!(result.is_err(), "Expected error for missing kind attribute");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("must have #[point] or #[element]"),
            "Error message should mention missing attribute"
        );
    }

    #[test]
    fn test_preserves_doc_comments() {
        let input: Input = parse_quote! {
            /// This is a doc comment.
            #[point]
            pub documented_field: C::NestedCurve,
        };

        let result = evaluate(
            input,
            RaguCorePath::default(),
            RaguPrimitivesPath::default(),
            parse_quote!(::arithmetic),
        )
        .unwrap();

        let result_str = result.to_string();
        assert!(
            result_str.contains("This is a doc comment"),
            "Should preserve doc comments"
        );
    }

    #[test]
    fn test_multiple_kind_attributes() {
        let input: Input = parse_quote! {
            #[point]
            #[element]
            pub conflicted_field: C::CircuitField,
        };

        let result = evaluate(
            input,
            RaguCorePath::default(),
            RaguPrimitivesPath::default(),
            parse_quote!(::arithmetic),
        );

        assert!(
            result.is_err(),
            "Expected error for multiple kind attributes"
        );
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("can only have one kind attribute"),
            "Error message should mention conflicting attributes"
        );
    }
}

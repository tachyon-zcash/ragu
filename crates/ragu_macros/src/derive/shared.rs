use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote};
use syn::{
    AngleBracketedGenericArguments, Data, DeriveInput, Error, Fields, GenericParam, Generics,
    Result, parse_quote, spanned::Spanned,
};

use crate::{
    helpers::{GenericDriver, attr_is},
    path_resolution::{RaguCorePath, RaguPrimitivesPath, UdonPath},
    substitution::replace_driver_field_in_generic_param,
};

pub fn derive(
    input: DeriveInput,
    udon_path: UdonPath,
    core: RaguCorePath,
    primitives: RaguPrimitivesPath,
) -> Result<TokenStream> {
    let driver = GenericDriver::extract(&input.generics)?;
    let field = format_ident!("DriverField");
    if let Some(clause) = &input.generics.where_clause {
        return Err(Error::new(
            clause.span(),
            "Shared derive does not yet support where clauses",
        ));
    }
    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => &fields.named,
            _ => {
                return Err(Error::new(
                    data.struct_token.span(),
                    "Shared derive requires named fields",
                ));
            }
        },
        _ => {
            return Err(Error::new(
                Span::call_site(),
                "Shared derive requires a struct",
            ));
        }
    };
    let mut names = Vec::new();
    for member in fields {
        if member
            .attrs
            .iter()
            .any(|a| attr_is(a, "skip") || attr_is(a, "wire") || attr_is(a, "value"))
        {
            return Err(Error::new(
                member.span(),
                "Shared fields cannot be skipped, raw wires, or witness-only values",
            ));
        }
        if member.attrs.iter().any(|a| attr_is(a, "phantom")) {
            if member.attrs.iter().any(|a| attr_is(a, "gadget")) {
                return Err(Error::new(
                    member.span(),
                    "a shared field cannot be both phantom and a gadget",
                ));
            }
        } else {
            names.push(member.ident.as_ref().unwrap());
        }
    }
    let mut params = input
        .generics
        .params
        .iter()
        .filter(|param| match param {
            GenericParam::Type(p) => p.ident != driver.ident,
            GenericParam::Lifetime(p) => p.lifetime.ident != driver.lifetime.ident,
            _ => true,
        })
        .cloned()
        .collect::<Vec<_>>();
    for param in &mut params {
        replace_driver_field_in_generic_param(param, &driver.ident, &field);
    }
    params.push(parse_quote!(#field: #udon_path::field::Field));
    let generics: Generics = parse_quote!(< #(#params),* >);
    let (impl_generics, _, _) = generics.split_for_impl();
    let (_, args, _) = input.generics.split_for_impl();
    let args: AngleBracketedGenericArguments = parse_quote!(#args);
    let kind_args = driver.kind_subst_arguments(&args);
    let name = &input.ident;
    let lifetime = &driver.lifetime;
    let driver_name = &driver.ident;
    Ok(quote! {
        #[automatically_derived]
        impl #impl_generics #primitives::shared::Shared<#field> for #name #kind_args {
            fn num_values() -> #core::Result<usize> {
                let mut size = 0;
                #(size = #primitives::shared::add_sizes(size,
                    #primitives::shared::field_size::<#field, Self, _>(|this| &this.#names)?)?;)*
                Ok(size)
            }
            fn write_shared<#lifetime, #driver_name: #core::drivers::Driver<#lifetime, F = #field>>(
                this: &#core::gadgets::Bound<#lifetime, #driver_name, Self>,
                values: &mut #primitives::shared::Vec<#primitives::Element<#lifetime, #driver_name>>,
            ) -> #core::Result<()> {
                #(#primitives::shared::write_field(&this.#names, values)?;)*
                Ok(())
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn derive_str(input: &str) -> Result<TokenStream> {
        derive(
            syn::parse_str(input).unwrap(),
            UdonPath::resolve().unwrap(),
            RaguCorePath::resolve().unwrap(),
            RaguPrimitivesPath::resolve().unwrap(),
        )
    }

    #[test]
    fn shared_derive_refuses_omitted_or_untyped_wire_fields() {
        for attribute in ["skip", "wire", "value"] {
            let input = format!(
                "struct Connection<'dr, D: Driver<'dr>> {{ #[ragu({attribute})] field: Element<'dr, D> }}"
            );
            assert!(derive_str(&input).is_err(), "{attribute}");
        }
    }

    #[test]
    fn shared_derive_refuses_unsupported_shapes() {
        for input in [
            "enum Connection<'dr, D: Driver<'dr>> { Empty }",
            "struct Connection<'dr, D: Driver<'dr>>(Element<'dr, D>);",
            "struct Connection<'dr, D: Driver<'dr>> where D: Clone { field: Element<'dr, D> }",
            "struct Connection<'dr, D: Driver<'dr>> { #[ragu(phantom)] #[ragu(gadget)] field: Element<'dr, D> }",
        ] {
            assert!(derive_str(input).is_err(), "{input}");
        }
    }

    #[test]
    fn shared_derive_accepts_nested_and_generic_layouts() {
        for input in [
            "struct Connection<'dr, D: Driver<'dr>> { input: Element<'dr, D>, state: Element<'dr, D> }",
            "struct Nested<'dr, D: Driver<'dr>, const N: usize> { connection: Connection<'dr, D>, rest: FixedVec<Element<'dr, D>, ConstLen<N>> }",
            "struct Marked<'dr, D: Driver<'dr>> { #[ragu(phantom)] marker: PhantomData<&'dr D>, value: Element<'dr, D> }",
        ] {
            assert!(derive_str(input).is_ok(), "{input}");
        }
    }
}

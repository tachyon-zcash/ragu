use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote};
use syn::{
    AngleBracketedGenericArguments, Data, DeriveInput, Error, Fields, GenericParam, Generics,
    Ident, Path, Result, parse_quote, spanned::Spanned,
};

use crate::helpers::*;

pub fn derive(
    input: DeriveInput,
    ragu_core_path: Path,
    ragu_primitives_path: Path,
) -> Result<TokenStream> {
    let DeriveInput {
        ident: struct_ident,
        generics,
        data,
        ..
    } = &input;

    let driver = &generics
        .params
        .iter()
        .find_map(|p| match p {
            GenericParam::Type(ty) => ty
                .attrs
                .iter()
                .any(|a| attr_is(a, "driver"))
                .then(|| extract_generic_driver(ty)),
            _ => None,
        })
        .unwrap_or(Ok(GenericDriver::default()))?;
    let driverfield_ident = format_ident!("DriverField");

    // impl_generics = <'a, 'b: 'a, C: Cycle, D: Driver, const N: usize>
    // ty_generics = <'a, 'b, C, D, N>
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    if let Some(wc) = where_clause {
        return Err(Error::new(
            wc.span(),
            "GadgetSerialize derive does not yet support where clauses",
        ));
    }
    let impl_generics = {
        let mut impl_generics: Generics = parse_quote!( #impl_generics );
        impl_generics.params.iter_mut().for_each(|gp| match gp {
            GenericParam::Type(ty) if ty.ident == driver.ident => {
                // Strip out driver attribute if present
                ty.attrs.retain(|a| !attr_is(a, "driver"));
            }
            _ => {}
        });
        impl_generics
    };
    let ty_generics: AngleBracketedGenericArguments = { parse_quote!( #ty_generics ) };

    enum FieldType {
        Serialize,
        Skip,
    }

    let fields: Vec<(Ident, FieldType)> = match data {
        Data::Struct(s) => {
            let fields = match &s.fields {
                Fields::Named(named) => &named.named,
                _ => {
                    return Err(Error::new(
                        s.struct_token.span(),
                        "GadgetSerialize derive only works on structs with named fields",
                    ));
                }
            };

            let mut res = vec![];

            for f in fields {
                let fid = f.ident.clone().expect("fields contains only named fields");
                let is_skip = f.attrs.iter().any(|a| attr_is(a, "skip"));
                let is_phantom = f.attrs.iter().any(|a| attr_is(a, "phantom"));

                if is_skip || is_phantom {
                    res.push((fid, FieldType::Skip));
                } else {
                    res.push((fid, FieldType::Serialize));
                }
            }

            res
        }
        _ => {
            return Err(Error::new(
                Span::call_site(),
                "GadgetSerialize derive only works on structs",
            ));
        }
    };

    let gadget_kind_generic_params: Generics = {
        let mut params: Vec<GenericParam> = impl_generics
            .clone()
            .params
            .into_iter()
            .filter(|gp| match gp {
                // strip out driver
                GenericParam::Type(ty) if ty.ident == driver.ident => false,
                // strip out driver lifetime
                GenericParam::Lifetime(lt) if lt.lifetime.ident == driver.lifetime.ident => false,
                _ => true,
            })
            .collect();
        for param in &mut params {
            replace_driver_field_in_generic_param(param, &driver.ident, &driverfield_ident);
        }
        params.push(parse_quote!( #driverfield_ident: ::ff::Field ));

        parse_quote!( < #( #params ),* >)
    };

    let kind_subst_arguments = driver.kind_subst_arguments(&ty_generics);

    let serialize_calls = fields.iter().filter_map(|(id, ty)| match ty {
        FieldType::Serialize => {
            Some(quote! { #ragu_primitives_path::GadgetExt::serialize(&this.#id, dr, buf)?; })
        }
        FieldType::Skip => None,
    });

    let gadgetserialize_impl = {
        let driver_ident = &driver.ident;
        let driver_lifetime = &driver.lifetime;
        quote! {
            #[automatically_derived]
            impl #gadget_kind_generic_params #ragu_primitives_path::serialize::GadgetSerialize<#driverfield_ident> for #struct_ident #kind_subst_arguments {
                fn serialize_gadget<#driver_lifetime, #driver_ident: #ragu_core_path::drivers::Driver<#driver_lifetime, F = #driverfield_ident>, B: #ragu_primitives_path::serialize::Buffer<#driver_lifetime, #driver_ident> >(
                    this: &<Self as #ragu_core_path::gadgets::GadgetKind<#driverfield_ident>>::Rebind<#driver_lifetime, #driver_ident>,
                    dr: &mut #driver_ident,
                    buf: &mut B
                ) -> #ragu_core_path::Result<()> {
                    #( #serialize_calls )*
                    Ok(())
                }
            }
        }
    };

    Ok(quote! {
        #gadgetserialize_impl
    })
}

#[rustfmt::skip]
#[test]
fn test_gadget_serialize_derive() {
    use syn::parse_quote;

    let input: DeriveInput = parse_quote! {
        #[derive(GadgetSerialize)]
        pub struct MyGadget<'my_dr, #[ragu(driver)] MyD: Driver<'my_dr>, C: CurveAffine, const N: usize> {
            field1: Element<'my_dr, MyD>,
            field2: Boolean<'my_dr, MyD>,
            #[ragu(skip)]
            phantom: ::core::marker::PhantomData<()>,
        }
    };

    let result = derive(input, parse_quote!(::ragu_core), parse_quote!(::ragu_primitives)).unwrap();

    assert_eq!(
        result.to_string(),
        quote!(
            #[automatically_derived]
            impl<C: CurveAffine, const N: usize, DriverField: ::ff::Field> ::ragu_primitives::serialize::GadgetSerialize<DriverField>
                for MyGadget<'static, ::core::marker::PhantomData< DriverField >, C, N>
            {
                fn serialize_gadget<'my_dr, MyD: ::ragu_core::drivers::Driver<'my_dr, F = DriverField>, B: ::ragu_primitives::serialize::Buffer<'my_dr, MyD> >(
                    this: &<Self as ::ragu_core::gadgets::GadgetKind<DriverField>>::Rebind<'my_dr, MyD>,
                    dr: &mut MyD,
                    buf: &mut B
                ) -> ::ragu_core::Result<()> {
                    ::ragu_primitives::GadgetExt::serialize(&this.field1, dr, buf)?;
                    ::ragu_primitives::GadgetExt::serialize(&this.field2, dr, buf)?;
                    Ok(())
                }
            }
        ).to_string()
    );
}

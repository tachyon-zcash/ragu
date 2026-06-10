use proc_macro2::Span;
use quote::{format_ident, quote};
use syn::{
    AngleBracketedGenericArguments, Data, DeriveInput, Error, Fields, GenericParam, Generics,
    Ident, Result, parse_quote, spanned::Spanned,
};

use crate::{
    helpers::{GenericDriver, attr_is},
    path_resolution::{RaguArithmeticPath, RaguCorePath, RaguPrimitivesPath},
    substitution::replace_driver_field_in_generic_param,
};

pub fn derive(
    input: DeriveInput,
    ragu_arithmetic_path: RaguArithmeticPath,
    ragu_core_path: RaguCorePath,
    ragu_primitives_path: RaguPrimitivesPath,
) -> Result<proc_macro2::TokenStream> {
    let DeriveInput {
        ident: struct_ident,
        generics,
        data,
        ..
    } = &input;

    let driver = &GenericDriver::extract(generics)?;
    let driverfield_ident = format_ident!("DriverField");

    enum FieldType {
        Value,
        Wire,
        Gadget,
        Phantom,
    }

    let fields: Vec<(Ident, FieldType)> = match data {
        Data::Struct(s) => {
            let fields = match &s.fields {
                Fields::Named(named) => &named.named,
                _ => {
                    return Err(Error::new(
                        s.struct_token.span(),
                        "GadgetEquals derive only works on structs with named fields",
                    ));
                }
            };

            let mut res = vec![];

            for f in fields {
                let fid = f.ident.clone().expect("fields contains only named fields");
                let is_value = f.attrs.iter().any(|a| attr_is(a, "value"));
                let is_wire = f.attrs.iter().any(|a| attr_is(a, "wire"));
                let is_gadget = f.attrs.iter().any(|a| attr_is(a, "gadget"));
                let is_phantom = f.attrs.iter().any(|a| attr_is(a, "phantom"));

                match (is_value, is_wire, is_gadget, is_phantom) {
                    (true, false, false, false) => {
                        res.push((fid, FieldType::Value));
                    }
                    (false, true, false, false) => {
                        res.push((fid, FieldType::Wire));
                    }
                    (false, false, true, false) => {
                        res.push((fid, FieldType::Gadget));
                    }
                    (false, false, false, true) => {
                        res.push((fid, FieldType::Phantom));
                    }
                    (false, false, false, false) => {
                        res.push((fid, FieldType::Gadget));
                    }
                    _ => {
                        return Err(Error::new(
                            fid.span(),
                            "field cannot have multiple annotations; use only one of: #[ragu(value)], #[ragu(wire)], #[ragu(gadget)], or #[ragu(phantom)]",
                        ));
                    }
                }
            }

            res
        }
        _ => {
            return Err(Error::new(
                Span::call_site(),
                "GadgetEquals derive only works on structs",
            ));
        }
    };

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    if let Some(wc) = where_clause {
        return Err(Error::new(
            wc.span(),
            "GadgetEquals derive does not yet support where clauses",
        ));
    }
    let impl_generics: Generics = {
        let mut impl_generics: Generics = parse_quote!( #impl_generics );
        impl_generics.params.iter_mut().for_each(|gp| match gp {
            GenericParam::Type(ty) if ty.ident == driver.ident => {
                ty.attrs.retain(|a| !attr_is(a, "driver"));
            }
            _ => {}
        });
        impl_generics
    };
    let ty_generics: AngleBracketedGenericArguments = parse_quote!( #ty_generics );
    let gadget_kind_generic_params: Generics = {
        let mut params: Vec<GenericParam> = impl_generics
            .params
            .clone()
            .into_iter()
            .filter(|gp| match gp {
                GenericParam::Type(ty) if ty.ident == driver.ident => false,
                GenericParam::Lifetime(lt) if lt.lifetime.ident == driver.lifetime.ident => false,
                _ => true,
            })
            .collect();
        for param in &mut params {
            replace_driver_field_in_generic_param(param, &driver.ident, &driverfield_ident);
        }
        params.push(parse_quote!( #driverfield_ident: #ragu_arithmetic_path::ff::Field ));

        parse_quote!( < #( #params ),* >)
    };
    let kind_subst_arguments = driver.kind_subst_arguments(&ty_generics);

    let equality_driver = format_ident!("D1");
    let equality_source = format_ident!("D2");
    let driver_lifetime = &driver.lifetime;
    let equality_calls = fields.iter().filter_map(|(id, ty)| match ty {
        FieldType::Wire => {
            Some(quote! { #ragu_core_path::drivers::Driver::enforce_equal(dr, &a.#id, &b.#id)?; })
        }
        FieldType::Gadget => {
            Some(quote! { #ragu_primitives_path::GadgetExt::enforce_equal(&a.#id, dr, &b.#id)?; })
        }
        _ => None,
    });

    Ok(quote! {
        #[automatically_derived]
        impl #gadget_kind_generic_params #ragu_primitives_path::comparison::GadgetEquals<#driverfield_ident>
            for #struct_ident #kind_subst_arguments
        {
            fn enforce_equal_gadget<
                #driver_lifetime,
                #equality_driver: #ragu_core_path::drivers::Driver<#driver_lifetime, F = #driverfield_ident>,
                #equality_source: #ragu_core_path::drivers::Driver<
                    #driver_lifetime,
                    F = #driverfield_ident,
                    Wire = <#equality_driver as #ragu_core_path::drivers::Driver<#driver_lifetime>>::Wire,
                >,
            >(
                dr: &mut #equality_driver,
                a: &#ragu_core_path::gadgets::Bound<#driver_lifetime, #equality_source, Self>,
                b: &#ragu_core_path::gadgets::Bound<#driver_lifetime, #equality_source, Self>,
            ) -> #ragu_core_path::Result<()>
            {
                #( #equality_calls )*
                Ok(())
            }
        }
    })
}

#[rustfmt::skip]
#[test]
fn test_gadgetequals_derive() {
    use syn::parse_quote;

    let input: DeriveInput = parse_quote! {
        #[derive(GadgetEquals)]
        struct MyGadget<'mydr, #[ragu(driver)] MyD: Driver<'mydr>> {
            #[ragu(wire)]
            wire: MyD::Wire,
            field: Element<'mydr, MyD>,
            #[ragu(value)]
            value: DriverValue<MyD, bool>,
            #[ragu(phantom)]
            marker: ::core::marker::PhantomData<()>,
        }
    };

    let result = derive(
        input,
        RaguArithmeticPath::default(),
        RaguCorePath::default(),
        RaguPrimitivesPath::default(),
    )
    .unwrap();

    assert_eq!(
        result.to_string(),
        quote!(
            #[automatically_derived]
            impl<DriverField: ::ragu_arithmetic::ff::Field> ::ragu_primitives::comparison::GadgetEquals<DriverField>
                for MyGadget<'static, ::core::marker::PhantomData<DriverField> >
            {
                fn enforce_equal_gadget<
                    'mydr,
                    D1: ::ragu_core::drivers::Driver<'mydr, F = DriverField>,
                    D2: ::ragu_core::drivers::Driver<
                        'mydr,
                        F = DriverField,
                        Wire = <D1 as ::ragu_core::drivers::Driver<'mydr>>::Wire,
                    >,
                >(
                    dr: &mut D1,
                    a: &::ragu_core::gadgets::Bound<'mydr, D2, Self>,
                    b: &::ragu_core::gadgets::Bound<'mydr, D2, Self>,
                ) -> ::ragu_core::Result<()>
                {
                    ::ragu_core::drivers::Driver::enforce_equal(dr, &a.wire, &b.wire)?;
                    ::ragu_primitives::GadgetExt::enforce_equal(&a.field, dr, &b.field)?;
                    Ok(())
                }
            }
        ).to_string()
    );
}

#[test]
fn test_gadgetequals_derive_rejects_where_clause() {
    use syn::parse_quote;

    let input: DeriveInput = parse_quote! {
        #[derive(GadgetEquals)]
        struct MyGadget<'mydr, #[ragu(driver)] MyD: Driver<'mydr>>
        where
            MyD: Clone,
        {
            field: Element<'mydr, MyD>,
        }
    };

    assert!(
        derive(
            input,
            RaguArithmeticPath::default(),
            RaguCorePath::default(),
            RaguPrimitivesPath::default()
        )
        .is_err()
    );
}

use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::{
    AngleBracketedGenericArguments, Data, DeriveInput, Error, Fields, GenericParam, Generics,
    Ident, Result, parse_quote, spanned::Spanned,
};

use crate::{
    helpers::{GenericDriver, attr_is},
    path_resolution::RaguCorePath,
};

pub fn derive(input: DeriveInput, ragu_core_path: RaguCorePath) -> Result<TokenStream> {
    let DeriveInput {
        ident: struct_ident,
        generics,
        data,
        ..
    } = &input;

    let driver = &GenericDriver::extract(generics)?;

    // impl_generics = <'a, 'b: 'a, C: Cycle, D: Driver, const N: usize>
    // ty_generics = <'a, 'b, C, D, N>
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    if let Some(wc) = where_clause {
        return Err(Error::new(
            wc.span(),
            "Consistent derive does not yet support where clauses",
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

    let fields: Vec<(Ident, bool)> = match data {
        Data::Struct(s) => {
            let fields = match &s.fields {
                Fields::Named(named) => &named.named,
                _ => {
                    return Err(Error::new(
                        s.struct_token.span(),
                        "Consistent derive only works on structs with named fields",
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

                // Treat as gadget if explicitly marked OR if no annotation present
                // (matches Gadget derive behavior)
                let should_enforce = is_gadget || (!is_value && !is_wire && !is_phantom);
                res.push((fid, should_enforce));
            }

            res
        }
        _ => {
            return Err(Error::new(
                Span::call_site(),
                "Consistent derive only works on structs",
            ));
        }
    };

    // Generate enforce_consistent calls for gadget fields (explicit or defaulted)
    let enforce_calls = fields.iter().filter_map(|(id, should_enforce)| {
        if *should_enforce {
            Some(quote! { #ragu_core_path::gadgets::Consistent::enforce_consistent(&self.#id, dr)?; })
        } else {
            None
        }
    });

    let driver_ident = &driver.ident;
    let driver_lifetime = &driver.lifetime;

    let consistent_impl = quote! {
        #[automatically_derived]
        impl #impl_generics #ragu_core_path::gadgets::Consistent<#driver_lifetime, #driver_ident> for #struct_ident #ty_generics {
            fn enforce_consistent(&self, dr: &mut #driver_ident) -> #ragu_core_path::Result<()> {
                #( #enforce_calls )*
                Ok(())
            }
        }
    };

    Ok(consistent_impl)
}

#[rustfmt::skip]
#[test]
fn test_consistent_derive() {
    use syn::parse_quote;

    let input: DeriveInput = parse_quote! {
        #[derive(Consistent)]
        struct MyGadget<'mydr, #[ragu(driver)] MyD: Driver<'mydr>> {
            #[ragu(gadget)]
            point: Point<'mydr, MyD>,
            #[ragu(wire)]
            wire_field: MyD::Wire,
            #[ragu(value)]
            value_field: DriverValue<MyD, bool>,
        }
    };

    let result = derive(input, RaguCorePath::default()).unwrap();

    assert_eq!(
        result.to_string(),
        quote!(
            #[automatically_derived]
            impl<'mydr, MyD: Driver<'mydr> > ::ragu_core::gadgets::Consistent<'mydr, MyD> for MyGadget<'mydr, MyD> {
                fn enforce_consistent(&self, dr: &mut MyD) -> ::ragu_core::Result<()> {
                    ::ragu_core::gadgets::Consistent::enforce_consistent(&self.point, dr)?;
                    Ok(())
                }
            }
        ).to_string()
    );
}

#[rustfmt::skip]
#[test]
fn test_consistent_derive_no_gadgets() {
    use syn::parse_quote;

    // Test a struct with no gadget fields - should just return Ok(())
    let input: DeriveInput = parse_quote! {
        #[derive(Consistent)]
        struct SimpleGadget<'dr, D: Driver<'dr>> {
            #[ragu(wire)]
            wire: D::Wire,
            #[ragu(value)]
            value: DriverValue<D, bool>,
        }
    };

    let result = derive(input, RaguCorePath::default()).unwrap();

    assert_eq!(
        result.to_string(),
        quote!(
            #[automatically_derived]
            impl<'dr, D: Driver<'dr> > ::ragu_core::gadgets::Consistent<'dr, D> for SimpleGadget<'dr, D> {
                fn enforce_consistent(&self, dr: &mut D) -> ::ragu_core::Result<()> {
                    Ok(())
                }
            }
        ).to_string()
    );
}

#[rustfmt::skip]
#[test]
fn test_consistent_derive_multiple_gadgets() {
    use syn::parse_quote;

    let input: DeriveInput = parse_quote! {
        #[derive(Consistent)]
        struct CompositeGadget<'dr, D: Driver<'dr>> {
            #[ragu(gadget)]
            point_a: Point<'dr, D>,
            #[ragu(gadget)]
            point_b: Point<'dr, D>,
            #[ragu(wire)]
            wire: D::Wire,
        }
    };

    let result = derive(input, RaguCorePath::default()).unwrap();

    assert_eq!(
        result.to_string(),
        quote!(
            #[automatically_derived]
            impl<'dr, D: Driver<'dr> > ::ragu_core::gadgets::Consistent<'dr, D> for CompositeGadget<'dr, D> {
                fn enforce_consistent(&self, dr: &mut D) -> ::ragu_core::Result<()> {
                    ::ragu_core::gadgets::Consistent::enforce_consistent(&self.point_a, dr)?;
                    ::ragu_core::gadgets::Consistent::enforce_consistent(&self.point_b, dr)?;
                    Ok(())
                }
            }
        ).to_string()
    );
}

#[rustfmt::skip]
#[test]
fn test_consistent_derive_unannotated_defaults_to_gadget() {
    use syn::parse_quote;

    // Unannotated fields should be treated as gadgets (matching Gadget derive behavior)
    let input: DeriveInput = parse_quote! {
        #[derive(Consistent)]
        struct CompositeGadget<'dr, D: Driver<'dr>> {
            unannotated: Point<'dr, D>,  // No annotation - should be treated as gadget
            #[ragu(wire)]
            wire: D::Wire,
        }
    };

    let result = derive(input, RaguCorePath::default()).unwrap();

    assert_eq!(
        result.to_string(),
        quote!(
            #[automatically_derived]
            impl<'dr, D: Driver<'dr> > ::ragu_core::gadgets::Consistent<'dr, D> for CompositeGadget<'dr, D> {
                fn enforce_consistent(&self, dr: &mut D) -> ::ragu_core::Result<()> {
                    ::ragu_core::gadgets::Consistent::enforce_consistent(&self.unannotated, dr)?;
                    Ok(())
                }
            }
        ).to_string()
    );
}

use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote};
use syn::{
    AngleBracketedGenericArguments, Data, DeriveInput, Error, Fields, GenericArgument,
    GenericParam, Generics, Ident, Lifetime, Path, Result, Type, parse_quote, spanned::Spanned,
};

use crate::helpers::*;

impl GenericDriver {
    pub fn gadget_params(&self) -> AngleBracketedGenericArguments {
        let driver_ident = &self.ident;
        let lifetime = &self.lifetime;

        parse_quote!( <#lifetime, #driver_ident> )
    }

    pub fn is_lt(&self, other: &Lifetime) -> bool {
        self.lifetime.ident == other.ident
    }

    pub fn is_ty(&self, other: &Type) -> bool {
        if let Type::Path(path) = other {
            if let Some(seg) = path.path.segments.last() {
                if seg.ident == self.ident {
                    return true;
                }
            }
        }
        false
    }

    pub fn kind_arguments(
        &self,
        ty_generics: &AngleBracketedGenericArguments,
        ragu_core_path: &Path,
    ) -> AngleBracketedGenericArguments {
        let driver_ident = &self.ident;
        let static_lifetime = Lifetime::new("'static", Span::call_site());
        let current_lifetime = &self.lifetime;
        let args = ty_generics.args.iter().map(move |gp| { match gp {
            GenericArgument::Type(ty) if self.is_ty(ty) => parse_quote!( ::core::marker::PhantomData<<#driver_ident as #ragu_core_path::drivers::Driver<#current_lifetime>>::F> ),
            GenericArgument::Lifetime(lt) if self.is_lt(lt) => parse_quote!( #static_lifetime ),
            a => parse_quote!( #a ),
        }}).collect::<Vec<GenericArgument>>();
        parse_quote!( < #( #args ),* > )
    }

    pub fn kind_subst_arguments(
        &self,
        ty_generics: &AngleBracketedGenericArguments,
    ) -> AngleBracketedGenericArguments {
        let static_lifetime = Lifetime::new("'static", Span::call_site());
        let args = ty_generics
            .args
            .iter()
            .map(move |gp| match gp {
                GenericArgument::Type(ty) if self.is_ty(ty) => {
                    parse_quote!(::core::marker::PhantomData<DriverField>)
                }
                GenericArgument::Lifetime(lt) if self.is_lt(lt) => parse_quote!( #static_lifetime ),
                a => parse_quote!( #a ),
            })
            .collect::<Vec<GenericArgument>>();
        parse_quote!( < #( #args ),* > )
    }

    pub fn rebind_arguments(
        &self,
        ty_generics: &AngleBracketedGenericArguments,
    ) -> AngleBracketedGenericArguments {
        let driver_ident = &self.ident;
        let lifetime = &self.lifetime;
        let args = ty_generics
            .args
            .iter()
            .map(move |gp| match gp {
                GenericArgument::Type(ty) if self.is_ty(ty) => parse_quote!( #driver_ident ),
                GenericArgument::Lifetime(lt) if self.is_lt(lt) => {
                    parse_quote!( #lifetime )
                }
                a => parse_quote!( #a ),
            })
            .collect::<Vec<GenericArgument>>();
        parse_quote!( < #( #args ),* > )
    }
}

pub fn derive(input: DeriveInput, ragu_core_path: Path) -> Result<TokenStream> {
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
            "Gadget derive does not yet support where clauses",
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

    let gadget_args = driver.gadget_params();

    enum FieldType {
        Witness,
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
                        "Gadget derive only works on structs with named fields",
                    ));
                }
            };

            let mut res = vec![];

            for f in fields {
                let fid = f.ident.clone().expect("fields contains only named fields");
                let is_witness = f.attrs.iter().any(|a| attr_is(a, "witness"));
                let is_wire = f.attrs.iter().any(|a| attr_is(a, "wire"));
                let is_gadget = f.attrs.iter().any(|a| attr_is(a, "gadget"));
                let is_phantom = f.attrs.iter().any(|a| attr_is(a, "phantom"));

                match (is_witness, is_wire, is_gadget, is_phantom) {
                    (true, false, false, false) => {
                        res.push((fid, FieldType::Witness));
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
                    _ => {
                        return Err(Error::new(
                            fid.span(),
                            "field attributes must be one of: #[ragu(witness)], #[ragu(wire)], #[ragu(gadget)], or #[ragu(phantom)]",
                        ));
                    }
                }
            }

            res
        }
        _ => {
            return Err(Error::new(
                Span::call_site(),
                "Gadget derive only works on structs",
            ));
        }
    };

    let clone_impl_inits = fields.iter().map(|(id, ty)| {
        let init = match ty {
            FieldType::Witness => {
                let driver_id = &driver.ident;
                quote! { {
                    use #ragu_core_path::maybe::Maybe;
                    #driver_id::just(|| self.#id.view().take().clone())
                } }
            }
            _ => quote! { ::core::clone::Clone::clone(&self.#id) },
        };
        quote! { #id: #init }
    });

    let clone_impl = quote! {
        #[automatically_derived]
        impl #impl_generics ::core::clone::Clone for #struct_ident #ty_generics {
            fn clone(&self) -> Self {
                #struct_ident {
                    #( #clone_impl_inits, )*
                }
            }
        }
    };

    let equality_calls = fields.iter().filter_map(|(id, ty)| match ty {
        FieldType::Wire => {
            Some(quote! { #ragu_core_path::drivers::Driver::enforce_equal(dr, &a.#id, &b.#id)? })
        }
        FieldType::Gadget => Some(
            quote! { #ragu_core_path::gadgets::Gadget::enforce_equal_gadget(&a.#id, dr, &b.#id)? },
        ),
        _ => None,
    });

    let kind_ty_arguments = driver.kind_arguments(&ty_generics, &ragu_core_path);

    let gadget_impl = {
        quote! {
            #[automatically_derived]
            impl #impl_generics #ragu_core_path::gadgets::Gadget #gadget_args for #struct_ident #ty_generics  {
                type Kind = #struct_ident #kind_ty_arguments;
            }
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
    let rebind_arguments = driver.rebind_arguments(&ty_generics);

    let gadget_impl_inits = fields.iter().map(|(id, ty)| {
        let init = match ty {
            FieldType::Witness => quote! {
                {
                    use #ragu_core_path::maybe::Maybe;

                    let tmp = ND::just(|| this.#id.view().take().clone());
                    is_send(&tmp);
                    tmp
                }
            },
            FieldType::Wire => {
                quote! { #ragu_core_path::drivers::FromDriver::convert_wire(ndr, &this.#id)? }
            }
            FieldType::Gadget => {
                quote! { #ragu_core_path::gadgets::Gadget::map_gadget(&this.#id, ndr)? }
            }
            FieldType::Phantom => quote! { ::core::marker::PhantomData },
        };
        quote! { #id: #init }
    });

    let gadgetkind_impl = {
        let driver_ident = &driver.ident;
        let driver_lifetime = &driver.lifetime;
        quote! {
            #[automatically_derived]
            unsafe impl #gadget_kind_generic_params #ragu_core_path::gadgets::GadgetKind<#driverfield_ident> for #struct_ident #kind_subst_arguments  {
                type Rebind<#driver_lifetime, #driver_ident: #ragu_core_path::drivers::Driver<#driver_lifetime, F = #driverfield_ident>> = #struct_ident #rebind_arguments;

                fn map<#driver_lifetime, 'new_dr, #driver_ident: #ragu_core_path::drivers::Driver<#driver_lifetime, F = #driverfield_ident>, ND: #ragu_core_path::drivers::FromDriver<#driver_lifetime, 'new_dr, #driver_ident>>(
                    this: &Self::Rebind<#driver_lifetime, #driver_ident>,
                    ndr: &mut ND,
                ) -> #ragu_core_path::Result<Self::Rebind<'new_dr, ND::NewDriver>> {
                    fn is_send<T: Send>(_: &T) { }

                    Ok(#struct_ident {
                        #( #gadget_impl_inits, )*
                    })
                }

                fn enforce_equal<#driver_lifetime, D1: #ragu_core_path::drivers::Driver<#driver_lifetime, F = #driverfield_ident>, D2: #ragu_core_path::drivers::Driver<#driver_lifetime, F = #driverfield_ident, Wire = <D1 as #ragu_core_path::drivers::Driver<#driver_lifetime>>::Wire>>(
                    dr: &mut D1,
                    a: &Self::Rebind<#driver_lifetime, D2>,
                    b: &Self::Rebind<#driver_lifetime, D2>,
                ) -> #ragu_core_path::Result<()> {
                    #( #equality_calls; )*
                    Ok(())
                }
            }
        }
    };

    Ok(quote! {
        #clone_impl

        #gadget_impl

        #gadgetkind_impl
    })
}

#[test]
fn test_fail_enum() {
    let input: DeriveInput = parse_quote! {
        #[derive(Gadget)]
        enum Boolean<'my_dr, #[ragu(driver)] MyD: ragu_core::Driver<'my_dr>> {
            Is(MyD::W),
            Not(MyD::W)
        }
    };

    assert!(
        derive(input, parse_quote! {::ragu}).is_err(),
        "Expected error for enum usage"
    );
}

#[test]
fn test_fail_where_clause() {
    let input: DeriveInput = parse_quote! {
        #[derive(Gadget)]
        struct Boolean<'my_dr, #[ragu(driver)] MyD: ragu_core::Driver<'my_dr>>
            where MyD: Any
        {
            #[ragu(wire)]
            wire: MyD::W,
            #[ragu(witness)]
            value: Witness<'my_dr, MyD, bool>,
        }
    };

    assert!(
        derive(input, parse_quote! {::ragu}).is_err(),
        "Expected error for where clause"
    );
}

#[test]
fn test_fail_multi_annotations() {
    let input: DeriveInput = parse_quote! {
        #[derive(Gadget)]
        struct Boolean<'my_dr, #[ragu(driver)] MyD: ragu_core::Driver<'my_dr>> {
            #[ragu(wire)]
            wire: MyD::W,
            #[ragu(witness)]
            #[ragu(wire)]
            value: Witness<'my_dr, MyD, bool>,
        }
    };

    assert!(
        derive(input, parse_quote! {::ragu}).is_err(),
        "Expected error for multiple annotations on field"
    );
}

#[test]
fn test_fail_unnamed_struct() {
    let input: DeriveInput = parse_quote! {
        #[derive(Gadget)]
        struct Boolean<'my_dr, #[ragu(driver)] MyD: ragu_core::Driver<'my_dr>>
        (
            MyD::W,
            Witness<'my_dr, MyD, bool>,
        );
    };

    assert!(
        derive(input, parse_quote! {::ragu}).is_err(),
        "Expected error for unnamed struct fields"
    );
}

#[rustfmt::skip]
#[test]
fn test_gadget_derive_boolean_customdriver() {
    use syn::parse_quote;

    let input: DeriveInput = parse_quote! {
        #[derive(Gadget)]
        struct Boolean<'my_dr, #[ragu(driver)] MyD: ragu_core::Driver<'my_dr>> {
            #[ragu(wire)]
            wire: MyD::W,
            #[ragu(witness)]
            value: Witness<'my_dr, MyD, bool>,
        }
    };

    let result = derive(input, parse_quote!{::ragu}).unwrap();

    assert_eq!(
        result.to_string(),
        quote!(
            #[automatically_derived]
            impl<'my_dr, MyD: ragu_core::Driver<'my_dr> > ::core::clone::Clone for Boolean<'my_dr, MyD> {
                fn clone(&self) -> Self {
                    Boolean {
                        wire: ::core::clone::Clone::clone(&self.wire),
                        value: {
                            use ::ragu::maybe::Maybe;
                            MyD::just(|| self.value.view().take().clone())
                        },
                    }
                }
            }
            #[automatically_derived]
            impl<'my_dr, MyD: ragu_core::Driver<'my_dr> > ::ragu::gadgets::Gadget<'my_dr, MyD>
                for Boolean<'my_dr, MyD>
            {
                type Kind =
                    Boolean<'static, ::core::marker::PhantomData< <MyD as ::ragu::drivers::Driver<'my_dr> >::F> >;
            }
            #[automatically_derived]
            unsafe impl<DriverField: ::ff::Field> ::ragu::gadgets::GadgetKind<DriverField>
                for Boolean<'static, ::core::marker::PhantomData<DriverField> >
            {
                type Rebind<'my_dr, MyD: ::ragu::drivers::Driver<'my_dr, F = DriverField>> =
                    Boolean<'my_dr, MyD>;

                fn map<'my_dr, 'new_dr, MyD: ::ragu::drivers::Driver<'my_dr, F = DriverField>, ND: ::ragu::drivers::FromDriver<'my_dr, 'new_dr, MyD>>(
                    this: &Self::Rebind<'my_dr, MyD>,
                    ndr: &mut ND,
                ) -> ::ragu::Result<Self::Rebind<'new_dr, ND::NewDriver>> {
                    fn is_send<T: Send>(_: &T) { }

                    Ok(Boolean {
                        wire: ::ragu::drivers::FromDriver::convert_wire(ndr, &this.wire)?,
                        value: {
                            use ::ragu::maybe::Maybe;

                            let tmp = ND::just(|| this.value.view().take().clone());
                            is_send(&tmp);
                            tmp
                        },
                    })
                }

                fn enforce_equal<
                    'my_dr,
                    D1: ::ragu::drivers::Driver<'my_dr, F = DriverField>,
                    D2: ::ragu::drivers::Driver<
                            'my_dr,
                            F = DriverField,
                            Wire = <D1 as ::ragu::drivers::Driver<'my_dr>>::Wire>>
                (
                    dr: &mut D1,
                    a: &Self::Rebind<'my_dr, D2>,
                    b: &Self::Rebind<'my_dr, D2>,
                ) -> ::ragu::Result<()> {
                    ::ragu::drivers::Driver::enforce_equal(dr, &a.wire, &b.wire)?;
                    Ok(())
                }
            }
        ).to_string()
    );
}

#[rustfmt::skip]
#[test]
fn test_gadget_derive() {
    use syn::parse_quote;

    let input: DeriveInput = parse_quote! {
        #[derive(Gadget)]
        pub struct MyGadget<'mydr, #[ragu(driver)] MyD: Driver<'mydr>, C: Blah<MyD::F>, const N: usize> {
            #[ragu(witness)]
            witness_field: Witness<'mydr, MyD, MyD::F>,
            #[ragu(wire)]
            wire_field: MyD::W,
            #[ragu(gadget)]
            map_field: Lol<'mydr, MyD>,
            #[ragu(phantom)]
            phantom_field: ::core::marker::PhantomData<C>,
        }
    };

    let result = derive(input, parse_quote!{::ragu}).unwrap();

    assert_eq!(
        result.to_string(),
        quote!(
            #[automatically_derived]
            impl<'mydr, MyD: Driver<'mydr>, C: Blah<MyD::F>, const N: usize> ::core::clone::Clone for MyGadget<'mydr, MyD, C, N> {
                fn clone(&self) -> Self {
                    MyGadget {
                        witness_field: {
                            use ::ragu::maybe::Maybe;
                            MyD::just(|| self.witness_field.view().take().clone())
                        },
                        wire_field: ::core::clone::Clone::clone(&self.wire_field),
                        map_field: ::core::clone::Clone::clone(&self.map_field),
                        phantom_field: ::core::clone::Clone::clone(&self.phantom_field),
                    }
                }
            }

            #[automatically_derived]
            impl<'mydr, MyD: Driver<'mydr>, C: Blah<MyD::F>, const N: usize> ::ragu::gadgets::Gadget<'mydr, MyD> for MyGadget<'mydr, MyD, C, N> {
                type Kind = MyGadget<'static, ::core::marker::PhantomData< <MyD as ::ragu::drivers::Driver<'mydr> >::F >, C, N>;
            }

            #[automatically_derived]
            unsafe impl<C: Blah<DriverField>, const N: usize, DriverField: ::ff::Field> ::ragu::gadgets::GadgetKind<DriverField>
                for MyGadget<'static, ::core::marker::PhantomData< DriverField >, C, N>
            {
                type Rebind<'mydr, MyD: ::ragu::drivers::Driver<'mydr, F = DriverField>> = MyGadget<'mydr, MyD, C, N>;

                fn map<'mydr, 'new_dr, MyD: ::ragu::drivers::Driver<'mydr, F = DriverField>, ND: ::ragu::drivers::FromDriver<'mydr, 'new_dr, MyD>>(
                    this: &Self::Rebind<'mydr, MyD>,
                    ndr: &mut ND,
                ) -> ::ragu::Result<Self::Rebind<'new_dr, ND::NewDriver>> {
                    fn is_send<T: Send>(_: &T) { }

                    Ok(MyGadget {
                        witness_field: {
                            use ::ragu::maybe::Maybe;

                            let tmp = ND::just(|| this.witness_field.view().take().clone());
                            is_send(&tmp);
                            tmp
                        },
                        wire_field: ::ragu::drivers::FromDriver::convert_wire(ndr, &this.wire_field)?,
                        map_field: ::ragu::gadgets::Gadget::map_gadget(&this.map_field, ndr)?,
                        phantom_field: ::core::marker::PhantomData,
                    })
                }

                fn enforce_equal<
                    'mydr,
                    D1: ::ragu::drivers::Driver<'mydr, F = DriverField>,
                    D2: ::ragu::drivers::Driver<
                            'mydr,
                            F = DriverField,
                            Wire = <D1 as ::ragu::drivers::Driver<'mydr>>::Wire>>
                (
                    dr: &mut D1,
                    a: &Self::Rebind<'mydr, D2>,
                    b: &Self::Rebind<'mydr, D2>,
                ) -> ::ragu::Result<()> {
                    ::ragu::drivers::Driver::enforce_equal(dr, &a.wire_field, &b.wire_field)?;
                    ::ragu::gadgets::Gadget::enforce_equal_gadget(&a.map_field, dr, &b.map_field)?;
                    Ok(())
                }
            }

        ).to_string()
    );
}

#[test]
fn test_extract_generic_driver() {
    let driver = extract_generic_driver(&parse_quote!(D: ragu_core::Driver<'dr>)).unwrap();
    assert_eq!(driver.ident.to_string(), "D");
    assert_eq!(driver.lifetime.to_string(), "'dr");

    let driver = extract_generic_driver(&parse_quote!(D: Driver<'dr>)).unwrap();
    assert_eq!(driver.ident.to_string(), "D");
    assert_eq!(driver.lifetime.to_string(), "'dr");

    // Shouldn't cause an error in the macro to have a spurious driver type argument
    let driver = extract_generic_driver(&parse_quote!(D: Driver<'dr, T>)).unwrap();
    assert_eq!(driver.ident.to_string(), "D");
    assert_eq!(driver.lifetime.to_string(), "'dr");

    assert!(extract_generic_driver(&parse_quote!(D: Driver<'dr, 'another_dr>)).is_err());
    assert!(extract_generic_driver(&parse_quote!(D: Driver)).is_err());
    assert!(extract_generic_driver(&parse_quote!(D: 'a)).is_err());
}

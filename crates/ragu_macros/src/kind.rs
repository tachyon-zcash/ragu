use proc_macro2::TokenStream;
use quote::quote;
use syn::{
    GenericArgument, Lifetime, Path, PathArguments, Result, Token, Type, TypeParamBound, TypePath,
    parse::{Parse, ParseStream},
    parse_quote,
};

pub struct Input {
    f: Type,
    _semicolon: Token![;],
    path: Type,
}

impl Parse for Input {
    fn parse(input: ParseStream) -> Result<Self> {
        Ok(Self {
            f: input.parse()?,
            _semicolon: input.parse()?,
            path: input.parse()?,
        })
    }
}

pub fn evaluate(input: Input, ragu_core_path: Path) -> syn::Result<TokenStream> {
    let Input { f, path, .. } = input;

    let mut subst = path.clone();
    subst.substitute(&f);

    Ok(
        quote!(<#subst as #ragu_core_path::gadgets::Gadget<'static, ::core::marker::PhantomData<#f>>>::Kind),
    )
}

trait Substitution {
    /// Substitute any occurance of `'_` with `'static` and any bare `_` with
    /// `::core::marker::PhantomData::<F>`.
    fn substitute(&mut self, f: &Type);
}

impl Substitution for Type {
    fn substitute(&mut self, f: &Type) {
        match self {
            Type::Path(type_path) => {
                type_path.substitute(f);
            }
            Type::Tuple(tuple) => {
                for elem in &mut tuple.elems {
                    elem.substitute(f);
                }
            }
            Type::Infer(_) => {
                *self = parse_quote!(::core::marker::PhantomData<#f>);
            }
            _ => {}
        }
    }
}

impl Substitution for Lifetime {
    fn substitute(&mut self, _: &Type) {
        if self.ident == "_" {
            *self = parse_quote!('static);
        }
    }
}

impl Substitution for TypePath {
    fn substitute(&mut self, f: &Type) {
        for seg in &mut self.path.segments {
            if let PathArguments::AngleBracketed(ab) = &mut seg.arguments {
                for arg in ab.args.iter_mut() {
                    match arg {
                        GenericArgument::Type(t) => {
                            t.substitute(f);
                        }
                        GenericArgument::Lifetime(lt) => {
                            lt.substitute(f);
                        }
                        GenericArgument::Constraint(constraint) => {
                            constraint.bounds.iter_mut().for_each(|bound| {
                                bound.substitute(f);
                            });
                        }
                        GenericArgument::AssocType(assoc_type) => {
                            assoc_type.ty.substitute(f);
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

impl Substitution for TypeParamBound {
    fn substitute(&mut self, f: &Type) {
        if let TypeParamBound::Trait(trait_bound) = self {
            for seg in &mut trait_bound.path.segments {
                if let syn::PathArguments::AngleBracketed(ab) = &mut seg.arguments {
                    for arg in ab.args.iter_mut() {
                        match arg {
                            GenericArgument::Type(t) => {
                                t.substitute(f);
                            }
                            GenericArgument::Constraint(constraint) => {
                                constraint.bounds.iter_mut().for_each(|b| {
                                    b.substitute(f);
                                });
                            }
                            GenericArgument::AssocType(assoc_type) => {
                                assoc_type.ty.substitute(f);
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }
}

#[rustfmt::skip]
#[test]
fn test_evaluate() {
    use syn::parse_quote;

    assert_eq!(
        evaluate(
            parse_quote!(F; MyGadget<'_, _, C, 5>),
            parse_quote! {::ragu}
        )
        .unwrap()
        .to_string(),
        quote!(
            <MyGadget<'static, ::core::marker::PhantomData<F>, C, 5> as ::ragu::gadgets::Gadget<'static, ::core::marker::PhantomData<F>>>::Kind
        )
        .to_string()
    );
}

pub mod consistent;
pub mod gadget;
pub mod gadgetwrite;

use proc_macro2::Span;
use syn::{AngleBracketedGenericArguments, GenericArgument, Lifetime, Type, parse_quote};

use crate::helpers::GenericDriver;

impl GenericDriver {
    fn is_ty(&self, other: &Type) -> bool {
        if let Type::Path(path) = other
            && let Some(seg) = path.path.segments.last()
            && seg.ident == self.ident
        {
            return true;
        }
        false
    }

    fn is_lt(&self, other: &Lifetime) -> bool {
        self.lifetime.ident == other.ident
    }

    fn kind_subst_arguments(
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
}

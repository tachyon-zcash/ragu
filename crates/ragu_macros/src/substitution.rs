use syn::{
    GenericArgument, GenericParam, Ident, Lifetime, PathArguments, Type, TypeParam, TypeParamBound,
    TypePath, parse_quote,
};

trait Strategy {
    fn ty_path(&self, _: &mut TypePath) -> bool {
        false
    }
    fn ty(&self, _: &mut Type) -> bool {
        false
    }
    fn lt(&self, _: &mut Lifetime) -> bool {
        false
    }
}

trait Substitution {
    fn substitute(&mut self, strategy: &impl Strategy);
}

impl Substitution for Lifetime {
    fn substitute(&mut self, strategy: &impl Strategy) {
        strategy.lt(self);
    }
}

impl Substitution for GenericArgument {
    fn substitute(&mut self, strategy: &impl Strategy) {
        match self {
            GenericArgument::Type(t) => {
                t.substitute(strategy);
            }
            GenericArgument::Lifetime(lt) => {
                lt.substitute(strategy);
            }
            GenericArgument::Constraint(constraint) => {
                constraint.bounds.iter_mut().for_each(|bound| {
                    bound.substitute(strategy);
                });
            }
            GenericArgument::AssocType(assoc_type) => {
                assoc_type.ty.substitute(strategy);
            }
            _ => {}
        }
    }
}

impl Substitution for TypePath {
    fn substitute(&mut self, strategy: &impl Strategy) {
        if strategy.ty_path(self) {
            return;
        }

        for seg in &mut self.path.segments {
            if let PathArguments::AngleBracketed(ab) = &mut seg.arguments {
                for arg in ab.args.iter_mut() {
                    arg.substitute(strategy);
                }
            }
        }
    }
}

impl Substitution for Type {
    fn substitute(&mut self, strategy: &impl Strategy) {
        if strategy.ty(self) {
            return;
        }

        match self {
            Type::Path(type_path) => {
                type_path.substitute(strategy);
            }
            Type::Tuple(tuple) => {
                for elem in &mut tuple.elems {
                    elem.substitute(strategy);
                }
            }
            _ => {}
        }
    }
}

impl Substitution for TypeParamBound {
    fn substitute(&mut self, strategy: &impl Strategy) {
        if let TypeParamBound::Trait(trait_bound) = self {
            for seg in &mut trait_bound.path.segments {
                if let syn::PathArguments::AngleBracketed(ab) = &mut seg.arguments {
                    for arg in ab.args.iter_mut() {
                        arg.substitute(strategy);
                    }
                }
            }
        }
    }
}

/// Replace '_ with 'static
/// Replace _ with ::core::marker::PhantomData<$F>
pub fn replace_inferences(ty: &mut Type, field_type: &Type) {
    struct PhantomField<'a> {
        field_type: &'a Type,
    }

    impl Strategy for PhantomField<'_> {
        fn ty(&self, t: &mut Type) -> bool {
            match t {
                Type::Infer(_) => {
                    let replace = self.field_type;
                    *t = parse_quote!(::core::marker::PhantomData<#replace>);
                    true
                }
                _ => false,
            }
        }

        fn lt(&self, lt: &mut Lifetime) -> bool {
            if lt.ident == "_" {
                *lt = parse_quote!('static);
                return true;
            }
            false
        }
    }

    ty.substitute(&PhantomField { field_type });
}

/// Replace $D::F with $DriverField
pub fn replace_driver_field_in_generic_param(
    param: &mut syn::GenericParam,
    driver_id: &syn::Ident,
    driverfield_ident: &syn::Ident,
) {
    struct DriverFieldSubstitution<'a> {
        driver_id: &'a Ident,
        driverfield_ident: &'a Ident,
    }

    impl Strategy for DriverFieldSubstitution<'_> {
        fn ty_path(&self, ty_path: &mut TypePath) -> bool {
            if ty_path.qself.is_none() && ty_path.path.segments.len() == 2 {
                let segs = &ty_path.path.segments;
                if segs[0].ident == *self.driver_id && segs[1].ident == "F" {
                    let driverfield_ident = self.driverfield_ident;
                    *ty_path = parse_quote!(#driverfield_ident);
                    return true;
                }
            }

            false
        }
    }

    let strategy = &DriverFieldSubstitution {
        driver_id,
        driverfield_ident,
    };

    if let GenericParam::Type(TypeParam {
        bounds, default, ..
    }) = param
    {
        for bound in bounds.iter_mut() {
            bound.substitute(strategy);
        }
        if let Some(default_ty) = default {
            default_ty.1.substitute(strategy);
        }
    }
}

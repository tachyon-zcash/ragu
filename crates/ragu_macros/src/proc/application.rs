//! Implementation of the `#[application]` proc-macro.
//!
//! Parses an enum annotated with `#[application]` and generates:
//! - `ragu_pcd::step::Step` impls (with `const INDEX`) bridging from `ragu_app::Step`
//! - A wrapper struct with typed `build()`/`seed()`/`fuse()`/`verify()`/`rerandomize()`
//! - Compile-time assertions for header suffix uniqueness

use std::collections::BTreeSet;

use heck::ToSnakeCase;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{
    Attribute, Error, Fields, GenericParam, Generics, Ident, ItemEnum, Result, Token, Type,
    Variant, Visibility, parse::Parse, parse::ParseStream,
};

use crate::path_resolution::RaguAppPath;

/// Main entry point for the `#[application]` macro.
///
/// # Example
///
/// ```ignore
/// #[application]
/// enum MyApp<'param, C: Cycle> {
///    #[step(output = LeafNode)]
///    WitnessLeaf(WitnessLeaf<'params, C>),
///
///    #[step(output = HashNode)]
///    Hash2(Hash2<'params, C>),
/// }
pub fn evaluate(input: ItemEnum) -> Result<TokenStream> {
    let app = RaguAppPath::resolve()?;

    let vis = &input.vis;
    let enum_ident = &input.ident;
    let enum_generics = &input.generics;
    let cycle = find_cycle_param(enum_generics)?;
    let params_lt = find_params_lifetime(enum_generics)?;

    // Parse all variants, each variant is a step type with a #[step(...)] attribute.
    // The variant name (e.g. `WitnessLeaf`) is used as the `build()` parameter name
    // (converted to snake_case); the inner type is the actual Step implementor.
    let mut variants = Vec::new();
    for (index, variant) in input.variants.iter().enumerate() {
        let step_attr = parse_step_attr(&variant.attrs)?;
        let step_ty = extract_variant_type(variant)?;
        variants.push(ParsedVariant {
            name: variant.ident.clone(),
            step_ty,
            step_attr,
            index,
        });
    }

    if variants.is_empty() {
        return Err(Error::new_spanned(
            &input,
            "application must have at least one step",
        ));
    }

    // Collect unique headers for suffix/Header impl generation.
    let headers = collect_unique_headers(&variants);
    // All generated code references items through `ragu_app::__macro_internal`.
    let prelude = quote!(#app::__macro_internal);

    let header_impls = generate_header_impls(&headers, &app, &prelude);
    let step_impls = generate_step_impls(&variants, enum_generics, &cycle, &app, &prelude)?;
    let wrapper = generate_wrapper(
        vis,
        enum_ident,
        enum_generics,
        &cycle,
        &params_lt,
        &variants,
        &headers,
        &app,
        &prelude,
    )?;

    Ok(quote! {
        #header_impls
        #step_impls
        #wrapper
    })
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

/// Parsed `#[step(...)]` attribute on a variant.
/// Expected format: `#[step(output = Type)]`
///
/// Only the `output` header type is required — left/right are inferred from
/// the `ragu_app::Step` trait implementation. The macro needs `output` to
/// collect unique header types for suffix assignment (proc-macros can't
/// resolve associated types).
struct StepAttr {
    output: Type,
}

impl Parse for StepAttr {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let mut output = None;

        while !input.is_empty() {
            let ident: Ident = input.parse()?;
            input.parse::<Token![=]>()?;
            let ty: Type = input.parse()?;

            match ident.to_string().as_str() {
                "output" => output = Some(ty),
                other => {
                    return Err(Error::new(
                        ident.span(),
                        format!("unknown attribute `{other}`"),
                    ));
                }
            }

            if !input.is_empty() {
                input.parse::<Token![,]>()?;
            }
        }

        Ok(StepAttr {
            output: output
                .ok_or_else(|| Error::new(input.span(), "missing `output` in #[step(...)]"))?,
        })
    }
}

/// A parsed enum variant: its name (used for `build()` param naming),
/// inner step type, step attribute, and declaration index.
struct ParsedVariant {
    /// Variant name (e.g. `WitnessLeaf`), used to derive the `build()` parameter
    /// name via snake_case conversion (e.g. `witness_leaf`).
    name: Ident,
    step_ty: Type,
    step_attr: StepAttr,
    index: usize,
}

/// Extract the `#[step(...)]` attribute from a variant's attributes.
fn parse_step_attr(attrs: &[Attribute]) -> Result<StepAttr> {
    for attr in attrs {
        if attr.path().is_ident("step") {
            return attr.parse_args::<StepAttr>();
        }
    }
    Err(Error::new(
        proc_macro2::Span::call_site(),
        "missing #[step(...)] attribute on variant",
    ))
}

/// Extract the inner type from a tuple variant with exactly one unnamed field.
fn extract_variant_type(variant: &Variant) -> Result<Type> {
    match &variant.fields {
        Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
            Ok(fields.unnamed.first().unwrap().ty.clone())
        }
        _ => Err(Error::new_spanned(
            variant,
            "application variants must be tuple variants with exactly one field",
        )),
    }
}

/// Collect unique non-unit header types from step `output` attributes,
/// preserving first-appearance order (which determines suffix assignment).
fn collect_unique_headers(variants: &[ParsedVariant]) -> Vec<Type> {
    let mut seen = BTreeSet::new();
    let mut headers = Vec::new();
    for v in variants {
        let ty = &v.step_attr.output;
        if is_unit_type(ty) {
            continue;
        }
        if seen.insert(quote!(#ty).to_string()) {
            headers.push(ty.clone());
        }
    }
    headers
}

fn is_unit_type(ty: &Type) -> bool {
    matches!(ty, Type::Tuple(t) if t.elems.is_empty())
}

// ---------------------------------------------------------------------------
// Generics helpers
// ---------------------------------------------------------------------------

/// Extract the Cycle type parameter ident from the enum's generics.
fn find_cycle_param(generics: &Generics) -> Result<Ident> {
    generics
        .params
        .iter()
        .find_map(|p| match p {
            GenericParam::Type(t) => Some(t.ident.clone()),
            _ => None,
        })
        .ok_or_else(|| Error::new_spanned(generics, "expected a Cycle type parameter on the enum"))
}

/// Get the lifetime from enum generics to use as 'params for Application.
fn find_params_lifetime(generics: &Generics) -> Result<syn::Lifetime> {
    generics
        .params
        .iter()
        .find_map(|p| match p {
            GenericParam::Lifetime(lt) => Some(lt.lifetime.clone()),
            _ => None,
        })
        .ok_or_else(|| {
            Error::new_spanned(
                generics,
                "application enum must have a lifetime parameter (e.g., `'params`)",
            )
        })
}

/// Build the impl generic params: enum generics (with bounds) + extra params.
fn impl_generics_with(generics: &Generics, extra: TokenStream) -> TokenStream {
    let params: Vec<_> = generics.params.iter().collect();
    if params.is_empty() {
        extra
    } else {
        quote!(#(#params),*, #extra)
    }
}

/// Build type arguments from enum generics (just names, no bounds) + extra args.
fn type_args_with(generics: &Generics, extra: TokenStream) -> TokenStream {
    let args: Vec<TokenStream> = generics
        .params
        .iter()
        .map(|p| match p {
            GenericParam::Lifetime(lt) => {
                let lt = &lt.lifetime;
                quote!(#lt)
            }
            GenericParam::Type(t) => {
                let ident = &t.ident;
                quote!(#ident)
            }
            GenericParam::Const(c) => {
                let ident = &c.ident;
                quote!(#ident)
            }
        })
        .collect();
    if args.is_empty() {
        extra
    } else {
        quote!(#(#args),*, #extra)
    }
}

// ---------------------------------------------------------------------------
// Code generation
// ---------------------------------------------------------------------------

/// Generate `ragu_pcd::step::Step` impls that bridge from `ragu_app::Step`.
///
/// For each variant at position `i`, generates an impl of `PcdStep<C>` on the
/// inner step type with `const INDEX = Index::new(i)`. The generated `witness()`
/// method encodes left/right headers via `Encoded::new`, delegates to the
/// user's `ragu_app::Step::synthesize` (which works with pre-encoded `&Bound`
/// gadgets), then wraps the output via `Encoded::from_gadget`.
///
/// Associated types (`Left`, `Right`, `Output`) are delegated to the
/// `ragu_app::Step` trait — the macro doesn't need to know them.
///
/// # Example
///
/// For variant `#[step(output = ExponentNode)] Hash2(Hash2<'p, C>)` at index 1:
///
/// ```ignore
/// impl<'p, C: Cycle> PcdStep<C> for Hash2<'p, C>
/// where
///     Hash2<'p, C>: ragu_app::Step<C>,
///     <Hash2<'p, C> as ragu_app::Step<C>>::Left: Header<C::CircuitField>,
///     <Hash2<'p, C> as ragu_app::Step<C>>::Right: Header<C::CircuitField>,
///     <Hash2<'p, C> as ragu_app::Step<C>>::Output: Header<C::CircuitField>,
/// {
///     const INDEX: Index = Index::new(1);
///     type Left = <Hash2<'p, C> as ragu_app::Step<C>>::Left;
///     type Right = <Hash2<'p, C> as ragu_app::Step<C>>::Right;
///     type Output = <Hash2<'p, C> as ragu_app::Step<C>>::Output;
///     // ... witness() bridging impl
/// }
/// ```
fn generate_step_impls(
    variants: &[ParsedVariant],
    enum_generics: &Generics,
    cycle: &Ident,
    app: &RaguAppPath,
    prelude: &TokenStream,
) -> Result<TokenStream> {
    let mut impls = TokenStream::new();

    let enum_params: Vec<_> = enum_generics.params.iter().collect();

    for v in variants {
        let step_ty = &v.step_ty;
        let index = v.index;

        impls.extend(quote! {
            impl<#(#enum_params),*> #prelude::PcdStep<#cycle> for #step_ty
            where
                #step_ty: #app::Step<#cycle>,
                <#step_ty as #app::Step<#cycle>>::Left: #prelude::Header<#cycle::CircuitField>,
                <#step_ty as #app::Step<#cycle>>::Right: #prelude::Header<#cycle::CircuitField>,
                <#step_ty as #app::Step<#cycle>>::Output: #prelude::Header<#cycle::CircuitField>,
            {
                const INDEX: #prelude::Index = #prelude::Index::new(#index);

                type Witness<'source> = <#step_ty as #app::Step<#cycle>>::Witness;
                type Left = <#step_ty as #app::Step<#cycle>>::Left;
                type Right = <#step_ty as #app::Step<#cycle>>::Right;
                type Output = <#step_ty as #app::Step<#cycle>>::Output;
                type Aux<'source> = <#step_ty as #app::Step<#cycle>>::Aux;

                fn witness<'dr, 'source: 'dr, __D: #prelude::Driver<'dr, F = #cycle::CircuitField>, const HEADER_SIZE: usize>(
                    &self,
                    dr: &mut __D,
                    witness: #prelude::DriverValue<__D, Self::Witness<'source>>,
                    left: #prelude::DriverValue<
                        __D,
                        <Self::Left as #prelude::Header<#cycle::CircuitField>>::Data,
                    >,
                    right: #prelude::DriverValue<
                        __D,
                        <Self::Right as #prelude::Header<#cycle::CircuitField>>::Data,
                    >,
                ) -> #prelude::Result<(
                    (
                        #prelude::Encoded<'dr, __D, Self::Left, HEADER_SIZE>,
                        #prelude::Encoded<'dr, __D, Self::Right, HEADER_SIZE>,
                        #prelude::Encoded<'dr, __D, Self::Output, HEADER_SIZE>,
                    ),
                    #prelude::DriverValue<
                        __D,
                        <Self::Output as #prelude::Header<#cycle::CircuitField>>::Data,
                    >,
                    #prelude::DriverValue<__D, Self::Aux<'source>>,
                )>
                where
                    Self: 'dr,
                {
                    let left_enc = #prelude::Encoded::new(dr, left)?;
                    let right_enc = #prelude::Encoded::new(dr, right)?;

                    // Helper to propagate HEADER_SIZE to synthesize.
                    fn call_synthesize<'dr, __C2: #app::Cycle, __D2: #prelude::Driver<'dr, F = __C2::CircuitField>, __S2, const HS: usize>(
                        step: &__S2,
                        dr: &mut __D2,
                        witness: #prelude::DriverValue<__D2, __S2::Witness>,
                        left: &#prelude::Bound<'dr, __D2, <__S2::Left as #prelude::Header<__C2::CircuitField>>::Output>,
                        right: &#prelude::Bound<'dr, __D2, <__S2::Right as #prelude::Header<__C2::CircuitField>>::Output>,
                    ) -> #prelude::Result<(
                        #prelude::Bound<'dr, __D2, <__S2::Output as #prelude::Header<__C2::CircuitField>>::Output>,
                        #prelude::DriverValue<__D2, <__S2::Output as #prelude::Header<__C2::CircuitField>>::Data>,
                        #prelude::DriverValue<__D2, __S2::Aux>,
                    )>
                    where
                        __S2: #app::Step<__C2> + 'dr,
                    {
                        __S2::synthesize::<__D2, HS>(step, dr, witness, left, right)
                    }

                    let (output_gadget, output_data, aux) =
                        call_synthesize::<#cycle, __D, #step_ty, HEADER_SIZE>(
                            self,
                            dr,
                            witness,
                            left_enc.as_gadget(),
                            right_enc.as_gadget(),
                        )?;

                    let output_enc = #prelude::Encoded::from_gadget(output_gadget);
                    Ok(((left_enc, right_enc, output_enc), output_data, aux))
                }
            }
        });
    }

    Ok(impls)
}

/// Generate `ragu_pcd::header::Header` impls from `ragu_app::HeaderContent` impls.
///
/// Each unique non-unit header type gets an auto-assigned `const SUFFIX` based
/// on its first-appearance order across all `#[step(...)]` attributes. The unit
/// type `()` already has a blanket `Header` impl and is skipped.
///
/// # Example
///
/// Given headers `[LeafNode, ExponentNode, ScaledPoint]` (collected in order):
///
/// ```ignore
/// impl<F: Field> Header<F> for LeafNode
/// where LeafNode: HeaderContent<F> {
///     const SUFFIX: Suffix = Suffix::new(0);
///     // ... delegates Data/Output/encode to HeaderContent
/// }
/// impl<F: Field> Header<F> for ExponentNode
/// where ExponentNode: HeaderContent<F> {
///     const SUFFIX: Suffix = Suffix::new(1);
///     // ...
/// }
/// impl<F: Field> Header<F> for ScaledPoint
/// where ScaledPoint: HeaderContent<F> {
///     const SUFFIX: Suffix = Suffix::new(2);
///     // ...
/// }
/// ```
fn generate_header_impls(
    headers: &[Type],
    app: &RaguAppPath,
    prelude: &TokenStream,
) -> TokenStream {
    let mut impls = TokenStream::new();

    for (i, header_ty) in headers.iter().enumerate() {
        impls.extend(quote! {
            impl<__F: #prelude::Field> #prelude::Header<__F> for #header_ty
            where
                #header_ty: #app::HeaderContent<__F>,
            {
                const SUFFIX: #prelude::Suffix = #prelude::Suffix::new(#i);

                type Data = <#header_ty as #app::HeaderContent<__F>>::Data;
                type Output = <#header_ty as #app::HeaderContent<__F>>::Output;

                fn encode<'dr, __D: #prelude::Driver<'dr, F = __F>>(
                    dr: &mut __D,
                    witness: #prelude::DriverValue<__D, Self::Data>,
                ) -> #prelude::Result<#prelude::Bound<'dr, __D, Self::Output>> {
                    <#header_ty as #app::HeaderContent<__F>>::encode(dr, witness)
                }
            }
        });
    }

    impls
}

/// Generate the wrapper struct and its `build`/`seed`/`fuse`/`verify`/
/// `rerandomize`/`trivial_pcd` methods.
///
/// # Example transformation
///
/// Given the input enum (after parsing):
///
/// ```ignore
/// #[application]
/// pub enum ExampleApp<'params, C: Cycle> {
///     #[step(output = LeafNode)]
///     WitnessLeaf(WitnessLeaf<'params, C>),
///
///     #[step(output = ExponentNode)]
///     Hash2(Hash2<'params, C>),
/// }
/// ```
///
/// This function generates:
///
/// ```ignore
/// pub struct ExampleApp<'params, C: Cycle, __R: Rank, const HEADER_SIZE: usize> {
///     inner: Application<'params, C, __R, HEADER_SIZE>,
/// }
///
/// impl<'params, C: Cycle, __R: Rank, const HEADER_SIZE: usize>
///     ExampleApp<'params, C, __R, HEADER_SIZE>
/// where
///     // Header bounds — needed so non-generic headers (e.g. `ScaledPoint:
///     // Header<Fp>`) gate the impl to compatible cycles.
///     LeafNode: Header<C::CircuitField>,
///     ExponentNode: Header<C::CircuitField>,
///     // Step bounds — needed because `build()` calls `.register()` which
///     // requires `PcdStep<C>`, and the generated `PcdStep` impls are
///     // conditional on `ragu_app::Step<C>`. Without these, non-generic
///     // steps (e.g. `Endoscale: Step<Pasta>`) fail to resolve for
///     // generic `C`.
///     WitnessLeaf<'params, C>: Step<C>,
///     Hash2<'params, C>: Step<C>,
/// {
///     pub fn build(
///         params: &'params C::Params,
///         witness_leaf: WitnessLeaf<'params, C>,  // snake_case of variant name
///         hash2: Hash2<'params, C>,
///     ) -> Result<Self> { /* registers each step then finalizes */ }
///
///     pub fn seed(...)  -> Result<(Pcd<..., S::Output>, S::Aux)> { ... }
///     pub fn fuse(...)  -> Result<(Pcd<..., S::Output>, S::Aux)> { ... }
///     pub fn verify(...) -> Result<bool> { ... }
///     pub fn rerandomize(...) -> Result<Pcd<..., H>> { ... }
///     pub fn trivial_pcd(...) -> Pcd<..., ()> { ... }
/// }
/// ```
#[allow(clippy::too_many_arguments)]
fn generate_wrapper(
    vis: &Visibility,
    enum_ident: &Ident,
    enum_generics: &Generics,
    cycle: &Ident,
    params_lt: &syn::Lifetime,
    variants: &[ParsedVariant],
    headers: &[Type],
    app: &RaguAppPath,
    prelude: &TokenStream,
) -> Result<TokenStream> {
    // `build()` parameters: one per variant, snake_case name with the step type.
    // e.g. `WitnessLeaf(WitnessLeaf<'p, C>)` → `witness_leaf: WitnessLeaf<'p, C>`
    let build_params: Vec<_> = variants
        .iter()
        .map(|v| {
            let name = format_ident!("{}", v.name.to_string().to_snake_case());
            let ty = &v.step_ty;
            quote!(#name: #ty)
        })
        .collect();

    // Chained `.register(step)?` calls inside `build()`, one per variant.
    let register_calls: Vec<_> = variants
        .iter()
        .map(|v| {
            let name = format_ident!("{}", v.name.to_string().to_snake_case());
            quote!(.register(#name)?)
        })
        .collect();

    // Struct/impl generics: enum's own params + `__R: Rank, const HEADER_SIZE: usize`.
    let impl_gen = impl_generics_with(
        enum_generics,
        quote!(__R: #prelude::Rank, const HEADER_SIZE: usize),
    );
    let struct_args = type_args_with(enum_generics, quote!(__R, HEADER_SIZE));

    // Where clause: each unique header must impl `Header<C::CircuitField>`.
    let header_bounds: Vec<_> = headers
        .iter()
        .map(|h| quote!(#h: #prelude::Header<#cycle::CircuitField>))
        .collect();

    // Where clause: each step type must impl `ragu_app::Step<C>`.
    // Required so `.register()` in `build()` can resolve the generated
    // `PcdStep<C>` impl (which is conditional on this bound). Without these,
    // non-generic steps (e.g. `Endoscale: Step<Pasta>`) fail to resolve for
    // generic `C`.
    let step_bounds: Vec<_> = variants
        .iter()
        .map(|v| {
            let step_ty = &v.step_ty;
            quote!(#step_ty: #app::Step<#cycle>)
        })
        .collect();

    Ok(quote! {
        /// Generated application wrapper.
        #vis struct #enum_ident<#impl_gen> {
            inner: #prelude::Application<#params_lt, #cycle, __R, HEADER_SIZE>,
        }

        impl<#impl_gen> #enum_ident<#struct_args>
        where
            #(#header_bounds,)*
            #(#step_bounds,)*
        {
            /// Build the application by registering all steps.
            #vis fn build(
                params: &#params_lt #cycle::Params,
                #(#build_params),*
            ) -> #prelude::Result<Self> {
                let inner = #prelude::ApplicationBuilder::<#cycle, __R, HEADER_SIZE>::new()
                    #(#register_calls)*
                    .finalize(params)?;
                Ok(Self { inner })
            }

            /// Seed a new computation by running a step with trivial inputs.
            #vis fn seed<'source, __RNG: #prelude::CryptoRng, __S: #prelude::PcdStep<#cycle, Left = (), Right = ()>>(
                &self,
                rng: &mut __RNG,
                step: __S,
                witness: __S::Witness<'source>,
            ) -> #prelude::Result<(#prelude::Pcd<#cycle, __R, __S::Output>, __S::Aux<'source>)> {
                self.inner.seed(rng, step, witness)
            }

            /// Fuse two pieces of proof-carrying data using a step.
            #vis fn fuse<'source, __RNG: #prelude::CryptoRng, __S: #prelude::PcdStep<#cycle>>(
                &self,
                rng: &mut __RNG,
                step: __S,
                witness: __S::Witness<'source>,
                left: #prelude::Pcd<#cycle, __R, __S::Left>,
                right: #prelude::Pcd<#cycle, __R, __S::Right>,
            ) -> #prelude::Result<(#prelude::Pcd<#cycle, __R, __S::Output>, __S::Aux<'source>)> {
                self.inner.fuse(rng, step, witness, left, right)
            }

            /// Verify proof-carrying data.
            #vis fn verify<__RNG: #prelude::CryptoRng, __H: #prelude::Header<#cycle::CircuitField>>(
                &self,
                pcd: &#prelude::Pcd<#cycle, __R, __H>,
                rng: __RNG,
            ) -> #prelude::Result<bool> {
                self.inner.verify(pcd, rng)
            }

            /// Rerandomize proof-carrying data.
            #vis fn rerandomize<__RNG: #prelude::CryptoRng, __H: #prelude::Header<#cycle::CircuitField>>(
                &self,
                pcd: #prelude::Pcd<#cycle, __R, __H>,
                rng: &mut __RNG,
            ) -> #prelude::Result<#prelude::Pcd<#cycle, __R, __H>> {
                self.inner.rerandomize(pcd, rng)
            }

            /// Returns a seeded trivial PCD with no header data, suitable
            /// as a placeholder input for steps that only use one of their
            /// two inputs.
            #vis fn trivial_pcd<__RNG: #prelude::CryptoRng>(&self, rng: &mut __RNG) -> #prelude::Pcd<#cycle, __R, ()> {
                self.inner.seeded_trivial_pcd(rng)
            }
        }
    })
}

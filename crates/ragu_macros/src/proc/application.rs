//! Implementation of the `#[application]` proc-macro.
//!
//! Parses an enum annotated with `#[application]` and generates:
//! - `ragu_pcd::step::Step` impls (with `const INDEX`) bridging from `ragu_app::Step`
//! - A wrapper struct with typed `build()`/`seed()`/`fuse()`/`verify()`/`rerandomize()`
//! - Compile-time assertions for header suffix uniqueness
//!
//! The enum carries no generics: the macro supplies `<'params, C: Cycle>`
//! itself. Each variant is a unit variant whose name is the step type,
//! which must take `<'params, C: Cycle>` generics, annotated with
//! `#[produces(OutputHeader)]`.

use std::collections::BTreeSet;

use heck::ToSnakeCase;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Error, Fields, Ident, ItemEnum, Result, Type, Variant, Visibility};

use crate::path_resolution::RaguAppPath;

/// Main entry point for the `#[application]` macro.
///
/// # Example
///
/// ```ignore
/// #[application]
/// enum MyApp {
///    #[produces(LeafNode)]
///    WitnessLeaf,
///
///    #[produces(HashNode)]
///    Hash2,
/// }
pub fn evaluate(input: ItemEnum) -> Result<TokenStream> {
    let app = RaguAppPath::resolve()?;

    let vis = &input.vis;
    let enum_ident = &input.ident;

    if !input.generics.params.is_empty() || input.generics.where_clause.is_some() {
        return Err(Error::new_spanned(
            &input.generics,
            "#[application] enums must not have generic parameters or where clauses; \
             the macro supplies `<'params, C: Cycle>` itself",
        ));
    }

    // Parse all variants. Each variant is a unit variant whose name is the
    // step type (instantiated as `Name<'params, C>`), annotated with a
    // #[produces(...)] attribute naming the output header. The variant name
    // is also used as the `build()` parameter name (converted to snake_case).
    let mut variants = Vec::new();
    for (index, variant) in input.variants.iter().enumerate() {
        if !matches!(variant.fields, Fields::Unit) {
            return Err(Error::new_spanned(
                variant,
                "application variants must be unit variants naming a step type \
                 with `<'params, C: Cycle>` generics",
            ));
        }
        let output = parse_produces_attr(variant)?;
        let name = variant.ident.clone();
        let step_ty = quote!(#name<'params, C>);
        variants.push(ParsedVariant {
            name,
            step_ty,
            output,
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
    let step_impls = generate_step_impls(&variants, &app, &prelude);
    let wrapper = generate_wrapper(vis, enum_ident, &variants, &headers, &app, &prelude);

    Ok(quote! {
        #header_impls
        #step_impls
        #wrapper
    })
}

/// A parsed enum variant: its name (which doubles as the step type name and,
/// via snake_case conversion, the `build()` parameter name), the instantiated
/// step type, the output header, and the declaration index.
struct ParsedVariant {
    /// Variant name (e.g. `WitnessLeaf`), which is the step type's name and
    /// derives the `build()` parameter name (e.g. `witness_leaf`).
    name: Ident,
    /// The step type: the variant name applied to the macro-supplied
    /// generics, i.e. `Name<'params, C>`.
    step_ty: TokenStream,
    /// The output header type from `#[produces(...)]`.
    output: Type,
    index: usize,
}

/// Extract the output header type from a variant's `#[produces(...)]` attribute.
fn parse_produces_attr(variant: &Variant) -> Result<Type> {
    for attr in &variant.attrs {
        if attr.path().is_ident("produces") {
            return attr.parse_args::<Type>();
        }
    }
    Err(Error::new_spanned(
        variant,
        "missing #[produces(...)] attribute on variant",
    ))
}

/// Collect unique non-unit header types from step `output` attributes,
/// preserving first-appearance order (which determines suffix assignment).
fn collect_unique_headers(variants: &[ParsedVariant]) -> Vec<Type> {
    let mut seen = BTreeSet::new();
    let mut headers = Vec::new();
    for v in variants {
        let ty = &v.output;
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
/// For variant `#[produces(ExponentNode)] Hash2` at index 1:
///
/// ```ignore
/// impl<'params, C: Cycle> PcdStep<C> for Hash2<'params, C>
/// where
///     Hash2<'params, C>: ragu_app::Step<C>,
///     <Hash2<'params, C> as ragu_app::Step<C>>::Left: Header<C::CircuitField>,
///     <Hash2<'params, C> as ragu_app::Step<C>>::Right: Header<C::CircuitField>,
///     <Hash2<'params, C> as ragu_app::Step<C>>::Output: Header<C::CircuitField>,
/// {
///     const INDEX: Index = Index::new(1);
///     type Left = <Hash2<'params, C> as ragu_app::Step<C>>::Left;
///     type Right = <Hash2<'params, C> as ragu_app::Step<C>>::Right;
///     type Output = <Hash2<'params, C> as ragu_app::Step<C>>::Output;
///     // ... witness() bridging impl
/// }
/// ```
fn generate_step_impls(
    variants: &[ParsedVariant],
    app: &RaguAppPath,
    prelude: &TokenStream,
) -> TokenStream {
    let mut impls = TokenStream::new();

    for v in variants {
        let step_ty = &v.step_ty;
        let index = v.index;

        impls.extend(quote! {
            impl<'params, C: #app::Cycle> #prelude::PcdStep<C> for #step_ty
            where
                #step_ty: #app::Step<C>,
                <#step_ty as #app::Step<C>>::Left: #prelude::Header<C::CircuitField>,
                <#step_ty as #app::Step<C>>::Right: #prelude::Header<C::CircuitField>,
                <#step_ty as #app::Step<C>>::Output: #prelude::Header<C::CircuitField>,
            {
                const INDEX: #prelude::Index = #prelude::Index::new(#index);

                type Witness<'source> = <#step_ty as #app::Step<C>>::Witness;
                type Left = <#step_ty as #app::Step<C>>::Left;
                type Right = <#step_ty as #app::Step<C>>::Right;
                type Output = <#step_ty as #app::Step<C>>::Output;
                type Aux<'source> = <#step_ty as #app::Step<C>>::Aux;

                fn witness<'dr, 'source: 'dr, __D: #prelude::Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
                    &self,
                    dr: &mut __D,
                    witness: #prelude::DriverValue<__D, Self::Witness<'source>>,
                    left: #prelude::DriverValue<
                        __D,
                        <Self::Left as #prelude::Header<C::CircuitField>>::Data,
                    >,
                    right: #prelude::DriverValue<
                        __D,
                        <Self::Right as #prelude::Header<C::CircuitField>>::Data,
                    >,
                ) -> #prelude::Result<(
                    (
                        #prelude::Encoded<'dr, __D, Self::Left, HEADER_SIZE>,
                        #prelude::Encoded<'dr, __D, Self::Right, HEADER_SIZE>,
                        #prelude::Encoded<'dr, __D, Self::Output, HEADER_SIZE>,
                    ),
                    #prelude::DriverValue<
                        __D,
                        <Self::Output as #prelude::Header<C::CircuitField>>::Data,
                    >,
                    #prelude::DriverValue<__D, Self::Aux<'source>>,
                )>
                where
                    Self: 'dr,
                {
                    let allocator = &mut #prelude::Standard::new();
                    let left_enc = #prelude::Encoded::new(dr, allocator, left)?;
                    let right_enc = #prelude::Encoded::new(dr, allocator, right)?;

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
                        call_synthesize::<C, __D, #step_ty, HEADER_SIZE>(
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

    impls
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

                fn encode<'dr, __D: #prelude::Driver<'dr, F = __F>, __A: #prelude::Allocator<'dr, __D>>(
                    dr: &mut __D,
                    allocator: &mut __A,
                    witness: #prelude::DriverValue<__D, Self::Data>,
                ) -> #prelude::Result<#prelude::Bound<'dr, __D, Self::Output>> {
                    <#header_ty as #app::HeaderContent<__F>>::encode(dr, allocator, witness)
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
/// pub enum ExampleApp {
///     #[produces(LeafNode)]
///     WitnessLeaf,
///
///     #[produces(ExponentNode)]
///     Hash2,
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
///     // conditional on `ragu_app::Step<C>`. Without these, steps
///     // implemented for one concrete cycle (e.g. `Endoscale<'_, Pasta>:
///     // Step<Pasta>`) fail to resolve for generic `C`.
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
fn generate_wrapper(
    vis: &Visibility,
    enum_ident: &Ident,
    variants: &[ParsedVariant],
    headers: &[Type],
    app: &RaguAppPath,
    prelude: &TokenStream,
) -> TokenStream {
    // `build()` parameters: one per variant, snake_case name with the step type.
    // e.g. `WitnessLeaf` → `witness_leaf: WitnessLeaf<'params, C>`
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

    // Struct/impl generics: the macro-supplied `'params, C: Cycle` plus
    // `__R: Rank, const HEADER_SIZE: usize`.
    let impl_gen = quote!('params, C: #app::Cycle, __R: #prelude::Rank, const HEADER_SIZE: usize);
    let struct_args = quote!('params, C, __R, HEADER_SIZE);

    // Where clause: each unique header must impl `Header<C::CircuitField>`.
    let header_bounds: Vec<_> = headers
        .iter()
        .map(|h| quote!(#h: #prelude::Header<C::CircuitField>))
        .collect();

    // Where clause: each step type must impl `ragu_app::Step<C>`.
    // Required so `.register()` in `build()` can resolve the generated
    // `PcdStep<C>` impl (which is conditional on this bound). Without these,
    // steps implemented for one concrete cycle (e.g. `Endoscale<'_, Pasta>:
    // Step<Pasta>`) fail to resolve for generic `C`.
    let step_bounds: Vec<_> = variants
        .iter()
        .map(|v| {
            let step_ty = &v.step_ty;
            quote!(#step_ty: #app::Step<C>)
        })
        .collect();

    quote! {
        /// Generated application wrapper.
        #vis struct #enum_ident<#impl_gen> {
            inner: #prelude::Application<'params, C, __R, HEADER_SIZE>,
        }

        impl<#impl_gen> #enum_ident<#struct_args>
        where
            #(#header_bounds,)*
            #(#step_bounds,)*
        {
            /// Build the application by registering all steps.
            #vis fn build(
                params: &'params C::Params,
                #(#build_params),*
            ) -> #prelude::Result<Self> {
                let inner = #prelude::ApplicationBuilder::<C, __R, HEADER_SIZE>::new()
                    #(#register_calls)*
                    .finalize(params)?;
                Ok(Self { inner })
            }

            /// Seed a new computation by running a step with trivial inputs.
            #vis fn seed<'source, __RNG: #prelude::CryptoRngCore, __S: #prelude::PcdStep<C, Left = (), Right = ()>>(
                &self,
                rng: &mut __RNG,
                step: __S,
                witness: __S::Witness<'source>,
            ) -> #prelude::Result<(#prelude::Pcd<C, __R, __S::Output>, __S::Aux<'source>)> {
                self.inner.seed(rng, step, witness)
            }

            /// Fuse two pieces of proof-carrying data using a step.
            #vis fn fuse<'source, __RNG: #prelude::CryptoRngCore, __S: #prelude::PcdStep<C>>(
                &self,
                rng: &mut __RNG,
                step: __S,
                witness: __S::Witness<'source>,
                left: #prelude::Pcd<C, __R, __S::Left>,
                right: #prelude::Pcd<C, __R, __S::Right>,
            ) -> #prelude::Result<(#prelude::Pcd<C, __R, __S::Output>, __S::Aux<'source>)> {
                self.inner.fuse(rng, step, witness, left, right)
            }

            /// Verify proof-carrying data.
            #vis fn verify<__RNG: #prelude::CryptoRngCore, __H: #prelude::Header<C::CircuitField>>(
                &self,
                pcd: &#prelude::Pcd<C, __R, __H>,
                rng: __RNG,
            ) -> #prelude::Result<bool> {
                self.inner.verify(pcd, rng)
            }

            /// Rerandomize proof-carrying data.
            #vis fn rerandomize<__RNG: #prelude::CryptoRngCore, __H: #prelude::Header<C::CircuitField>>(
                &self,
                pcd: #prelude::Pcd<C, __R, __H>,
                rng: &mut __RNG,
            ) -> #prelude::Result<#prelude::Pcd<C, __R, __H>> {
                self.inner.rerandomize(pcd, rng)
            }

            /// Returns a seeded trivial PCD with no header data, suitable
            /// as a placeholder input for steps that only use one of their
            /// two inputs.
            #vis fn trivial_pcd<__RNG: #prelude::CryptoRngCore>(&self, rng: &mut __RNG) -> #prelude::Pcd<C, __R, ()> {
                self.inner.seeded_trivial_pcd(rng)
            }
        }
    }
}

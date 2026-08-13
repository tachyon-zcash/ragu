//! Implementation of the `#[application]` proc-macro.
//!
//! Parses an enum annotated with `#[application]` and generates:
//! - `ragu_pcd::header::Header` impls with `const SUFFIX` values auto-assigned
//!   from the first-appearance order of `#[produces(...)]` header types
//! - `ragu_pcd::step::Step` impls (with `const INDEX`) bridging from `ragu_pcd::app::Step`
//! - A wrapper struct with typed `build()`/`seed()`/`fuse()`/`verify()`/`rerandomize()`
//!
//! The enum carries no generics: the macro supplies `<'params, C: Cycle>`
//! itself. Each variant is a unit variant whose name is the step type,
//! which must take `<'params, C: Cycle>` generics, annotated with
//! `#[produces(OutputHeader)]`.
//! If the same header is named through a type alias or a different path, use
//! `#[produces(OutputAlias, canonical = OutputHeader)]` so suffix assignment
//! uses one canonical spelling. The macro asserts that both names are the
//! same Rust type.
//!
//! `#[application(cycle = ..., rank = ..., header_size = ...)]` optionally
//! sets defaults for the generated wrapper's generic parameters, so the
//! application type can be named without turbofish.

use std::collections::BTreeSet;

use heck::ToSnakeCase;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{
    Error, Expr, Fields, Ident, ItemEnum, Result, Token, Type, Variant, Visibility,
    parse::{Parse, ParseStream},
};

use crate::path_resolution::RaguAppPath;

/// The parsed `#[application(...)]` attribute arguments: optional defaults
/// for the generated wrapper's generic parameters.
///
/// Because defaulted generic parameters must be trailing, `cycle` requires
/// `rank`, which in turn requires `header_size`.
pub struct ApplicationAttr {
    cycle: Option<Type>,
    rank: Option<Type>,
    header_size: Option<Expr>,
}

impl Parse for ApplicationAttr {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let mut cycle = None;
        let mut rank = None;
        let mut header_size = None;
        let mut cycle_span = None;
        let mut rank_span = None;

        while !input.is_empty() {
            let ident: Ident = input.parse()?;
            input.parse::<Token![=]>()?;

            match ident.to_string().as_str() {
                "cycle" => {
                    if cycle.is_some() {
                        return Err(Error::new(
                            ident.span(),
                            "duplicate `cycle` key in #[application(...)]",
                        ));
                    }
                    cycle_span = Some(ident.span());
                    cycle = Some(input.parse::<Type>()?);
                }
                "rank" => {
                    if rank.is_some() {
                        return Err(Error::new(
                            ident.span(),
                            "duplicate `rank` key in #[application(...)]",
                        ));
                    }
                    rank_span = Some(ident.span());
                    rank = Some(input.parse::<Type>()?);
                }
                "header_size" => {
                    if header_size.is_some() {
                        return Err(Error::new(
                            ident.span(),
                            "duplicate `header_size` key in #[application(...)]",
                        ));
                    }
                    header_size = Some(input.parse::<Expr>()?);
                }
                other => {
                    return Err(Error::new(
                        ident.span(),
                        format!(
                            "unknown attribute `{other}`, expected `cycle`, `rank`, or `header_size`"
                        ),
                    ));
                }
            }

            // Consume optional trailing comma.
            let _ = input.parse::<Token![,]>();
        }

        // The generated generics are ordered `C, __R, HEADER_SIZE`, and Rust
        // requires defaulted parameters to be trailing.
        if let (Some(span), None) = (cycle_span, &rank) {
            return Err(Error::new(
                span,
                "`cycle` default requires a `rank` default (defaults must be trailing)",
            ));
        }
        if let (Some(span), None) = (rank_span, &header_size) {
            return Err(Error::new(
                span,
                "`rank` default requires a `header_size` default (defaults must be trailing)",
            ));
        }

        Ok(ApplicationAttr {
            cycle,
            rank,
            header_size,
        })
    }
}

/// Main entry point for the `#[application]` macro.
///
/// # Example
///
/// ```ignore
/// #[application(cycle = Pasta, rank = ProductionRank, header_size = 4)]
/// enum MyApp {
///    #[produces(LeafNode)]
///    WitnessLeaf,
///
///    #[produces(HashNode)]
///    Hash2,
/// }
pub fn evaluate(attr: ApplicationAttr, input: ItemEnum) -> Result<TokenStream> {
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
        let produces = parse_produces_attr(variant)?;
        let output = produces.output;
        let (header, has_explicit_canonical) = match produces.canonical {
            Some(canonical) => (canonical, true),
            None => (output.clone(), false),
        };
        let name = variant.ident.clone();
        let step_ty = quote!(#name<'params, C>);
        variants.push(ParsedVariant {
            name,
            step_ty,
            output,
            header,
            has_explicit_canonical,
            index,
        });
    }

    if variants.is_empty() {
        return Err(Error::new_spanned(
            &input,
            "application must have at least one step",
        ));
    }

    // Collect unique canonical headers for suffix/Header impl generation.
    let headers = collect_unique_headers(&variants);
    // All generated code references items through `ragu_pcd::app::__macro_internal`.
    let prelude = quote!(#app::__macro_internal);

    let header_impls = generate_header_impls(&headers, &app, &prelude);
    let header_alias_assertions = generate_header_alias_assertions(&variants);
    let step_impls = generate_step_impls(&variants, &app, &prelude);
    let wrapper = generate_wrapper(vis, enum_ident, &attr, &variants, &headers, &app, &prelude);

    Ok(quote! {
        #header_alias_assertions
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
    /// The canonical spelling used to generate and deduplicate the `Header`
    /// implementation. This is normally identical to `output`.
    header: Type,
    /// Whether `header` came from an explicit `canonical = ...` option and
    /// therefore needs a generated semantic type-equality assertion.
    has_explicit_canonical: bool,
    index: usize,
}

/// Parsed contents of `#[produces(Output[, canonical = CanonicalOutput])]`.
struct ProducesAttr {
    output: Type,
    canonical: Option<Type>,
}

impl Parse for ProducesAttr {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let output = input.parse::<Type>()?;

        if input.is_empty() {
            return Ok(Self {
                output,
                canonical: None,
            });
        }

        input.parse::<Token![,]>()?;
        if input.is_empty() {
            return Ok(Self {
                output,
                canonical: None,
            });
        }

        let option = input.parse::<Ident>()?;
        if option != "canonical" {
            return Err(Error::new(
                option.span(),
                "unknown #[produces(...)] option; expected `canonical`",
            ));
        }
        input.parse::<Token![=]>()?;
        let canonical = input.parse::<Type>()?;

        if !input.is_empty() {
            input.parse::<Token![,]>()?;
        }
        if !input.is_empty() {
            return Err(input.error("unexpected tokens after `canonical` header type"));
        }

        Ok(Self {
            output,
            canonical: Some(canonical),
        })
    }
}

/// Extract the output header declaration from a variant's `#[produces(...)]`
/// attribute.
fn parse_produces_attr(variant: &Variant) -> Result<ProducesAttr> {
    let mut produces = None;
    for attr in &variant.attrs {
        if attr.path().is_ident("produces") {
            if produces.is_some() {
                return Err(Error::new_spanned(
                    attr,
                    "duplicate #[produces(...)] attribute on variant",
                ));
            }
            produces = Some(attr.parse_args::<ProducesAttr>()?);
        }
    }
    produces
        .ok_or_else(|| Error::new_spanned(variant, "missing #[produces(...)] attribute on variant"))
}

/// Collect syntactically unique non-unit canonical header types, preserving
/// first-appearance order (which determines suffix assignment).
///
/// Procedural macros cannot resolve aliases or decide whether two paths name
/// the same Rust type. Callers express that relationship with the optional
/// `canonical = ...` form, which makes `header` identical for deduplication and
/// is checked by [`generate_header_alias_assertions`].
fn collect_unique_headers(variants: &[ParsedVariant]) -> Vec<Type> {
    let mut seen = BTreeSet::new();
    let mut headers = Vec::new();
    for v in variants {
        let ty = &v.header;
        if is_unit_type(ty) {
            continue;
        }
        if seen.insert(quote!(#ty).to_string()) {
            headers.push(ty.clone());
        }
    }
    headers
}

/// Assert that every explicit canonical header spelling denotes exactly the
/// same Rust type as the output spelling.
///
/// A small identity function is enough to make rustc perform semantic type
/// resolution (including aliases), which a proc macro cannot do from tokens.
fn generate_header_alias_assertions(variants: &[ParsedVariant]) -> TokenStream {
    let assertions = variants.iter().filter_map(|variant| {
        if !variant.has_explicit_canonical {
            return None;
        }

        let output = &variant.output;
        let header = &variant.header;
        Some(quote! {
            const _: () = {
                fn __ragu_assert_same_header_type(value: #output) -> #header {
                    value
                }
            };
        })
    });

    quote!(#(#assertions)*)
}

fn is_unit_type(ty: &Type) -> bool {
    matches!(ty, Type::Tuple(t) if t.elems.is_empty())
}

/// Generate `ragu_pcd::step::Step` impls that bridge from `ragu_pcd::app::Step`.
///
/// For each variant at position `i`, generates an impl of `PcdStep<C>` on the
/// inner step type with `const INDEX = Index::new(i)`. The generated `witness()`
/// method encodes left/right headers via `Encoded::new`, delegates to the
/// user's `ragu_pcd::app::Step::synthesize` (which works with pre-encoded `&Bound`
/// gadgets), then wraps the output via `Encoded::from_gadget`.
///
/// Associated input types are delegated to `ragu_pcd::app::Step`. The output
/// is set to the type named by `#[produces(...)]`, and the where-clause requires
/// it to equal `ragu_pcd::app::Step::Output`.
///
/// # Example
///
/// For variant `#[produces(ExponentNode)] Hash2` at index 1:
///
/// ```ignore
/// impl<'params, C: Cycle> PcdStep<C> for Hash2<'params, C>
/// where
///     Hash2<'params, C>: ragu_pcd::app::Step<C, Output = ExponentNode>,
///     <Hash2<'params, C> as ragu_pcd::app::Step<C>>::Left: Header<C::CircuitField>,
///     <Hash2<'params, C> as ragu_pcd::app::Step<C>>::Right: Header<C::CircuitField>,
///     <Hash2<'params, C> as ragu_pcd::app::Step<C>>::Output: Header<C::CircuitField>,
/// {
///     const INDEX: Index = Index::new(1);
///     type Left = <Hash2<'params, C> as ragu_pcd::app::Step<C>>::Left;
///     type Right = <Hash2<'params, C> as ragu_pcd::app::Step<C>>::Right;
///     type Output = ExponentNode;
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
        let output = &v.output;
        let index = v.index;

        impls.extend(quote! {
            impl<'params, C: #app::Cycle> #prelude::PcdStep<C> for #step_ty
            where
                #step_ty: #app::Step<C, Output = #output>,
                <#step_ty as #app::Step<C>>::Left: #prelude::Header<C::CircuitField>,
                <#step_ty as #app::Step<C>>::Right: #prelude::Header<C::CircuitField>,
                #output: #prelude::Header<C::CircuitField>,
            {
                const INDEX: #prelude::Index = #prelude::Index::new(#index);

                type Witness<'source> = <#step_ty as #app::Step<C>>::Witness;
                type Left = <#step_ty as #app::Step<C>>::Left;
                type Right = <#step_ty as #app::Step<C>>::Right;
                type Output = #output;
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

/// Generate `ragu_pcd::header::Header` impls from `ragu_pcd::app::HeaderContent` impls.
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
/// #[application(cycle = Pasta, rank = ProductionRank, header_size = 4)]
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
/// pub struct ExampleApp<
///     'params,
///     C: Cycle = Pasta,
///     __R: Rank = ProductionRank,
///     const HEADER_SIZE: usize = 4,
/// > {
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
///     // conditional on `ragu_pcd::app::Step<C>`. Without these, steps
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
#[allow(clippy::too_many_arguments)]
fn generate_wrapper(
    vis: &Visibility,
    enum_ident: &Ident,
    attr: &ApplicationAttr,
    variants: &[ParsedVariant],
    headers: &[Type],
    app: &RaguAppPath,
    prelude: &TokenStream,
) -> TokenStream {
    // Private marker traits make the generated wrapper a closed application
    // boundary. Downstream crates cannot implement these traits for a foreign
    // step/header that happens to reuse the same INDEX/SUFFIX values.
    let step_marker = format_ident!("__RaguApplicationStepFor{}", enum_ident);
    let header_marker = format_ident!("__RaguApplicationHeaderFor{}", enum_ident);

    let step_memberships: Vec<_> = variants
        .iter()
        .map(|variant| {
            let step_ty = &variant.step_ty;
            quote! {
                impl<'params, C: #app::Cycle> #step_marker<C> for #step_ty {}
            }
        })
        .collect();

    let header_memberships: Vec<_> = headers
        .iter()
        .map(|header| {
            quote! {
                impl<__F: #prelude::Field> #header_marker<__F> for #header
                where
                    #header: #prelude::Header<__F>,
                {}
            }
        })
        .collect();

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
    // `__R: Rank, const HEADER_SIZE: usize`. The struct declaration carries
    // any defaults from `#[application(...)]`; impls repeat the generics
    // without them (defaults are not permitted in impl generics).
    let cycle_default = attr
        .cycle
        .as_ref()
        .map(|t| quote!(= #t))
        .unwrap_or_default();
    let rank_default = attr.rank.as_ref().map(|t| quote!(= #t)).unwrap_or_default();
    let header_size_default = attr
        .header_size
        .as_ref()
        .map(|e| quote!(= #e))
        .unwrap_or_default();
    let struct_gen = quote!(
        'params,
        C: #app::Cycle #cycle_default,
        __R: #prelude::Rank #rank_default,
        const HEADER_SIZE: usize #header_size_default
    );
    let impl_gen = quote!('params, C: #app::Cycle, __R: #prelude::Rank, const HEADER_SIZE: usize);
    let struct_args = quote!('params, C, __R, HEADER_SIZE);

    // Where clause: each unique header must impl `Header<C::CircuitField>`.
    let header_bounds: Vec<_> = headers
        .iter()
        .map(|h| quote!(#h: #prelude::Header<C::CircuitField>))
        .collect();

    // Where clause: each step type must impl `ragu_pcd::app::Step<C>`.
    // Required so `.register()` in `build()` can resolve the generated
    // `PcdStep<C>` impl (which is conditional on this bound). Without these,
    // steps implemented for one concrete cycle (e.g. `Endoscale<'_, Pasta>:
    // Step<Pasta>`) fail to resolve for generic `C`.
    let step_bounds: Vec<_> = variants
        .iter()
        .map(|v| {
            let step_ty = &v.step_ty;
            let output = &v.output;
            quote!(#step_ty: #app::Step<C, Output = #output>)
        })
        .collect();

    quote! {
        // These deliberately remain private even when the application wrapper
        // is public: they seal its generic methods to the declared membership.
        #[doc(hidden)]
        trait #step_marker<__C: #app::Cycle> {}

        #[doc(hidden)]
        trait #header_marker<__F: #prelude::Field> {}

        #(#step_memberships)*
        #(#header_memberships)*
        impl<__F: #prelude::Field> #header_marker<__F> for () {}

        /// Generated application wrapper.
        #vis struct #enum_ident<#struct_gen> {
            inner: #prelude::Application<'params, C, __R, HEADER_SIZE>,
        }

        #[allow(private_bounds)]
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
            #vis fn seed<'source, __RNG: #prelude::CryptoRngCore, __S>(
                &self,
                rng: &mut __RNG,
                step: __S,
                witness: __S::Witness<'source>,
            ) -> #prelude::Result<(#prelude::Pcd<C, __R, __S::Output>, __S::Aux<'source>)>
            where
                __S: #prelude::PcdStep<C, Left = (), Right = ()> + #step_marker<C>,
                __S::Output: #header_marker<C::CircuitField>,
            {
                self.inner.seed(rng, step, witness)
            }

            /// Fuse two pieces of proof-carrying data using a step.
            #vis fn fuse<'source, __RNG: #prelude::CryptoRngCore, __S>(
                &self,
                rng: &mut __RNG,
                step: __S,
                witness: __S::Witness<'source>,
                left: #prelude::Pcd<C, __R, __S::Left>,
                right: #prelude::Pcd<C, __R, __S::Right>,
            ) -> #prelude::Result<(#prelude::Pcd<C, __R, __S::Output>, __S::Aux<'source>)>
            where
                __S: #prelude::PcdStep<C> + #step_marker<C>,
                __S::Left: #header_marker<C::CircuitField>,
                __S::Right: #header_marker<C::CircuitField>,
                __S::Output: #header_marker<C::CircuitField>,
            {
                self.inner.fuse(rng, step, witness, left, right)
            }

            /// Verify proof-carrying data.
            #vis fn verify<__RNG: #prelude::CryptoRngCore, __H>(
                &self,
                pcd: &#prelude::Pcd<C, __R, __H>,
                rng: __RNG,
            ) -> #prelude::Result<bool>
            where
                __H: #prelude::Header<C::CircuitField> + #header_marker<C::CircuitField>,
            {
                self.inner.verify(pcd, rng)
            }

            /// Rerandomize proof-carrying data.
            #vis fn rerandomize<__RNG: #prelude::CryptoRngCore, __H>(
                &self,
                pcd: #prelude::Pcd<C, __R, __H>,
                rng: &mut __RNG,
            ) -> #prelude::Result<#prelude::Pcd<C, __R, __H>>
            where
                __H: #prelude::Header<C::CircuitField> + #header_marker<C::CircuitField>,
            {
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

#[cfg(test)]
mod tests {
    use syn::parse_quote;

    use super::*;

    fn parse_attr(tokens: TokenStream) -> Result<ApplicationAttr> {
        syn::parse2(tokens)
    }

    fn parse_attr_err(tokens: TokenStream) -> String {
        match parse_attr(tokens) {
            Ok(_) => panic!("expected a parse error"),
            Err(err) => err.to_string(),
        }
    }

    #[test]
    fn attr_accepts_empty_and_full_defaults() {
        let attr = parse_attr(quote!()).unwrap();
        assert!(attr.cycle.is_none() && attr.rank.is_none() && attr.header_size.is_none());

        let attr = parse_attr(quote!(
            cycle = Pasta,
            rank = ProductionRank,
            header_size = 4
        ))
        .unwrap();
        assert!(attr.cycle.is_some() && attr.rank.is_some() && attr.header_size.is_some());
    }

    #[test]
    fn attr_accepts_trailing_subsets() {
        assert!(parse_attr(quote!(header_size = 4)).is_ok());
        assert!(parse_attr(quote!(rank = ProductionRank, header_size = 4)).is_ok());
    }

    #[test]
    fn attr_rejects_non_trailing_defaults() {
        let err = parse_attr_err(quote!(cycle = Pasta, header_size = 4));
        assert!(err.contains("requires a `rank` default"));

        let err = parse_attr_err(quote!(rank = ProductionRank));
        assert!(err.contains("requires a `header_size` default"));
    }

    #[test]
    fn attr_rejects_duplicate_and_unknown_keys() {
        let err = parse_attr_err(quote!(header_size = 4, header_size = 8));
        assert!(err.contains("duplicate `header_size` key"));

        let err = parse_attr_err(quote!(size = 4));
        assert!(err.contains("unknown attribute `size`"));
    }

    fn produces_err(variant: &Variant) -> String {
        match parse_produces_attr(variant) {
            Ok(_) => panic!("expected a parse error"),
            Err(err) => err.to_string(),
        }
    }

    #[test]
    fn produces_attr_is_required_and_unique() {
        let variant: Variant = parse_quote! {
            #[produces(LeafNode)]
            WitnessLeaf
        };
        let produces = parse_produces_attr(&variant).unwrap();
        let output = &produces.output;
        assert_eq!(quote!(#output).to_string(), "LeafNode");
        assert!(produces.canonical.is_none());

        let variant: Variant = parse_quote! {
            #[produces(LeafAlias, canonical = crate::LeafNode)]
            WitnessLeaf
        };
        let produces = parse_produces_attr(&variant).unwrap();
        let output = &produces.output;
        let canonical = produces.canonical.as_ref().unwrap();
        assert_eq!(quote!(#output).to_string(), "LeafAlias");
        assert_eq!(quote!(#canonical).to_string(), "crate :: LeafNode");

        let variant: Variant = parse_quote!(WitnessLeaf);
        let err = produces_err(&variant);
        assert!(err.contains("missing #[produces(...)]"));

        let variant: Variant = parse_quote! {
            #[produces(LeafNode)]
            #[produces(ExponentNode)]
            WitnessLeaf
        };
        let err = produces_err(&variant);
        assert!(err.contains("duplicate #[produces(...)]"));

        let variant: Variant = parse_quote! {
            #[produces(LeafNode, alias = OtherLeaf)]
            WitnessLeaf
        };
        let err = produces_err(&variant);
        assert!(err.contains("expected `canonical`"));
    }

    fn parsed_variant(
        name: &str,
        output: Type,
        header: Type,
        has_explicit_canonical: bool,
        index: usize,
    ) -> ParsedVariant {
        let name = Ident::new(name, proc_macro2::Span::call_site());
        let step_ty = quote!(#name<'params, C>);
        ParsedVariant {
            name,
            step_ty,
            output,
            header,
            has_explicit_canonical,
            index,
        }
    }

    #[test]
    fn canonical_header_spelling_deduplicates_aliases_and_is_asserted() {
        let variants = vec![
            parsed_variant(
                "First",
                parse_quote!(LeafAlias),
                parse_quote!(LeafNode),
                true,
                0,
            ),
            parsed_variant(
                "Second",
                parse_quote!(LeafNode),
                parse_quote!(LeafNode),
                false,
                1,
            ),
        ];

        let headers = collect_unique_headers(&variants);
        assert_eq!(headers.len(), 1);
        let header = &headers[0];
        assert_eq!(quote!(#header).to_string(), "LeafNode");

        let assertions = generate_header_alias_assertions(&variants)
            .to_string()
            .replace(' ', "");
        assert!(assertions.contains("fn__ragu_assert_same_header_type(value:LeafAlias)->LeafNode"));
    }

    #[test]
    fn generated_wrapper_is_application_sealed_and_checks_output_type() {
        let variants = vec![parsed_variant(
            "WitnessLeaf",
            parse_quote!(LeafNode),
            parse_quote!(LeafNode),
            false,
            0,
        )];
        let headers = collect_unique_headers(&variants);
        let app = RaguAppPath::default();
        let prelude = quote!(::ragu_pcd::app::__macro_internal);

        let steps = generate_step_impls(&variants, &app, &prelude)
            .to_string()
            .replace(' ', "");
        assert!(steps.contains("Step<C,Output=LeafNode>"));
        assert!(steps.contains("typeOutput=LeafNode;"));

        let wrapper = generate_wrapper(
            &parse_quote!(pub),
            &parse_quote!(ExampleApp),
            &parse_attr(quote!()).unwrap(),
            &variants,
            &headers,
            &app,
            &prelude,
        )
        .to_string()
        .replace(' ', "");
        assert!(wrapper.contains("trait__RaguApplicationStepForExampleApp"));
        assert!(wrapper.contains("trait__RaguApplicationHeaderForExampleApp"));
        assert!(
            wrapper.contains("PcdStep<C,Left=(),Right=()>+__RaguApplicationStepForExampleApp<C>")
        );
        assert!(
            wrapper.contains("__S::Left:__RaguApplicationHeaderForExampleApp<C::CircuitField>")
        );
        assert!(
            wrapper.contains("__S::Right:__RaguApplicationHeaderForExampleApp<C::CircuitField>")
        );
        assert!(
            wrapper.contains("__S::Output:__RaguApplicationHeaderForExampleApp<C::CircuitField>")
        );
        assert!(wrapper.contains(
            "Header<C::CircuitField>+__RaguApplicationHeaderForExampleApp<C::CircuitField>"
        ));
    }
}

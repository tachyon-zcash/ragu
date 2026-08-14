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
//! `#[produces(())]` is rejected: suffixes assigned here start past the range
//! reserved for internal headers, and `()` is the internal trivial header whose
//! suffix marks a proof as a recursion base case. Producing it from an
//! application step would let a real circuit mint that marker.
//!
//! `#[application(header_size = ..., cycle = ..., rank = ...)]` fixes the
//! application's header width and optionally sets defaults for the generated
//! wrapper's cycle and rank parameters, so the application type can be named
//! without turbofish.
//!
//! Because the enum is a declaration DSL rather than an emitted enum, variant
//! attributes other than `#[produces(...)]` and explicit discriminants are
//! rejected. Enum attributes are limited to metadata that can be forwarded
//! faithfully to the generated wrapper.

use std::collections::{BTreeMap, BTreeSet};

use heck::ToSnakeCase;
use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote};
use syn::{
    Attribute, Error, Expr, Fields, Ident, ItemEnum, Result, Token, Type, Variant, Visibility,
    ext::IdentExt,
    parse::{Parse, ParseStream},
    punctuated::Punctuated,
};

use crate::{
    helpers::{collect_idents, fresh_ident},
    path_resolution::RaguAppPath,
};

/// The parsed `#[application(...)]` attribute arguments: a required fixed
/// header width and optional defaults for the generated wrapper's cycle and
/// rank parameters.
///
/// Because defaulted generic parameters must be trailing, `cycle` requires a
/// `rank` default.
pub struct ApplicationAttr {
    cycle: Option<Type>,
    rank: Option<Type>,
    header_size: Expr,
}

impl Parse for ApplicationAttr {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let mut cycle = None;
        let mut rank = None;
        let mut header_size = None;
        let mut cycle_span = None;
        let attr_span = input.span();

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

            // Entries are comma-separated; a trailing comma is permitted.
            if !input.is_empty() {
                input.parse::<Token![,]>()?;
            }
        }

        // The generated generics are ordered `C, __R`, and Rust requires
        // defaulted parameters to be trailing.
        if let (Some(span), None) = (cycle_span, &rank) {
            return Err(Error::new(
                span,
                "`cycle` default requires a `rank` default (defaults must be trailing)",
            ));
        }
        Ok(ApplicationAttr {
            cycle,
            rank,
            header_size: header_size.ok_or_else(|| {
                Error::new(
                    attr_span,
                    "missing required `header_size` in #[application(...)]",
                )
            })?,
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

    let attrs = &input.attrs;
    let vis = &input.vis;
    let enum_ident = &input.ident;

    validate_application_attributes(attrs)?;

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
    let build_parameter_idents = build_parameter_idents(&input.variants)?;
    let mut declarations = Vec::new();
    for variant in &input.variants {
        validate_variant_declaration(variant)?;
        declarations.push(parse_produces_attr(variant)?);
    }

    // Generated generic-parameter names must not capture any identifier the
    // caller wrote, so they are chosen after all declarations are parsed.
    let generics = MacroGenerics::fresh(enum_ident, &attr, &declarations);
    let cycle = &generics.cycle;

    let mut variants = Vec::new();
    for ((index, (variant, produces)), build_parameter) in input
        .variants
        .iter()
        .zip(declarations)
        .enumerate()
        .zip(build_parameter_idents)
    {
        let output = produces.output;
        let (header, has_explicit_canonical) = match produces.canonical {
            Some(canonical) => (canonical, true),
            None => (output.clone(), false),
        };
        let name = variant.ident.clone();
        // Qualifying the caller's type through the invocation module prevents
        // names such as `C` from being captured by generated generic parameters.
        let step_ty = quote!(self::#name<'params, #cycle>);
        variants.push(ParsedVariant {
            build_parameter,
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

    let header_impls = generate_header_impls(&headers, &app, &prelude, &generics);
    let header_alias_assertions = generate_header_alias_assertions(&variants);
    let step_impls = generate_step_impls(&variants, &app, &prelude, &generics);
    let wrapper = generate_wrapper(
        attrs, vis, enum_ident, &attr, &variants, &headers, &app, &prelude, &generics,
    );

    Ok(quote! {
        #header_alias_assertions
        #header_impls
        #step_impls
        #wrapper
    })
}

/// Validates attributes that can be meaningfully forwarded from the enum DSL
/// declaration to the generated wrapper struct.
fn validate_application_attributes(attrs: &[Attribute]) -> Result<()> {
    for attr in attrs {
        let path = attr.path();
        let forwarded = path.is_ident("doc")
            || path.is_ident("allow")
            || path.is_ident("warn")
            || path.is_ident("deny")
            || path.is_ident("forbid")
            || path.is_ident("expect")
            || path.is_ident("must_use")
            || path.is_ident("deprecated");
        if forwarded {
            continue;
        }

        let message = if path.is_ident("cfg") || path.is_ident("cfg_attr") {
            "configuration attributes on an #[application] enum cannot gate the complete macro \
             expansion; put the application in a cfg-gated module instead"
        } else {
            "unsupported attribute on #[application] enum; only doc comments, lint attributes, \
             #[must_use], and #[deprecated] are forwarded to the generated wrapper"
        };
        return Err(Error::new_spanned(attr, message));
    }

    Ok(())
}

/// Rejects syntax that would disappear when the enum DSL declaration is
/// consumed rather than emitted as an enum.
fn validate_variant_declaration(variant: &Variant) -> Result<()> {
    for attr in &variant.attrs {
        if !attr.path().is_ident("produces") {
            return Err(Error::new_spanned(
                attr,
                "unsupported attribute on #[application] variant; only #[produces(...)] is \
                 accepted because the enum variant is consumed by the macro",
            ));
        }
    }

    if !matches!(variant.fields, Fields::Unit) {
        return Err(Error::new_spanned(
            variant,
            "application variants must be unit variants naming a step type \
             with `<'params, C: Cycle>` generics",
        ));
    }

    if let Some((_, discriminant)) = &variant.discriminant {
        return Err(Error::new_spanned(
            discriminant,
            "explicit discriminants are not supported on #[application] variants; step indices \
             are assigned from declaration order",
        ));
    }

    Ok(())
}

/// Computes collision-free Rust identifiers for the generated `build()`
/// parameters, reporting errors at the source variants rather than panicking
/// or leaving rustc to diagnose invisible generated code.
fn build_parameter_idents(variants: &Punctuated<Variant, Token![,]>) -> Result<Vec<Ident>> {
    let mut seen = BTreeMap::<String, Ident>::new();
    let mut generated = Vec::with_capacity(variants.len());

    for variant in variants {
        let parameter = variant.ident.unraw().to_string().to_snake_case();
        if parameter == "params" {
            return Err(Error::new(
                variant.ident.span(),
                "variant generates the reserved build parameter name `params`; rename the step",
            ));
        }

        let mut ident = syn::parse_str::<Ident>(&parameter).map_err(|_| {
            Error::new(
                variant.ident.span(),
                format!(
                    "variant generates `{parameter}`, which is not a valid Rust build parameter; \
                     rename the step"
                ),
            )
        })?;
        ident.set_span(variant.ident.span());

        if let Some(first) = seen.insert(parameter.clone(), variant.ident.clone()) {
            return Err(Error::new(
                variant.ident.span(),
                format!(
                    "variants `{first}` and `{}` both generate the build parameter \
                     `{parameter}`; rename one step",
                    variant.ident,
                ),
            ));
        }

        generated.push(ident);
    }

    Ok(generated)
}

/// A parsed enum variant: its generated `build()` parameter, instantiated step
/// type, output header, and declaration index.
struct ParsedVariant {
    /// Prevalidated snake_case identifier used as the `build()` parameter.
    build_parameter: Ident,
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
    let produces = produces.ok_or_else(|| {
        Error::new_spanned(variant, "missing #[produces(...)] attribute on variant")
    })?;

    // `()` is the framework's trivial header. Its suffix is what marks a proof
    // as a recursion base case, and in the base case the folded claim is left
    // unconstrained. An application step producing `()` would mint that marker
    // from a real circuit, so reject it and direct authors at an
    // application-owned header, which is assigned an ordinary suffix.
    if is_unit_type(&produces.output) {
        return Err(Error::new_spanned(&produces.output, UNIT_OUTPUT_REJECTION));
    }
    if let Some(canonical) = &produces.canonical
        && is_unit_type(canonical)
    {
        return Err(Error::new_spanned(canonical, UNIT_OUTPUT_REJECTION));
    }

    Ok(produces)
}

/// Diagnostic for `#[produces(())]`, which would let an application step emit
/// the reserved trivial-header suffix.
const UNIT_OUTPUT_REJECTION: &str = "`()` is the reserved trivial header and cannot be produced by \
     an application step: its suffix marks a proof as a recursion base case, where the folded \
     claim is left unconstrained. Declare an application-owned header instead, which carries no \
     data but is assigned its own suffix:\n\n    \
     struct Done;\n    \
     impl<F: Field> HeaderContent<F> for Done {\n        \
     type Data = ();\n        \
     type Output = ();\n        \
     fn encode(..) -> Result<Bound<'dr, D, Self::Output>> { Ok(()) }\n    \
     }";

/// Names of the generic parameters the macro introduces into generated items.
///
/// The preferred names are `C`, `__R`, `__F`, `__D`, and `__A`, but
/// user-written types are interpolated into scopes where these parameters are
/// live — cycle/rank defaults in the wrapper's generics, produced header
/// types in bounds and generated impls, and the wrapper's self type — so each
/// name is freshened until it collides with no identifier the caller wrote
/// anywhere in the declaration.
struct MacroGenerics {
    /// The `C: Cycle` parameter of generated impls and the wrapper.
    cycle: Ident,
    /// The `__R: Rank` parameter of the generated wrapper.
    rank: Ident,
    /// The `__F: Field` parameter of generated `Header` impls and markers.
    field: Ident,
    /// The `__D: Driver` parameter of generated `encode` methods.
    driver: Ident,
    /// The `__A: Allocator` parameter of generated `encode` methods.
    allocator: Ident,
}

impl MacroGenerics {
    fn fresh(enum_ident: &Ident, attr: &ApplicationAttr, declarations: &[ProducesAttr]) -> Self {
        let mut occupied = BTreeSet::new();
        occupied.insert(enum_ident.unraw().to_string());
        if let Some(cycle) = &attr.cycle {
            collect_idents(quote!(#cycle), &mut occupied);
        }
        if let Some(rank) = &attr.rank {
            collect_idents(quote!(#rank), &mut occupied);
        }
        // Const expressions can mention types (e.g. `size_of::<T>()`), so the
        // header size participates too.
        let header_size = &attr.header_size;
        collect_idents(quote!(#header_size), &mut occupied);
        for produces in declarations {
            let output = &produces.output;
            collect_idents(quote!(#output), &mut occupied);
            if let Some(canonical) = &produces.canonical {
                collect_idents(quote!(#canonical), &mut occupied);
            }
        }

        MacroGenerics {
            cycle: fresh_ident("C", &occupied, Span::call_site()),
            rank: fresh_ident("__R", &occupied, Span::call_site()),
            field: fresh_ident("__F", &occupied, Span::call_site()),
            driver: fresh_ident("__D", &occupied, Span::call_site()),
            allocator: fresh_ident("__A", &occupied, Span::call_site()),
        }
    }
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
/// A private trait with only the reflexive implementation makes rustc perform
/// semantic type resolution (including aliases), which a proc macro cannot do
/// from tokens. Unlike assignment or function-return coercion, this rejects
/// distinct types connected by a coercion.
fn generate_header_alias_assertions(variants: &[ParsedVariant]) -> TokenStream {
    let assertions = variants.iter().filter_map(|variant| {
        if !variant.has_explicit_canonical {
            return None;
        }

        let output = &variant.output;
        let header = &variant.header;
        Some(quote! {
            const _: () = {
                trait __RaguSameHeaderType<__T> {}
                impl<__T> __RaguSameHeaderType<__T> for __T {}

                fn __ragu_assert_same_header_type<__Output, __Header>()
                where
                    __Output: __RaguSameHeaderType<__Header>,
                {}

                let _ = __ragu_assert_same_header_type::<#output, #header>;
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
    generics: &MacroGenerics,
) -> TokenStream {
    let cycle = &generics.cycle;
    let driver = &generics.driver;
    let mut impls = TokenStream::new();

    for v in variants {
        let step_ty = &v.step_ty;
        let output = &v.output;
        let index = v.index;

        impls.extend(quote! {
            impl<'params, #cycle: #app::Cycle> #prelude::PcdStep<#cycle> for #step_ty
            where
                #step_ty: #app::Step<#cycle, Output = #output>,
                <#step_ty as #app::Step<#cycle>>::Left: #prelude::Header<#cycle::CircuitField>,
                <#step_ty as #app::Step<#cycle>>::Right: #prelude::Header<#cycle::CircuitField>,
                #output: #prelude::Header<#cycle::CircuitField>,
            {
                const INDEX: #prelude::Index = #prelude::Index::new(#index);

                type Witness<'source> = <#step_ty as #app::Step<#cycle>>::Witness;
                type Left = <#step_ty as #app::Step<#cycle>>::Left;
                type Right = <#step_ty as #app::Step<#cycle>>::Right;
                type Output = #output;
                type Aux<'source> = <#step_ty as #app::Step<#cycle>>::Aux;

                fn witness<'dr, 'source: 'dr, #driver: #prelude::Driver<'dr, F = #cycle::CircuitField>, const HEADER_SIZE: usize>(
                    &self,
                    dr: &mut #driver,
                    witness: #prelude::DriverValue<#driver, Self::Witness<'source>>,
                    left: #prelude::DriverValue<
                        #driver,
                        <Self::Left as #prelude::Header<#cycle::CircuitField>>::Data,
                    >,
                    right: #prelude::DriverValue<
                        #driver,
                        <Self::Right as #prelude::Header<#cycle::CircuitField>>::Data,
                    >,
                ) -> #prelude::Result<(
                    (
                        #prelude::Encoded<'dr, #driver, Self::Left, HEADER_SIZE>,
                        #prelude::Encoded<'dr, #driver, Self::Right, HEADER_SIZE>,
                        #prelude::Encoded<'dr, #driver, Self::Output, HEADER_SIZE>,
                    ),
                    #prelude::DriverValue<
                        #driver,
                        <Self::Output as #prelude::Header<#cycle::CircuitField>>::Data,
                    >,
                    #prelude::DriverValue<#driver, Self::Aux<'source>>,
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
                        call_synthesize::<#cycle, #driver, #step_ty, HEADER_SIZE>(
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
    generics: &MacroGenerics,
) -> TokenStream {
    let field = &generics.field;
    let driver = &generics.driver;
    let allocator = &generics.allocator;
    let mut impls = TokenStream::new();

    for (i, header_ty) in headers.iter().enumerate() {
        impls.extend(quote! {
            impl<#field: #prelude::Field> #prelude::Header<#field> for #header_ty
            where
                #header_ty: #app::HeaderContent<#field>,
            {
                const SUFFIX: #prelude::Suffix = #prelude::Suffix::new(#i);

                type Data = <#header_ty as #app::HeaderContent<#field>>::Data;
                type Output = <#header_ty as #app::HeaderContent<#field>>::Output;

                fn encode<'dr, #driver: #prelude::Driver<'dr, F = #field>, #allocator: #prelude::Allocator<'dr, #driver>>(
                    dr: &mut #driver,
                    allocator: &mut #allocator,
                    witness: #prelude::DriverValue<#driver, Self::Data>,
                ) -> #prelude::Result<#prelude::Bound<'dr, #driver, Self::Output>> {
                    <#header_ty as #app::HeaderContent<#field>>::encode(dr, allocator, witness)
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
/// > {
///     inner: Application<'params, C, __R, 4>,
/// }
///
/// impl<'params, C: Cycle, __R: Rank> ExampleApp<'params, C, __R>
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
    attrs: &[Attribute],
    vis: &Visibility,
    enum_ident: &Ident,
    attr: &ApplicationAttr,
    variants: &[ParsedVariant],
    headers: &[Type],
    app: &RaguAppPath,
    prelude: &TokenStream,
    generics: &MacroGenerics,
) -> TokenStream {
    let cycle = &generics.cycle;
    let rank = &generics.rank;
    let field = &generics.field;

    // Private marker traits make the generated wrapper a closed application
    // boundary. Downstream crates cannot implement these traits for a foreign
    // step/header that happens to reuse the same INDEX/SUFFIX values.
    let marker_stem = enum_ident.unraw();
    let step_marker = format_ident!("__RaguApplicationStepFor{}", marker_stem);
    let header_marker = format_ident!("__RaguApplicationHeaderFor{}", marker_stem);

    let step_memberships: Vec<_> = variants
        .iter()
        .map(|variant| {
            let step_ty = &variant.step_ty;
            quote! {
                impl<'params, #cycle: #app::Cycle> #step_marker<#cycle> for #step_ty {}
            }
        })
        .collect();

    let header_memberships: Vec<_> = headers
        .iter()
        .map(|header| {
            quote! {
                impl<#field: #prelude::Field> #header_marker<#field> for #header
                where
                    #header: #prelude::Header<#field>,
                {}
            }
        })
        .collect();

    // `build()` parameters: one per variant, snake_case name with the step type.
    // e.g. `WitnessLeaf` → `witness_leaf: WitnessLeaf<'params, C>`
    let build_params: Vec<_> = variants
        .iter()
        .map(|v| {
            let name = &v.build_parameter;
            let ty = &v.step_ty;
            quote!(#name: #ty)
        })
        .collect();

    // Chained `.register(step)?` calls inside `build()`, one per variant.
    let register_calls: Vec<_> = variants
        .iter()
        .map(|v| {
            let name = &v.build_parameter;
            quote!(.register(#name)?)
        })
        .collect();

    // Struct/impl generics: the macro-supplied `'params, C: Cycle` plus
    // `__R: Rank`. The struct declaration carries any cycle/rank defaults from
    // `#[application(...)]`; impls repeat the generics without them (defaults
    // are not permitted in impl generics). `header_size` is intentionally
    // fixed by the application definition rather than exposed as a generic.
    let cycle_default = attr
        .cycle
        .as_ref()
        .map(|t| quote!(= #t))
        .unwrap_or_default();
    let rank_default = attr.rank.as_ref().map(|t| quote!(= #t)).unwrap_or_default();
    let header_size = &attr.header_size;
    let struct_gen = quote!(
        'params,
        #cycle: #app::Cycle #cycle_default,
        #rank: #prelude::Rank #rank_default
    );
    let impl_gen = quote!('params, #cycle: #app::Cycle, #rank: #prelude::Rank);
    let struct_args = quote!('params, #cycle, #rank);

    // Where clause: each unique header must impl `Header<C::CircuitField>`.
    let header_bounds: Vec<_> = headers
        .iter()
        .map(|h| quote!(#h: #prelude::Header<#cycle::CircuitField>))
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
            quote!(#step_ty: #app::Step<#cycle, Output = #output>)
        })
        .collect();

    quote! {
        // These deliberately remain private even when the application wrapper
        // is public: they seal its generic methods to the declared membership.
        #[doc(hidden)]
        trait #step_marker<#cycle: #app::Cycle> {}

        #[doc(hidden)]
        trait #header_marker<#field: #prelude::Field> {}

        #(#step_memberships)*
        #(#header_memberships)*
        // `()` is deliberately a member of every application: trivial PCDs
        // are the universal placeholder input, so the seal cannot exclude
        // them. A trivial PCD minted elsewhere is instead rejected at runtime
        // by verification against this application's registry.
        impl<#field: #prelude::Field> #header_marker<#field> for () {}

        #(#attrs)*
        /// Generated application wrapper.
        #vis struct #enum_ident<#struct_gen> {
            inner: #prelude::Application<'params, #cycle, #rank, { #header_size }>,
        }

        #[allow(private_bounds)]
        impl<#impl_gen> #enum_ident<#struct_args>
        where
            #(#header_bounds,)*
            #(#step_bounds,)*
        {
            /// Build the application by registering all steps.
            ///
            /// Registration fixes each step's circuit from the instance passed
            /// here, including whatever configuration that instance carries.
            /// The steps later handed to `seed` and `fuse` are separate
            /// instances, and each must be configured identically to the one
            /// registered here. A step that differs traces against a circuit it
            /// no longer matches, which is not reported at that point: the call
            /// succeeds and only a later `verify` of the resulting PCD fails,
            /// by returning `Ok(false)`.
            ///
            /// Returns an initialization error if the configured header size
            /// is zero, and propagates registration errors such as a header
            /// encoding that does not fit in the configured width.
            #vis fn build(
                params: &'params #cycle::Params,
                #(#build_params),*
            ) -> #prelude::Result<Self> {
                if { #header_size } == 0 {
                    return Err(#prelude::Error::Initialization(
                        "HEADER_SIZE must be at least 1".into(),
                    ));
                }

                let inner = #prelude::ApplicationBuilder::<#cycle, #rank, { #header_size }>::new()
                    #(#register_calls)*
                    .finalize(params)?;
                Ok(Self { inner })
            }

            /// Seed a new computation by running a step with trivial inputs.
            ///
            /// `step` must be configured identically to the instance of the
            /// same step registered by `build`; see that method for what a
            /// mismatch costs.
            #vis fn seed<'source, __RNG: #prelude::CryptoRngCore, __S>(
                &self,
                rng: &mut __RNG,
                step: __S,
                witness: __S::Witness<'source>,
            ) -> #prelude::Result<(#prelude::Pcd<#cycle, #rank, __S::Output>, __S::Aux<'source>)>
            where
                __S: #prelude::PcdStep<#cycle, Left = (), Right = ()> + #step_marker<#cycle>,
                __S::Output: #header_marker<#cycle::CircuitField>,
            {
                self.inner.seed(rng, step, witness)
            }

            /// Fuse two pieces of proof-carrying data using a step.
            ///
            /// `step` must be configured identically to the instance of the
            /// same step registered by `build`; see that method for what a
            /// mismatch costs.
            #vis fn fuse<'source, __RNG: #prelude::CryptoRngCore, __S>(
                &self,
                rng: &mut __RNG,
                step: __S,
                witness: __S::Witness<'source>,
                left: #prelude::Pcd<#cycle, #rank, __S::Left>,
                right: #prelude::Pcd<#cycle, #rank, __S::Right>,
            ) -> #prelude::Result<(#prelude::Pcd<#cycle, #rank, __S::Output>, __S::Aux<'source>)>
            where
                __S: #prelude::PcdStep<#cycle> + #step_marker<#cycle>,
                __S::Left: #header_marker<#cycle::CircuitField>,
                __S::Right: #header_marker<#cycle::CircuitField>,
                __S::Output: #header_marker<#cycle::CircuitField>,
            {
                self.inner.fuse(rng, step, witness, left, right)
            }

            /// Verify proof-carrying data.
            #vis fn verify<__RNG: #prelude::CryptoRngCore, __H>(
                &self,
                pcd: &#prelude::Pcd<#cycle, #rank, __H>,
                rng: __RNG,
            ) -> #prelude::Result<bool>
            where
                __H: #prelude::Header<#cycle::CircuitField> + #header_marker<#cycle::CircuitField>,
            {
                self.inner.verify(pcd, rng)
            }

            /// Rerandomize proof-carrying data.
            #vis fn rerandomize<__RNG: #prelude::CryptoRngCore, __H>(
                &self,
                pcd: #prelude::Pcd<#cycle, #rank, __H>,
                rng: &mut __RNG,
            ) -> #prelude::Result<#prelude::Pcd<#cycle, #rank, __H>>
            where
                __H: #prelude::Header<#cycle::CircuitField> + #header_marker<#cycle::CircuitField>,
            {
                self.inner.rerandomize(pcd, rng)
            }

            /// Returns a seeded trivial PCD with no header data, suitable
            /// as a placeholder input for steps that only use one of their
            /// two inputs.
            #vis fn trivial_pcd<__RNG: #prelude::CryptoRngCore>(&self, rng: &mut __RNG) -> #prelude::Pcd<#cycle, #rank, ()> {
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
    fn attr_accepts_required_size_and_full_defaults() {
        let attr = parse_attr(quote!(header_size = 4)).unwrap();
        assert!(attr.cycle.is_none() && attr.rank.is_none());
        let header_size = &attr.header_size;
        assert_eq!(quote!(#header_size).to_string(), "4");

        let attr = parse_attr(quote!(
            cycle = Pasta,
            rank = ProductionRank,
            header_size = 4
        ))
        .unwrap();
        assert!(attr.cycle.is_some() && attr.rank.is_some());
    }

    #[test]
    fn attr_accepts_optional_rank_default() {
        assert!(parse_attr(quote!(rank = ProductionRank, header_size = 4)).is_ok());
    }

    #[test]
    fn attr_requires_header_size_and_rejects_non_trailing_defaults() {
        let err = parse_attr_err(quote!());
        assert!(err.contains("missing required `header_size`"));

        let err = parse_attr_err(quote!(rank = ProductionRank));
        assert!(err.contains("missing required `header_size`"));

        let err = parse_attr_err(quote!(cycle = Pasta, header_size = 4));
        assert!(err.contains("requires a `rank` default"));
    }

    #[test]
    fn attr_rejects_duplicate_and_unknown_keys() {
        let err = parse_attr_err(quote!(header_size = 4, header_size = 8));
        assert!(err.contains("duplicate `header_size` key"));

        let err = parse_attr_err(quote!(size = 4));
        assert!(err.contains("unknown attribute `size`"));
    }

    #[test]
    fn attr_requires_commas_between_entries() {
        assert!(parse_attr(quote!(rank = ProductionRank, header_size = 4,)).is_ok());

        let err = parse_attr_err(quote!(header_size = 4 cycle = Pasta));
        assert!(err.contains("expected `,`"));
    }

    #[test]
    fn application_attributes_are_forwarded_or_rejected_explicitly() {
        let item: ItemEnum = parse_quote! {
            #[doc = "An application"]
            #[must_use]
            #[allow(dead_code)]
            #[deprecated]
            enum App {
                #[produces(Header)]
                Step,
            }
        };
        assert!(validate_application_attributes(&item.attrs).is_ok());

        let item: ItemEnum = parse_quote! {
            #[cfg(feature = "optional-app")]
            enum App {}
        };
        let err = validate_application_attributes(&item.attrs)
            .unwrap_err()
            .to_string();
        assert!(err.contains("cfg-gated module"));

        let item: ItemEnum = parse_quote! {
            #[derive(Clone)]
            enum App {}
        };
        let err = validate_application_attributes(&item.attrs)
            .unwrap_err()
            .to_string();
        assert!(err.contains("unsupported attribute"));
    }

    #[test]
    fn variant_attributes_and_discriminants_are_rejected_explicitly() {
        let variant: Variant = parse_quote! {
            #[cfg(feature = "optional-step")]
            #[produces(Header)]
            Step
        };
        let err = validate_variant_declaration(&variant)
            .unwrap_err()
            .to_string();
        assert!(err.contains("unsupported attribute"));

        let variant: Variant = parse_quote! {
            #[produces(Header)]
            Step = 5
        };
        let err = validate_variant_declaration(&variant)
            .unwrap_err()
            .to_string();
        assert!(err.contains("explicit discriminants"));
    }

    #[test]
    fn build_parameter_names_are_prevalidated() {
        let item: ItemEnum = parse_quote! {
            enum App {
                FooBar,
                Foo_Bar,
            }
        };
        let err = build_parameter_idents(&item.variants)
            .unwrap_err()
            .to_string();
        assert!(err.contains("both generate the build parameter `foo_bar`"));

        let item: ItemEnum = parse_quote! { enum App { Params } };
        let err = build_parameter_idents(&item.variants)
            .unwrap_err()
            .to_string();
        assert!(err.contains("reserved build parameter name `params`"));

        let item: ItemEnum = parse_quote! { enum App { r#params } };
        let err = build_parameter_idents(&item.variants)
            .unwrap_err()
            .to_string();
        assert!(err.contains("reserved build parameter name `params`"));

        let item: ItemEnum = parse_quote! { enum App { Type } };
        let err = build_parameter_idents(&item.variants)
            .unwrap_err()
            .to_string();
        assert!(err.contains("`type`, which is not a valid Rust build parameter"));

        let item: ItemEnum = parse_quote! { enum App { Hash2 } };
        let names = build_parameter_idents(&item.variants).unwrap();
        assert_eq!(names[0], "hash2");
    }

    fn produces_err(variant: &Variant) -> String {
        match parse_produces_attr(variant) {
            Ok(_) => panic!("expected a parse error"),
            Err(err) => err.to_string(),
        }
    }

    #[test]
    fn produces_attr_rejects_the_reserved_trivial_header() {
        // `()` carries the internal trivial suffix, which marks a proof as a
        // recursion base case; an application step must not be able to emit it.
        let variant: Variant = parse_quote! {
            #[produces(())]
            Sink
        };
        assert!(produces_err(&variant).contains("reserved trivial header"));

        // The canonical spelling feeds suffix deduplication, so it is rejected
        // on the same grounds.
        let variant: Variant = parse_quote! {
            #[produces(Done, canonical = ())]
            Sink
        };
        assert!(produces_err(&variant).contains("reserved trivial header"));

        // A header that merely encodes no data is fine: it gets its own suffix.
        let variant: Variant = parse_quote! {
            #[produces(Done)]
            Sink
        };
        assert!(parse_produces_attr(&variant).is_ok());
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
        let name = Ident::new(name, Span::call_site());
        let build_parameter = syn::parse_str(&name.to_string().to_snake_case()).unwrap();
        let step_ty = quote!(self::#name<'params, C>);
        ParsedVariant {
            build_parameter,
            step_ty,
            output,
            header,
            has_explicit_canonical,
            index,
        }
    }

    /// The preferred parameter names, as chosen when nothing collides.
    fn test_generics() -> MacroGenerics {
        MacroGenerics {
            cycle: Ident::new("C", Span::call_site()),
            rank: Ident::new("__R", Span::call_site()),
            field: Ident::new("__F", Span::call_site()),
            driver: Ident::new("__D", Span::call_site()),
            allocator: Ident::new("__A", Span::call_site()),
        }
    }

    #[test]
    fn generated_parameters_avoid_caller_identifiers() {
        let attr = parse_attr(quote!(cycle = C, rank = __R, header_size = 4)).unwrap();
        let declarations = [ProducesAttr {
            output: parse_quote!(Wrapper<__F>),
            canonical: None,
        }];
        let enum_ident: Ident = parse_quote!(App);
        let generics = MacroGenerics::fresh(&enum_ident, &attr, &declarations);
        assert_eq!(generics.cycle, "C_");
        assert_eq!(generics.rank, "__R_");
        assert_eq!(generics.field, "__F_");
        assert_eq!(generics.driver, "__D");
        assert_eq!(generics.allocator, "__A");

        // The enum's own name is occupied too: the generated wrapper's self
        // type must not resolve to a generic parameter.
        let attr = parse_attr(quote!(header_size = 4)).unwrap();
        let enum_ident: Ident = parse_quote!(C);
        let generics = MacroGenerics::fresh(&enum_ident, &attr, &[]);
        assert_eq!(generics.cycle, "C_");
        assert_eq!(generics.rank, "__R");
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
        assert!(assertions.contains("trait__RaguSameHeaderType<__T>"));
        assert!(assertions.contains("impl<__T>__RaguSameHeaderType<__T>for__T"));
        assert!(assertions.contains("let_=__ragu_assert_same_header_type::<LeafAlias,LeafNode>;"));
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
        let attrs = vec![parse_quote!(#[must_use])];

        let steps = generate_step_impls(&variants, &app, &prelude, &test_generics())
            .to_string()
            .replace(' ', "");
        assert!(steps.contains("Step<C,Output=LeafNode>"));
        assert!(steps.contains("typeOutput=LeafNode;"));

        let wrapper = generate_wrapper(
            &attrs,
            &parse_quote!(pub),
            &parse_quote!(ExampleApp),
            &parse_attr(quote!(header_size = 4)).unwrap(),
            &variants,
            &headers,
            &app,
            &prelude,
            &test_generics(),
        )
        .to_string()
        .replace(' ', "");
        assert!(wrapper.contains("#[must_use]"));
        assert!(!wrapper.contains("constHEADER_SIZE"));
        assert!(wrapper.contains("Application<'params,C,__R,{4}>"));
        assert!(wrapper.contains("ApplicationBuilder::<C,__R,{4}>::new()"));
        assert!(wrapper.contains("if{4}==0"));
        assert!(wrapper.contains("Error::Initialization"));
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

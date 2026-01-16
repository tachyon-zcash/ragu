//! Implementation of the `#[define_application]` attribute macro.
//!
//! This macro transforms a module containing `#[step]` and `#[header]` annotated
//! structs into a complete application definition with generated trait implementations.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{
    Attribute, Error, Generics, Ident, Item, ItemMod, ItemStruct, Meta, Result, Type, Visibility,
    parse::{Parse, ParseStream, Parser},
    punctuated::Punctuated,
    spanned::Spanned,
};

use crate::path_resolution::{RaguArithmeticPath, RaguCorePath, RaguPcdPath};

// ============================================================================
// Attribute Parsing
// ============================================================================

/// Parsed `#[header(data = T, output = T)]` attribute.
#[derive(Clone)]
pub struct HeaderAttr {
    pub data: Type,
    pub output: Type,
}

/// Parsed `#[step(...)]` attribute.
#[derive(Clone)]
pub struct StepAttr {
    pub witness: Type,
    pub aux: Type,
    pub left: Option<Type>,
    pub right: Option<Type>,
    pub output: Option<Type>,
}

/// Key-value pair in attribute arguments.
struct AttrKeyValue {
    key: Ident,
    value: Type,
}

impl Parse for AttrKeyValue {
    fn parse(input: ParseStream) -> Result<Self> {
        let key: Ident = input.parse()?;
        input.parse::<syn::Token![=]>()?;
        let value: Type = input.parse()?;
        Ok(AttrKeyValue { key, value })
    }
}

/// Parse comma-separated key-value pairs from attribute arguments.
fn parse_attr_args(attr: &Attribute) -> Result<Vec<AttrKeyValue>> {
    let Meta::List(list) = &attr.meta else {
        return Err(Error::new(attr.span(), "expected attribute arguments"));
    };
    let parser = Punctuated::<AttrKeyValue, syn::Token![,]>::parse_terminated;
    let args = parser.parse2(list.tokens.clone())?;
    Ok(args.into_iter().collect())
}

impl HeaderAttr {
    /// Parse a `#[header(...)]` attribute.
    pub fn parse(attr: &Attribute) -> Result<Self> {
        let args = parse_attr_args(attr)?;
        let mut data = None;
        let mut output = None;

        for kv in args {
            match kv.key.to_string().as_str() {
                "data" => data = Some(kv.value),
                "output" => output = Some(kv.value),
                other => {
                    return Err(Error::new(kv.key.span(), format!("unknown key: {other}")));
                }
            }
        }

        Ok(HeaderAttr {
            data: data.ok_or_else(|| Error::new(attr.span(), "missing `data` key"))?,
            output: output.ok_or_else(|| Error::new(attr.span(), "missing `output` key"))?,
        })
    }
}

impl StepAttr {
    /// Parse a `#[step(...)]` attribute.
    pub fn parse(attr: &Attribute) -> Result<Self> {
        let args = parse_attr_args(attr)?;
        let mut witness = None;
        let mut aux = None;
        let mut left = None;
        let mut right = None;
        let mut output = None;

        for kv in args {
            match kv.key.to_string().as_str() {
                "witness" => witness = Some(kv.value),
                "aux" => aux = Some(kv.value),
                "left" => left = Some(kv.value),
                "right" => right = Some(kv.value),
                "output" => output = Some(kv.value),
                other => {
                    return Err(Error::new(kv.key.span(), format!("unknown key: {other}")));
                }
            }
        }

        Ok(StepAttr {
            witness: witness.ok_or_else(|| Error::new(attr.span(), "missing `witness` key"))?,
            aux: aux.ok_or_else(|| Error::new(attr.span(), "missing `aux` key"))?,
            left,
            right,
            output,
        })
    }
}

// ============================================================================
// Extracted Items
// ============================================================================

/// A header struct extracted from the module.
struct ExtractedHeader {
    item: ItemStruct,
    attr: HeaderAttr,
    suffix_index: usize,
}

/// A step struct extracted from the module.
struct ExtractedStep {
    item: ItemStruct,
    attr: StepAttr,
    step_index: usize,
}

/// Tracks declaration order for resolving implicit defaults.
#[derive(Clone)]
enum DeclKind {
    Header(usize), // index into headers vec
    Step(usize),   // index into steps vec
}

/// Check if an attribute matches a given name.
fn is_attr(attr: &Attribute, name: &str) -> bool {
    attr.path().is_ident(name)
}

/// Extract the attribute with the given name from a list.
fn take_attr(attrs: &mut Vec<Attribute>, name: &str) -> Option<Attribute> {
    if let Some(pos) = attrs.iter().position(|a| is_attr(a, name)) {
        Some(attrs.remove(pos))
    } else {
        None
    }
}

// ============================================================================
// Module Processing
// ============================================================================

/// Process a module and extract headers and steps.
struct ModuleProcessor {
    headers: Vec<ExtractedHeader>,
    steps: Vec<ExtractedStep>,
    /// Tracks the interleaved declaration order of steps and headers.
    declaration_order: Vec<DeclKind>,
    other_items: Vec<Item>,
    mod_attrs: Vec<Attribute>,
    mod_vis: Visibility,
    mod_ident: Ident,
}

impl ModuleProcessor {
    fn new(module: ItemMod) -> Result<Self> {
        let Some((_, items)) = module.content else {
            return Err(Error::new(
                module.span(),
                "#[define_application] requires a module with inline content",
            ));
        };

        let mut processor = ModuleProcessor {
            headers: Vec::new(),
            steps: Vec::new(),
            declaration_order: Vec::new(),
            other_items: Vec::new(),
            mod_attrs: module.attrs,
            mod_vis: module.vis,
            mod_ident: module.ident,
        };

        let mut header_count = 0;
        let mut step_count = 0;

        for item in items {
            match item {
                Item::Struct(mut s) => {
                    if let Some(attr) = take_attr(&mut s.attrs, "header") {
                        let header_attr = HeaderAttr::parse(&attr)?;
                        processor.headers.push(ExtractedHeader {
                            item: s,
                            attr: header_attr,
                            suffix_index: header_count,
                        });
                        processor.declaration_order.push(DeclKind::Header(header_count));
                        header_count += 1;
                    } else if let Some(attr) = take_attr(&mut s.attrs, "step") {
                        let step_attr = StepAttr::parse(&attr)?;
                        processor.steps.push(ExtractedStep {
                            item: s,
                            attr: step_attr,
                            step_index: step_count,
                        });
                        processor.declaration_order.push(DeclKind::Step(step_count));
                        step_count += 1;
                    } else {
                        processor.other_items.push(Item::Struct(s));
                    }
                }
                other => processor.other_items.push(other),
            }
        }

        Ok(processor)
    }

    /// Find the header that follows a step in declaration order.
    /// Returns None if no header follows the step.
    fn next_header_after_step(&self, step_idx: usize) -> Option<&Ident> {
        // Find position of this step in declaration order
        let step_pos = self.declaration_order.iter().position(|d| {
            matches!(d, DeclKind::Step(idx) if *idx == step_idx)
        })?;

        // Look for the next header after this position
        for decl in &self.declaration_order[step_pos + 1..] {
            if let DeclKind::Header(header_idx) = decl {
                return Some(&self.headers[*header_idx].item.ident);
            }
        }
        None
    }

    /// Find the output type of the previous step in declaration order.
    /// Returns None if this is the first step or no step precedes it.
    fn previous_step_output(&self, step_idx: usize) -> Option<&Type> {
        // Find position of this step in declaration order
        let step_pos = self.declaration_order.iter().position(|d| {
            matches!(d, DeclKind::Step(idx) if *idx == step_idx)
        })?;

        // Look backwards for the previous step
        for decl in self.declaration_order[..step_pos].iter().rev() {
            if let DeclKind::Step(prev_step_idx) = decl {
                // Return that step's output type (which must be resolved by now)
                return self.steps[*prev_step_idx].attr.output.as_ref();
            }
        }
        None
    }

    /// Resolve default `output`, `left`, and `right` for steps based on declaration order.
    ///
    /// Rules:
    /// - `output` defaults to the next header declared after the step
    /// - `left` and `right` default to the previous step's output, or `()` for the first step
    fn resolve_step_defaults(&mut self) -> Result<()> {
        // We need to process steps in declaration order so that previous step outputs
        // are resolved before we try to use them.
        let step_indices: Vec<usize> = self.declaration_order
            .iter()
            .filter_map(|d| match d {
                DeclKind::Step(idx) => Some(*idx),
                _ => None,
            })
            .collect();

        for step_idx in step_indices {
            // Resolve output: default to next header
            if self.steps[step_idx].attr.output.is_none() {
                if let Some(next_header) = self.next_header_after_step(step_idx) {
                    let header_ident = next_header.clone();
                    self.steps[step_idx].attr.output = Some(syn::parse_quote!(#header_ident));
                } else {
                    return Err(Error::new(
                        self.steps[step_idx].item.ident.span(),
                        "step has no explicit `output` and no header follows it in declaration order",
                    ));
                }
            }

            // Resolve left: default to previous step's output, or ()
            if self.steps[step_idx].attr.left.is_none() {
                if let Some(prev_output) = self.previous_step_output(step_idx) {
                    self.steps[step_idx].attr.left = Some(prev_output.clone());
                } else {
                    self.steps[step_idx].attr.left = Some(syn::parse_quote!(()));
                }
            }

            // Resolve right: default to previous step's output, or ()
            if self.steps[step_idx].attr.right.is_none() {
                if let Some(prev_output) = self.previous_step_output(step_idx) {
                    self.steps[step_idx].attr.right = Some(prev_output.clone());
                } else {
                    self.steps[step_idx].attr.right = Some(syn::parse_quote!(()));
                }
            }
        }

        Ok(())
    }
}

// ============================================================================
// Code Generation
// ============================================================================

/// Generate the Header trait implementation for a header struct.
fn generate_header_impl(
    header: &ExtractedHeader,
    ragu_core: &RaguCorePath,
    ragu_pcd: &RaguPcdPath,
) -> TokenStream {
    let name = &header.item.ident;
    let suffix_index = header.suffix_index;
    let data_type = &header.attr.data;
    let output_type = &header.attr.output;

    // The Header trait is generic over F: Field
    // Note: We use ::ff::Field directly since ff is not re-exported from ragu_core
    quote! {
        impl #name {
            /// The suffix index for this header within this application.
            pub const HEADER_SUFFIX: usize = #suffix_index;
        }

        impl<F: ::ff::Field> #ragu_pcd::header::Header<F> for #name {
            const SUFFIX: #ragu_pcd::header::Suffix = #ragu_pcd::header::Suffix::new(Self::HEADER_SUFFIX);

            type Data<'source> = #data_type;
            type Output = #ragu_core::gadgets::Kind![F; #output_type];

            fn encode<'dr, 'source: 'dr, D: #ragu_core::drivers::Driver<'dr, F = F>>(
                dr: &mut D,
                witness: #ragu_core::drivers::DriverValue<D, Self::Data<'source>>,
            ) -> #ragu_core::Result<<Self::Output as #ragu_core::gadgets::GadgetKind<F>>::Rebind<'dr, D>> {
                #name::encode(dr, witness)
            }
        }
    }
}

/// Extract the Cycle type parameter from step generics.
/// Returns (cycle_ident, other_generics).
fn extract_cycle_param(generics: &Generics) -> Result<(Ident, Vec<&syn::GenericParam>)> {
    let mut cycle_ident = None;
    let mut other_params = Vec::new();

    for param in &generics.params {
        if let syn::GenericParam::Type(ty) = param {
            // Check if this type has a Cycle bound
            let has_cycle_bound = ty.bounds.iter().any(|bound| {
                if let syn::TypeParamBound::Trait(t) = bound {
                    t.path.segments.last().map(|s| s.ident == "Cycle").unwrap_or(false)
                } else {
                    false
                }
            });
            if has_cycle_bound {
                cycle_ident = Some(ty.ident.clone());
            } else {
                other_params.push(param);
            }
        } else {
            other_params.push(param);
        }
    }

    cycle_ident
        .map(|c| (c, other_params))
        .ok_or_else(|| Error::new(generics.span(), "step struct must have a `C: Cycle` type parameter"))
}

/// Generate the Step trait implementation for a step struct.
fn generate_step_impl(
    step: &ExtractedStep,
    ragu_core: &RaguCorePath,
    ragu_pcd: &RaguPcdPath,
) -> Result<TokenStream> {
    let name = &step.item.ident;
    let step_index = step.step_index;
    let witness_type = &step.attr.witness;
    let aux_type = &step.attr.aux;
    let left_type = step.attr.left.as_ref().unwrap();
    let right_type = step.attr.right.as_ref().unwrap();
    let output_type = step.attr.output.as_ref().unwrap();

    let generics = &step.item.generics;
    let (cycle_ident, _other_params) = extract_cycle_param(generics)?;

    // Build the impl generics (lifetime params + Cycle param)
    let impl_generics = generics;
    let (impl_generics_tokens, ty_generics, where_clause) = impl_generics.split_for_impl();

    // For the impl, we need to use '_ for the lifetime in the type position
    // e.g., `impl<'params, C: Cycle> Step<C> for WitnessLeaf<'_, C>`
    let ty_generics_with_wildcard = {
        let params: Vec<_> = generics.params.iter().map(|p| {
            match p {
                syn::GenericParam::Lifetime(_) => quote!('_),
                syn::GenericParam::Type(t) => {
                    let ident = &t.ident;
                    quote!(#ident)
                }
                syn::GenericParam::Const(c) => {
                    let ident = &c.ident;
                    quote!(#ident)
                }
            }
        }).collect();
        if params.is_empty() {
            quote!()
        } else {
            quote!(<#(#params),*>)
        }
    };

    Ok(quote! {
        impl #impl_generics_tokens #name #ty_generics #where_clause {
            /// The step index for this step within this application.
            pub const STEP_INDEX: usize = #step_index;
        }

        impl #impl_generics_tokens #ragu_pcd::step::Step<#cycle_ident> for #name #ty_generics_with_wildcard #where_clause {
            const INDEX: #ragu_pcd::step::Index = #ragu_pcd::step::Index::new(Self::STEP_INDEX);

            type Witness<'source> = #witness_type;
            type Aux<'source> = #aux_type;
            type Left = #left_type;
            type Right = #right_type;
            type Output = #output_type;

            fn witness<'dr, 'source: 'dr, D: #ragu_core::drivers::Driver<'dr, F = #cycle_ident::CircuitField>, const HEADER_SIZE: usize>(
                &self,
                dr: &mut D,
                witness: #ragu_core::drivers::DriverValue<D, Self::Witness<'source>>,
                left: #ragu_pcd::step::Encoder<'dr, 'source, D, Self::Left, HEADER_SIZE>,
                right: #ragu_pcd::step::Encoder<'dr, 'source, D, Self::Right, HEADER_SIZE>,
            ) -> #ragu_core::Result<(
                (
                    #ragu_pcd::step::Encoded<'dr, D, Self::Left, HEADER_SIZE>,
                    #ragu_pcd::step::Encoded<'dr, D, Self::Right, HEADER_SIZE>,
                    #ragu_pcd::step::Encoded<'dr, D, Self::Output, HEADER_SIZE>,
                ),
                #ragu_core::drivers::DriverValue<D, Self::Aux<'source>>,
            )>
            where
                Self: 'dr,
            {
                // Delegate to user-defined witness method with tuple input
                self.witness((dr, witness, left, right))
            }
        }
    })
}

/// Generate the build function for the application.
fn generate_build_fn(
    steps: &[ExtractedStep],
    ragu_arithmetic: &RaguArithmeticPath,
    ragu_core: &RaguCorePath,
    ragu_pcd: &RaguPcdPath,
) -> TokenStream {
    let step_registrations: Vec<_> = steps.iter().map(|s| {
        let name = &s.item.ident;
        quote! {
            .register(#name::new(params))?
        }
    }).collect();

    // Note: We use resolved paths for Cycle to handle different crate aliasing.
    // Rank is still hardcoded as ::ragu_circuits as that's the standard path.
    quote! {
        /// Build the application by registering all steps.
        ///
        /// Each step struct must implement `fn new(params: &'params C::Params) -> Self`.
        pub fn build<'params, C: #ragu_arithmetic::Cycle, R: ::ragu_circuits::polynomials::Rank, const HEADER_SIZE: usize>(
            params: &'params C::Params,
        ) -> #ragu_core::Result<#ragu_pcd::Application<'params, C, R, HEADER_SIZE>> {
            #ragu_pcd::ApplicationBuilder::new()
                #(#step_registrations)*
                .finalize(params)
        }
    }
}

// ============================================================================
// Main Entry Point
// ============================================================================

/// Evaluate the `#[define_application]` macro.
pub fn evaluate(
    module: ItemMod,
    ragu_arithmetic: RaguArithmeticPath,
    ragu_core: RaguCorePath,
    ragu_pcd: RaguPcdPath,
) -> Result<TokenStream> {
    let mut processor = ModuleProcessor::new(module)?;
    processor.resolve_step_defaults()?;

    // Generate header struct definitions (preserved) and impls
    let header_items: Vec<_> = processor.headers.iter().map(|h| {
        Item::Struct(h.item.clone())
    }).collect();

    let header_impls: Vec<_> = processor.headers.iter().map(|h| {
        generate_header_impl(h, &ragu_core, &ragu_pcd)
    }).collect();

    // Generate step struct definitions (preserved) and impls
    let step_items: Vec<_> = processor.steps.iter().map(|s| {
        Item::Struct(s.item.clone())
    }).collect();

    let step_impls: Result<Vec<_>> = processor.steps.iter().map(|s| {
        generate_step_impl(s, &ragu_core, &ragu_pcd)
    }).collect();
    let step_impls = step_impls?;

    // Generate build function
    let build_fn = generate_build_fn(&processor.steps, &ragu_arithmetic, &ragu_core, &ragu_pcd);

    // Other items from the module
    let other_items = &processor.other_items;

    // Module attributes and visibility
    let mod_attrs = &processor.mod_attrs;
    let mod_vis = &processor.mod_vis;
    let mod_ident = &processor.mod_ident;

    Ok(quote! {
        #(#mod_attrs)*
        #mod_vis mod #mod_ident {
            #(#other_items)*

            // Header struct definitions
            #(#header_items)*

            // Step struct definitions
            #(#step_items)*

            // Header trait implementations
            #(#header_impls)*

            // Step trait implementations
            #(#step_impls)*

            // Build function
            #build_fn
        }
    })
}

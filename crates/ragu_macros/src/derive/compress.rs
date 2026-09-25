use proc_macro2::{TokenStream, TokenTree};
use quote::{ToTokens, format_ident, quote};
use syn::{
    Attribute, Data, DeriveInput, Error, Expr, Fields, GenericParam, Ident, Result, Token, Type,
    meta::ParseNestedMeta, parse_quote, spanned::Spanned,
};

use crate::path_resolution::RaguPrimitivesPath;

// The ragu namespace is shared with Gadget, Write, and other derives.
fn skip_foreign(meta: ParseNestedMeta<'_>) -> Result<()> {
    if meta.input.peek(Token![=]) {
        let _: Expr = meta.value()?.parse()?;
    } else if meta.input.peek(syn::token::Paren) {
        let content;
        syn::parenthesized!(content in meta.input);
        let _: TokenStream = content.parse()?;
    }
    Ok(())
}

fn retain_generated_attrs(attrs: &mut Vec<Attribute>) {
    attrs.retain(|attr| {
        [
            "doc", "cfg", "cfg_attr", "allow", "expect", "warn", "deny", "forbid",
        ]
        .iter()
        .any(|name| attr.path().is_ident(name))
    });
}

fn mentions(tokens: TokenStream, name: &str) -> bool {
    tokens.into_iter().any(|token| match token {
        TokenTree::Ident(id) => id == name,
        TokenTree::Group(group) => mentions(group.stream(), name),
        TokenTree::Punct(_) | TokenTree::Literal(_) => false,
    })
}

// Self would refer to different types in the source and generated structs.
fn contains_self(tokens: TokenStream) -> bool {
    mentions(tokens, "Self")
}

pub fn derive(input: DeriveInput, path: RaguPrimitivesPath) -> Result<TokenStream> {
    let name = &input.ident;
    let visibility = &input.vis;
    let wire = quote!(#path::wire);
    let mut compressed_name = None;
    let mut derived_name = None;
    for attr in input.attrs.iter().filter(|a| a.path().is_ident("ragu")) {
        attr.parse_nested_meta(|meta| {
            let slot = if meta.path.is_ident("compressed") {
                &mut compressed_name
            } else if meta.path.is_ident("derived") {
                &mut derived_name
            } else {
                return skip_foreign(meta);
            };
            if slot.is_some() {
                return Err(meta.error("duplicate name"));
            }
            *slot = Some(meta.value()?.parse::<Ident>()?);
            Ok(())
        })?;
    }
    let compressed_name = compressed_name.unwrap_or_else(|| format_ident!("{}Compressed", name));
    let derived_name = derived_name.unwrap_or_else(|| format_ident!("{}Derived", name));
    if compressed_name == *name || derived_name == *name || compressed_name == derived_name {
        return Err(Error::new(
            name.span(),
            "the source, compressed and derived names must all differ",
        ));
    }
    let Data::Struct(data) = &input.data else {
        return Err(Error::new(
            input.span(),
            "Compress requires a struct with named fields",
        ));
    };
    let Fields::Named(named) = &data.fields else {
        return Err(Error::new(
            data.fields.span(),
            "Compress requires a struct with named fields",
        ));
    };
    let mut fields = Vec::new();
    let mut codecs = Vec::<Type>::new();
    let mut omitted = Vec::new();
    let mut derived_fields = Vec::new();
    // (batch, partner, partner type, field)
    let mut checked = Vec::<(Option<Ident>, Ident, Type, Ident)>::new();
    for field in &named.named {
        let id = field.ident.as_ref().unwrap();
        let mut provided = None;
        let mut partner = None;
        let mut batch = None;
        let mut codec = None;
        for attr in field.attrs.iter().filter(|a| a.path().is_ident("ragu")) {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("provided")
                    || meta.path.is_ident("derived")
                    || meta.path.is_ident("checked")
                {
                    if provided.is_some() {
                        return Err(meta.error(
                            "field requires exactly one provided/derived/checked classification",
                        ));
                    }
                    provided = Some(!meta.path.is_ident("derived"));
                    if meta.path.is_ident("checked") {
                        partner = Some(meta.value()?.parse::<Ident>()?);
                    }
                } else if meta.path.is_ident("codec") {
                    if codec.is_some() {
                        return Err(meta.error("duplicate codec"));
                    }
                    codec = Some(meta.value()?.parse::<Type>()?);
                } else if meta.path.is_ident("batch") {
                    if batch.is_some() {
                        return Err(meta.error("duplicate batch"));
                    }
                    batch = Some(meta.value()?.parse::<Ident>()?);
                } else {
                    return skip_foreign(meta);
                }
                Ok(())
            })?;
        }
        let provided = provided.ok_or_else(|| {
            Error::new(
                field.span(),
                "field requires #[ragu(provided)], #[ragu(derived)] or #[ragu(checked = field)]",
            )
        })?;
        match (partner, batch) {
            (Some(partner), batch) => {
                let partner_ty = named
                    .named
                    .iter()
                    .find(|f| f.ident.as_ref() == Some(&partner))
                    .map(|f| f.ty.clone())
                    .ok_or_else(|| {
                        Error::new(partner.span(), "checked against an unknown field")
                    })?;
                checked.push((batch, partner, partner_ty, id.clone()));
            }
            (None, Some(batch)) => {
                return Err(Error::new(batch.span(), "batch requires checked = field"));
            }
            (None, None) => {}
        }
        if !provided {
            if codec.is_some() {
                return Err(Error::new(
                    field.span(),
                    "derived fields cannot specify a codec",
                ));
            }
            omitted.push(format!("`{id}`"));
            let mut field = field.clone();
            retain_generated_attrs(&mut field.attrs);
            derived_fields.push(field);
            continue;
        }
        let codec = codec.unwrap_or_else(|| parse_quote!(#wire::DefaultEncoding));
        if contains_self(field.ty.to_token_stream()) || contains_self(codec.to_token_stream()) {
            return Err(Error::new(
                field.span(),
                "Compress does not support Self in provided field types or codecs",
            ));
        }
        let mut field = field.clone();
        // Other derives' helpers must not be copied onto the generated struct.
        retain_generated_attrs(&mut field.attrs);
        fields.push(field);
        codecs.push(codec);
    }
    let mut docs = format!("Compressed representation of [`{name}`].");
    if !omitted.is_empty() {
        docs.push_str(&format!(
            "\n\nFields marked `derived` and omitted: {}.",
            omitted.join(", ")
        ));
    }
    if !checked.is_empty() {
        let pairs: Vec<_> = checked
            .iter()
            .map(|(batch, partner, _, id)| match batch {
                Some(batch) => format!("`{id}` against `{partner}` ({batch})"),
                None => format!("`{id}` against `{partner}`"),
            })
            .collect();
        docs.push_str(&format!(
            "\n\nFields marked `checked`, retained and visited by `for_each_checked`: {}.",
            pairs.join(", ")
        ));
    }
    // Preserve the source's parameters and bounds. Parameters used only by
    // omitted fields are outside this prototype's supported generic shapes.
    let mut generics = input.generics.clone();
    for param in &mut generics.params {
        let attrs = match param {
            GenericParam::Type(p) => &mut p.attrs,
            GenericParam::Lifetime(p) => &mut p.attrs,
            GenericParam::Const(p) => &mut p.attrs,
        };
        retain_generated_attrs(attrs);
    }
    let derived_docs = format!(
        "The fields of [`{name}`] marked `derived`, recomputed from a [`{compressed_name}`] to expand it."
    );
    let derived_ids: Vec<_> = derived_fields
        .iter()
        .map(|f| f.ident.as_ref().unwrap())
        .collect();
    // A parameter no derived field mentions still has to appear in the
    // derived struct; a `fn` pointer phantom neither adds bounds nor
    // changes auto traits or variance.
    let derived_types = derived_fields
        .iter()
        .map(|f| f.ty.to_token_stream())
        .collect::<TokenStream>();
    let unused: Vec<TokenStream> = generics
        .params
        .iter()
        .filter_map(|param| match param {
            GenericParam::Type(p) => {
                (!mentions(derived_types.clone(), &p.ident.to_string())).then(|| {
                    let id = &p.ident;
                    quote!(#id)
                })
            }
            GenericParam::Lifetime(p) => {
                (!mentions(derived_types.clone(), &p.lifetime.ident.to_string())).then(|| {
                    let lt = &p.lifetime;
                    quote!(&#lt ())
                })
            }
            GenericParam::Const(_) => None,
        })
        .collect();
    let derived_marker = (!unused.is_empty())
        .then(|| quote!(__ragu_unused: ::core::marker::PhantomData<fn() -> (#(#unused,)*)>,));
    let ids: Vec<_> = fields.iter().map(|f| f.ident.as_ref().unwrap()).collect();
    let types: Vec<_> = fields.iter().map(|f| &f.ty).collect();
    let cfg: Vec<_> = input
        .attrs
        .iter()
        .filter(|a| a.path().is_ident("cfg") || a.path().is_ident("cfg_attr"))
        .collect();
    let (_, compressed_args, compressed_where) = generics.split_for_impl();
    let mut clone_generics = generics.clone();
    let mut encode_generics = generics.clone();
    let mut decode_generics = generics.clone();
    for (ty, codec) in types.iter().zip(&codecs) {
        clone_generics
            .make_where_clause()
            .predicates
            .push(parse_quote!(#ty: ::core::clone::Clone));
        encode_generics
            .make_where_clause()
            .predicates
            .push(parse_quote!(#ty: #wire::Encode<#codec>));
        decode_generics
            .make_where_clause()
            .predicates
            .push(parse_quote!(#ty: #wire::Decode<#codec>));
    }
    let (clone_impl, source_args, clone_where) = clone_generics.split_for_impl();
    let (encode_impl, _, encode_where) = encode_generics.split_for_impl();
    let (source_impl, _, source_where) = input.generics.split_for_impl();
    // One visitor per batch: a sink is typed by the batch it collects, and
    // a single sink over every batch would need impls coherence cannot separate.
    let mut batches: Vec<Option<Ident>> = Vec::new();
    for (batch, ..) in &checked {
        if !batches.contains(batch) {
            batches.push(batch.clone());
        }
    }
    let visitors: Vec<TokenStream> = batches
        .iter()
        .map(|batch| {
            let members: Vec<_> = checked.iter().filter(|(b, ..)| b == batch).collect();
            let field_ty: Vec<_> = members
                .iter()
                .map(|(_, _, _, id)| &fields.iter().find(|f| f.ident.as_ref() == Some(id)).unwrap().ty)
                .collect();
            let partner: Vec<_> = members.iter().map(|(_, p, _, _)| p).collect();
            let partner_ty: Vec<_> = members.iter().map(|(_, _, ty, _)| ty).collect();
            let id: Vec<_> = members.iter().map(|(_, _, _, id)| id).collect();
            let method = match batch {
                Some(batch) => format_ident!("for_each_checked_{}", batch),
                None => format_ident!("for_each_checked"),
            };
            let doc = match batch {
                Some(batch) => format!(
                    "Hands every field of the `{batch}` batch marked `checked` to `sink` with the field it is checked against, in declaration order."
                ),
                None => String::from(
                    "Hands every field marked `checked` to `sink` with the field it is checked against, in declaration order.",
                ),
            };
            quote! {
                #(#cfg)*
                #[automatically_derived]
                impl #source_impl #name #source_args #source_where {
                    #[doc = #doc]
                    pub(crate) fn #method<'__ragu_checked, __Sink>(
                        &'__ragu_checked self,
                        sink: &mut __Sink,
                    ) where
                        __Sink: #(#wire::Checked<'__ragu_checked, #partner_ty, #field_ty>)+*,
                    {
                        #(<__Sink as #wire::Checked<'__ragu_checked, #partner_ty, #field_ty>>::check(sink, &self.#partner, &self.#id);)*
                    }
                }
            }
        })
        .collect();
    let (decode_impl, _, decode_where) = decode_generics.split_for_impl();
    let mut lifetime = syn::Lifetime::new("'__ragu_wire", name.span());
    while generics.lifetimes().any(|p| p.lifetime == lifetime) {
        lifetime = syn::Lifetime::new(&format!("{}x", lifetime), name.span());
    }
    Ok(quote! {
        #(#cfg)*
        #[doc = #docs]
        #visibility struct #compressed_name #generics #compressed_where {
            #(#fields,)*
        }
        #(#visitors)*
        #(#cfg)*
        #[doc = #derived_docs]
        // Plumbing for expansion; a consumer that never expands leaves it unused.
        #[allow(dead_code)]
        #visibility struct #derived_name #generics #compressed_where {
            #(#derived_fields,)*
            #derived_marker
        }
        #(#cfg)*
        #[automatically_derived]
        impl #clone_impl #wire::Compress for #name #source_args #clone_where {
            type Compressed = #compressed_name #compressed_args;
            type Derived = #derived_name #compressed_args;
            fn compress(&self) -> Self::Compressed {
                #compressed_name { #(#ids: ::core::clone::Clone::clone(&self.#ids),)* }
            }
            fn expand(compressed: Self::Compressed, derived: Self::Derived) -> Self {
                Self {
                    #(#ids: compressed.#ids,)*
                    #(#derived_ids: derived.#derived_ids,)*
                }
            }
        }
        #(#cfg)*
        #[automatically_derived]
        impl #encode_impl #wire::Encode for #compressed_name #compressed_args #encode_where {
            fn encode(&self, output: &mut #wire::__private::Vec<u8>) {
                #(<#types as #wire::Encode<#codecs>>::encode(&self.#ids, output);)*
            }
        }
        #(#cfg)*
        #[automatically_derived]
        impl #decode_impl #wire::Decode for #compressed_name #compressed_args #decode_where {
            fn min_encoded_len() -> usize {
                0usize #(.saturating_add(<#types as #wire::Decode<#codecs>>::min_encoded_len()))*
            }
            fn decode<#lifetime>(reader: &mut #wire::Reader<#lifetime>) -> ::core::result::Result<Self, #wire::Error<#lifetime>> {
                Ok(Self { #(#ids: <#types as #wire::Decode<#codecs>>::decode(reader)?,)* })
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignores_foreign_metadata_without_consuming_owned_keys() {
        let input = parse_quote! {
            #[ragu(other = "container", nested(flag), compressed = Package)]
            struct Working {
                #[ragu(gadget, other = "field", nested(flag), provided)]
                value: u64,
            }
        };
        derive(input, RaguPrimitivesPath::default()).unwrap();
    }

    #[test]
    fn rejects_invalid_classifications() {
        let cases: &[(DeriveInput, &str)] = &[
            (
                parse_quote!(
                    struct Missing {
                        x: u64,
                    }
                ),
                "requires #[ragu(provided)]",
            ),
            (
                parse_quote!(
                    struct Conflict {
                        #[ragu(provided, derived)]
                        x: u64,
                    }
                ),
                "exactly one",
            ),
            (
                parse_quote!(
                    struct Duplicate {
                        #[ragu(provided)]
                        #[ragu(provided)]
                        x: u64,
                    }
                ),
                "exactly one",
            ),
            (
                parse_quote!(
                    struct Typo {
                        #[ragu(provded)]
                        x: u64,
                    }
                ),
                "requires #[ragu(provided)]",
            ),
            (
                parse_quote!(
                    struct Codec {
                        #[ragu(derived, codec = Scalar)]
                        x: u64,
                    }
                ),
                "cannot specify a codec",
            ),
            (
                parse_quote!(
                    struct Codecs {
                        #[ragu(provided, codec = A, codec = B)]
                        x: u64,
                    }
                ),
                "duplicate codec",
            ),
            (
                parse_quote!(
                    struct Unknown {
                        #[ragu(checked = missing)]
                        x: u64,
                    }
                ),
                "unknown field",
            ),
            (
                parse_quote!(
                    struct Tuple(u64);
                ),
                "named fields",
            ),
            (
                parse_quote!(
                    enum Enum {
                        X,
                    }
                ),
                "named fields",
            ),
        ];
        for (input, message) in cases {
            let error = derive(input.clone(), RaguPrimitivesPath::default()).unwrap_err();
            assert!(error.to_string().contains(message), "{error}");
        }
    }
}

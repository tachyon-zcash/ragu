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

// Self would refer to different types in the source and generated structs.
fn contains_self(tokens: TokenStream) -> bool {
    tokens.into_iter().any(|token| match token {
        TokenTree::Ident(id) => id == "Self",
        TokenTree::Group(group) => contains_self(group.stream()),
        _ => false,
    })
}

pub fn derive(input: DeriveInput, path: RaguPrimitivesPath) -> Result<TokenStream> {
    let name = &input.ident;
    let visibility = &input.vis;
    let wire = quote!(#path::wire);
    let mut compressed_name = None;
    for attr in input.attrs.iter().filter(|a| a.path().is_ident("ragu")) {
        attr.parse_nested_meta(|meta| {
            if !meta.path.is_ident("compressed") {
                return skip_foreign(meta);
            }
            if compressed_name.is_some() {
                return Err(meta.error("duplicate compressed name"));
            }
            compressed_name = Some(meta.value()?.parse::<Ident>()?);
            Ok(())
        })?;
    }
    let compressed_name = compressed_name.unwrap_or_else(|| format_ident!("{}Compressed", name));
    if compressed_name == *name {
        return Err(Error::new(
            name.span(),
            "compressed name must differ from the source struct",
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
    for field in &named.named {
        let id = field.ident.as_ref().unwrap();
        let mut provided = None;
        let mut codec = None;
        for attr in field.attrs.iter().filter(|a| a.path().is_ident("ragu")) {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("provided") || meta.path.is_ident("derived") {
                    if provided.is_some() {
                        return Err(meta
                            .error("field requires exactly one provided/derived classification"));
                    }
                    provided = Some(meta.path.is_ident("provided"));
                } else if meta.path.is_ident("codec") {
                    if codec.is_some() {
                        return Err(meta.error("duplicate codec"));
                    }
                    codec = Some(meta.value()?.parse::<Type>()?);
                } else {
                    return skip_foreign(meta);
                }
                Ok(())
            })?;
        }
        let provided = provided.ok_or_else(|| {
            Error::new(
                field.span(),
                "field requires #[ragu(provided)] or #[ragu(derived)]",
            )
        })?;
        if !provided {
            if codec.is_some() {
                return Err(Error::new(
                    field.span(),
                    "derived fields cannot specify a codec",
                ));
            }
            omitted.push(format!("`{id}`"));
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
        #(#cfg)*
        #[automatically_derived]
        impl #clone_impl #wire::Compress for #name #source_args #clone_where {
            type Compressed = #compressed_name #compressed_args;
            fn compress(&self) -> Self::Compressed {
                #compressed_name { #(#ids: ::core::clone::Clone::clone(&self.#ids),)* }
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

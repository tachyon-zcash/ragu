use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Index, LitInt, Result};

pub fn evaluate(input: LitInt) -> Result<TokenStream> {
    let max_tuple_size = input.base10_parse::<usize>()?;
    if max_tuple_size < 2 {
        return Err(syn::Error::new_spanned(
            input,
            "max tuple size must be at least 2",
        ));
    }

    let impls = (2..=max_tuple_size).map(generate_impl_for_size);

    Ok(quote! {
        #(#impls)*
    })
}

/// Generate a single MaybeCast implementation for a tuple of the given size.
fn generate_impl_for_size(size: usize) -> TokenStream {
    let types: Vec<_> = (0..size).map(|i| format_ident!("T{}", i)).collect();
    let indices = (0..size).map(Index::from);
    let empties = std::iter::repeat_n(quote! { K::empty() }, size);

    quote! {
        impl<#(#types: Send,)* K: MaybeKind> MaybeCast<(#(#types,)*), K> for (#(#types,)*) {
            type Output = (#(Perhaps<K, #types>,)*);

            fn empty() -> Self::Output {
                (#(#empties,)*)
            }

            fn cast(self) -> Self::Output {
                (#(K::maybe_just(|| self.#indices),)*)
            }
        }
    }
}

#[test]
fn test_generate_2tuple() {
    let output = generate_impl_for_size(2);
    let expected = quote! {
        impl<T0: Send, T1: Send, K: MaybeKind> MaybeCast<(T0, T1,), K> for (T0, T1,) {
            type Output = (Perhaps<K, T0>, Perhaps<K, T1>,);

            fn empty() -> Self::Output {
                (K::empty(), K::empty(),)
            }

            fn cast(self) -> Self::Output {
                (K::maybe_just(|| self.0), K::maybe_just(|| self.1),)
            }
        }
    };
    assert_eq!(output.to_string(), expected.to_string());
}

#[test]
fn test_evaluate() {
    use syn::parse_quote;

    // Test with 3 to generate implementations for sizes 2 and 3 (inclusive)
    let input: LitInt = parse_quote!(3);
    let output = evaluate(input).unwrap();
    assert!(!output.is_empty());

    // Verify it contains impl for 2-tuple and 3-tuple, but not 4-tuple
    let output_str = output.to_string();
    assert!(output_str.contains("T0"));
    assert!(output_str.contains("T1"));
    assert!(output_str.contains("T2"));
    assert!(!output_str.contains("T3"));
}

#[test]
fn test_evaluate_minimum() {
    use syn::parse_quote;

    // Test minimum valid input (2 generates only 2-tuple)
    let input: LitInt = parse_quote!(2);
    let output = evaluate(input).unwrap();
    let output_str = output.to_string();
    assert!(output_str.contains("T0"));
    assert!(output_str.contains("T1"));
    assert!(!output_str.contains("T2"));
}

#[test]
fn test_evaluate_rejects_small_max() {
    use syn::parse_quote;

    let input: LitInt = parse_quote!(1);
    assert!(evaluate(input).is_err());
}

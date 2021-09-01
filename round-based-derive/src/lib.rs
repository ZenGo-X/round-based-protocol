use proc_macro2::TokenStream;
use quote::{quote, quote_spanned};
use syn::{parse_macro_input, Data, DeriveInput, Fields, Generics, Ident, Variant};

#[proc_macro_derive(ProtocolMessage)]
pub fn protocol_message(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let enum_data = match input.data {
        Data::Enum(e) => e,
        Data::Struct(s) => {
            return quote_spanned! {s.struct_token.span => compile_error!("only enum may implement ProtocolMessage");}.into()
        }
        Data::Union(s) => {
            return quote_spanned! {s.union_token.span => compile_error!("only enum may implement ProtocolMessage");}.into()
        }
    };

    let name = input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let variant_id_method = variant_id(&name, enum_data.variants.iter());

    let impl_protocol_message = quote! {
        impl #impl_generics round_based::rounds::ProtocolMessage for #name #ty_generics #where_clause {
            fn variant_id(&self) -> u16 {
                #variant_id_method
            }
        }
    };

    let impl_round_message = round_messages(&name, &input.generics, enum_data.variants.iter());

    proc_macro::TokenStream::from(quote! {
        #impl_protocol_message
        #impl_round_message
    })
}

fn variant_id<'v>(enum_name: &Ident, variants: impl Iterator<Item = &'v Variant>) -> TokenStream {
    let match_variants = (0u16..).zip(variants).map(|(i, variant)| {
        let variant_name = &variant.ident;
        match &variant.fields {
            Fields::Unit => quote_spanned! {
                variant.ident.span() =>
                #enum_name::#variant_name => compile_error!("unit variants are not allowed in ProtocolMessage"),
            },
            Fields::Named(_) => quote_spanned! {
                variant.ident.span() =>
                #enum_name::#variant_name{..} => compile_error!("named variants are not allowed in ProtocolMessage"),
            },
            Fields::Unnamed(unnamed) => if unnamed.unnamed.len() == 1 {
                quote_spanned! {
                    variant.ident.span() =>
                    #enum_name::#variant_name(_) => #i,
                }
            } else {
                quote_spanned! {
                    variant.ident.span() =>
                    #enum_name::#variant_name(..) => compile_error!("this variant must contain exactly one field to be valid ProtocolMessage"),
                }
            },
        }
    });
    quote! {
        match self {
            #(#match_variants)*
        }
    }
}

fn round_messages<'v>(
    enum_name: &Ident,
    generics: &Generics,
    variants: impl Iterator<Item = &'v Variant>,
) -> TokenStream {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let impls = (0u16..).zip(variants).map(|(i, variant)| {
        let variant_name = &variant.ident;
        match &variant.fields {
            Fields::Unnamed(unnamed) if unnamed.unnamed.len() == 1 => {
                let msg_type = &unnamed.unnamed[0].ty;
                quote_spanned! {
                    variant.ident.span() =>
                    impl #impl_generics round_based::rounds::RoundMessage<#msg_type> for #enum_name #ty_generics #where_clause {
                        const VARIANT_ID: u16 = #i;
                        fn into_round_message(self) -> Option<#msg_type> {
                            match self {
                                #enum_name::#variant_name(msg) => Some(msg),
                                _ => None,
                            }
                        }
                        fn from_round_message(msg: #msg_type) -> Self {
                            #enum_name::#variant_name(msg)
                        }
                    }
                }
            }
            _ => quote! {},
        }
    });
    quote! {
        #(#impls)*
    }
}

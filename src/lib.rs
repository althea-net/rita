#![recursion_limit = "128"]
extern crate proc_macro;

#[macro_use]
extern crate quote;
extern crate syn;
use proc_macro::TokenStream;

#[proc_macro_derive(ArrayTupleDeref)]
pub fn deref(input: TokenStream) -> TokenStream {
    impl_deref(&syn::parse_derive_input(&input.to_string()).unwrap())
        .parse()
        .unwrap()
}

#[proc_macro_derive(ArrayTupleBase64)]
pub fn b64(input: TokenStream) -> TokenStream {
    impl_base64(&syn::parse_derive_input(&input.to_string()).unwrap())
        .parse()
        .unwrap()
}

fn get_array_length(body: &syn::Body) -> usize {
    match *body {
        syn::Body::Struct(ref variant_data) => match *variant_data {
            syn::VariantData::Tuple(ref fields) => match fields[0].ty {
                syn::Ty::Array(_, ref const_expr) => match *const_expr {
                    syn::ConstExpr::Lit(ref lit) => match *lit {
                        syn::Lit::Int(ref num, _) => *num as usize,
                        _ => panic!("cannot derive array deref on this type"),
                    },
                    _ => panic!("cannot derive array deref on this type"),
                },
                _ => panic!("cannot derive array deref on this type"),
            },
            _ => panic!("cannot derive array deref on this type"),
        },
        _ => panic!("cannot derive array deref on this type"),
    }
}

fn impl_deref(ast: &syn::DeriveInput) -> quote::Tokens {
    let length = get_array_length(&ast.body);
    let name = &ast.ident;

    quote! {
        impl Deref for #name {
          type Target = [u8; #length as usize];

          fn deref(&self) -> &[u8; #length as usize] {
              &self.0
          }
        }
    }
}

fn impl_base64(ast: &syn::DeriveInput) -> quote::Tokens {
    let length = get_array_length(&ast.body);
    let name = &ast.ident;

    quote! {
        impl Serialize for #name {
          fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
          where
            S: Serializer,
          {
            serializer.serialize_str(&base64::encode(&*self.as_ref()))
          }
        }

        impl<'de: 'a, 'a> Deserialize<'de> for #name {
          fn deserialize<D>(deserializer: D) -> Result<#name, D::Error>
          where
            D: Deserializer<'de>,
          {
            let s = <&str>::deserialize(deserializer)?;

            base64::decode(s).map(|v| {
              let mut arr = [0u8; #length];
              arr.clone_from_slice(&v);
              #name(arr)
            })
            .map_err(serde::de::Error::custom)
          }
        }
    }
}

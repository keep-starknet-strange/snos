extern crate proc_macro;

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{parse_macro_input, Data, DeriveInput, Fields};

#[proc_macro_derive(CairoType)]
pub fn cairo_type_derive(input: TokenStream) -> TokenStream {
    // Parse the input tokens into a syntax tree
    let input = parse_macro_input!(input as DeriveInput);

    // Get the identifier of the struct
    let struct_ident = &input.ident;

    // Generate code to implement the trait
    let expanded = match &input.data {
        Data::Struct(data_struct) => match &data_struct.fields {
            Fields::Named(fields) => {
                let field_names_read = fields.named.iter().map(|f| &f.ident);
                let field_names_write = field_names_read.clone();
                let n_fields = field_names_read.clone().count();
                let field_values = field_names_read.clone().enumerate().map(|(index, field_name)| {
                    quote! {
                        let #field_name = vm.get_integer(&address + #index)?.into_owned();
                    }
                });

                quote! {
                    impl CairoType for #struct_ident {
                        fn from_memory(vm: &VirtualMachine, address: Relocatable) -> Result<Self, MemoryError> {
                         #(#field_values)*
                            Ok(Self {
                                #( #field_names_read ),*
                            })
                        }
                        fn to_memory(&self, vm: &mut VirtualMachine, address: Relocatable) -> Result<(), MemoryError> {
                            let mut offset = 0;
                            #(vm.insert_value(&address + offset, &self.#field_names_write)?; offset += 1;)*

                            Ok(())
                        }

                        fn n_fields() -> usize {
                            #n_fields
                        }
                    }
                }
            }
            Fields::Unnamed(_) | Fields::Unit => {
                // Unsupported field types
                quote! {
                    compile_error!("CairoType only supports structs with named fields");
                }
            }
        },
        Data::Enum(_) | Data::Union(_) => {
            // Unsupported data types
            quote! {
                compile_error!("CairoType only supports structs");
            }
        }
    };

    // Convert the generated code into a TokenStream and return it
    TokenStream::from(expanded)
}

/// Provides a method to compute the address of each field
#[proc_macro_derive(FieldOffsetGetters)]
pub fn get_field_addr_derive(input: TokenStream) -> TokenStream {
    // Parse the input tokens into a syntax tree
    let input = parse_macro_input!(input as DeriveInput);

    // Get the identifier of the struct
    let struct_ident = &input.ident;

    // Generate code to implement the trait
    let getters = match &input.data {
        Data::Struct(data_struct) => {
            // Extract fields' names and types
            let fields = match &data_struct.fields {
                Fields::Named(fields) => &fields.named,
                _ => {
                    return quote! {
                        compile_error!("FieldOffsetGetters only supports structs with named fields");
                    }
                    .into();
                }
            };

            // Generate setter methods for each field
            let get_field_offset_methods = fields.iter().enumerate().map(|(index, field)| {
                let field_name = field.ident.as_ref().expect("Expected named field");
                let fn_name = format_ident!("{}_offset", field_name);
                quote! {
                    pub fn #fn_name() -> usize {
                        #index
                    }
                }
            });

            // Combine all setter methods
            quote! {
                impl #struct_ident {
                    #( #get_field_offset_methods )*
                }
            }
        }
        _ => {
            quote! {
                compile_error!("FieldOffsetGetters only supports structs");
            }
        }
    };

    // Convert the generated code into a TokenStream and return it
    getters.into()
}

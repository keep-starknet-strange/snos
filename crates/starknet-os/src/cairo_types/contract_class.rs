use cairo_type_derive::FieldOffsetGetters;
use cairo_vm::Felt252;

/// Holds the hashes of the contract class components, to be used for calculating the final hash.
/// Note: the order of the struct members must not be changed since it determines the hash order.
#[derive(FieldOffsetGetters)]
#[allow(unused)]
pub(crate) struct ContractClassComponentHashes {
    contract_class_version: Felt252,
    external_functions_hash: Felt252,
    l1_handlers_hash: Felt252,
    constructors_hash: Felt252,
    abi_hash: Felt252,
    sierra_program_hash: Felt252,
}

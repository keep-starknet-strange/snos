use cairo_type_derive::FieldOffsetGetters;
use cairo_vm::Felt252;

#[allow(unused)]
#[derive(FieldOffsetGetters)]
pub struct ExecutionContext {
    pub entry_point_type: Felt252,
    pub class_hash: Felt252,
    pub calldata_size: Felt252,
    pub calldata: Felt252,
    pub execution_info: Felt252,
    pub deprecated_tx_info: Felt252,
}

#[allow(unused)]
#[derive(FieldOffsetGetters)]
pub struct CompiledClassFact {
    pub hash: Felt252,
    pub compiled_class: Felt252,
}

#[allow(unused)]
#[derive(FieldOffsetGetters)]
pub struct CompiledClass {
    compiled_class_version: Felt252,
    n_external_functions: Felt252,
    external_functions: Felt252,
    n_l1_handlers: Felt252,
    l1_handlers: Felt252,
    n_constructors: Felt252,
    constructors: Felt252,
    bytecode_length: Felt252,
    bytecode_ptr: Felt252,
}

#[allow(unused)]
#[derive(FieldOffsetGetters)]
pub struct EntryPointReturnValues {
    gas_builtin: Felt252,
    syscall_ptr: Felt252,
    failure_flag: Felt252,
    retdata_start: Felt252,
    retdata_end: Felt252,
}

#[allow(unused)]
#[derive(FieldOffsetGetters)]
pub struct BuiltinParams {
    builtin_encodings: Felt252,
    builtin_instance_sizes: Felt252,
}

#[allow(unused)]
#[derive(FieldOffsetGetters)]
pub struct CallContractResponse {
    retdata_start: Felt252,
    retdata_end: Felt252,
}

// TODO: how to handle this?
// struct BuiltinPointers {
//     selectable: SelectableBuiltins,
//     non_selectable: NonSelectableBuiltins,
// }

// #[allow(unused)]
// #[derive(FieldOffsetGetters)]
// pub struct BuiltinPointers {
//     selectable: Felt252,
//     non_selectable: Felt252,
// }

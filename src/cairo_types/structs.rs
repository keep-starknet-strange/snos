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

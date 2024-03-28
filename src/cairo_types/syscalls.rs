use cairo_type_derive::FieldOffsetGetters;
use cairo_vm::Felt252;

#[derive(FieldOffsetGetters)]
pub struct StorageWrite {
    pub selector: Felt252,
    pub address: Felt252,
    pub value: Felt252,
}

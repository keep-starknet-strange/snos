use cairo_type_derive::FieldOffsetGetters;
use cairo_vm::Felt252;

#[derive(FieldOffsetGetters)]
pub struct DictAccess {
    pub key: Felt252,
    pub prev_value: Felt252,
    pub new_value: Felt252,
}

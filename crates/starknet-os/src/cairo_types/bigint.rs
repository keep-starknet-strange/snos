use cairo_type_derive::FieldOffsetGetters;
use cairo_vm::Felt252;

#[derive(FieldOffsetGetters)]
pub struct BigInt3 {
    pub d0: Felt252,
    pub d1: Felt252,
    pub d2: Felt252,
}

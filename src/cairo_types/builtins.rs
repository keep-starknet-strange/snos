use cairo_type_derive::FieldOffsetGetters;
use cairo_vm::Felt252;

#[allow(unused)]
#[derive(FieldOffsetGetters)]
pub struct HashBuiltin {
    pub x: Felt252,
    pub y: Felt252,
    pub result: Felt252,
}

#[allow(unused)]
#[derive(FieldOffsetGetters)]
pub struct SpongeHashBuiltin {
    pub x: Felt252,
    pub y: Felt252,
    pub c_in: Felt252,
    pub result: Felt252,
    pub result1: Felt252,
    pub c_out: Felt252,
}

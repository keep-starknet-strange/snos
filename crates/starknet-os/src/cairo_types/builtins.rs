use cairo_type_derive::FieldOffsetGetters;
use cairo_vm::Felt252;

#[derive(FieldOffsetGetters)]
pub struct HashBuiltin {
    #[allow(unused)]
    pub x: Felt252,
    #[allow(unused)]
    pub y: Felt252,
    #[allow(unused)]
    pub result: Felt252,
}

#[derive(FieldOffsetGetters)]
pub struct SpongeHashBuiltin {
    #[allow(unused)]
    pub x: Felt252,
    #[allow(unused)]
    pub y: Felt252,
    #[allow(unused)]
    pub c_in: Felt252,
    #[allow(unused)]
    pub result: Felt252,
    #[allow(unused)]
    pub result1: Felt252,
    #[allow(unused)]
    pub c_out: Felt252,
}

use cairo_type_derive::FieldOffsetGetters;
use cairo_vm::Felt252;

#[derive(FieldOffsetGetters)]
pub struct BigInt3 {
    #[allow(unused)]
    pub d0: Felt252,
    #[allow(unused)]
    pub d1: Felt252,
    #[allow(unused)]
    pub d2: Felt252,
}

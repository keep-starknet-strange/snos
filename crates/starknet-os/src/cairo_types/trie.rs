use cairo_type_derive::{CairoType, FieldOffsetGetters};
use cairo_vm::types::relocatable::Relocatable;
use cairo_vm::vm::errors::memory_errors::MemoryError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;

use crate::cairo_types::traits::CairoType;

#[derive(CairoType, FieldOffsetGetters)]
pub struct NodeEdge {
    pub length: Felt252,
    pub path: Felt252,
    pub bottom: Felt252,
}

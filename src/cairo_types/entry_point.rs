use cairo_type_derive::FieldOffsetGetters;
use cairo_vm::types::relocatable::Relocatable;
use cairo_vm::Felt252;

#[derive(FieldOffsetGetters)]
pub struct EntryPointReturnValues {
    pub gas_builtin: Felt252,
    pub syscall_ptr: Relocatable,
    /// The failure_flag is 0 if the execution succeeded and 1 if it failed.
    pub failure_flag: Felt252,
    pub retdata_start: Relocatable,
    pub retdata_end: Relocatable,
}

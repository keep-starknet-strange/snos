use std::collections::HashMap;

use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::insert_value_from_var_name;
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use indoc::indoc;

use crate::hints::vars;

pub const ADDITIONAL_DATA_NEW_SEGMENT: &str = indoc! {r#"
    ids.additional_data = segments.add()"#
};

pub fn additional_data_new_segment(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    insert_value_from_var_name(vars::ids::ADDITIONAL_DATA, vm.add_memory_segment(), vm, ids_data, ap_tracking)
}

pub const DATA_TO_HASH_NEW_SEGMENT: &str = indoc! {r#"
    ids.data_to_hash = segments.add()"#
};

pub fn data_to_hash_new_segment(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    insert_value_from_var_name(vars::ids::DATA_TO_HASH, vm.segments.add(), vm, ids_data, ap_tracking)
}

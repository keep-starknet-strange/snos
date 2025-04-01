use std::collections::HashMap;

use cairo_vm::Felt252;
use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{
    get_integer_from_var_name, get_ptr_from_var_name, insert_value_into_ap,
};
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;

use crate::cairo_types::syscalls::SecpNewResponse;
use crate::hints::vars;

pub const READ_EC_POINT_ADDRESS: &str = r#"memory[ap] = to_felt_or_relocatable(ids.response.ec_point.address_ if ids.not_on_curve == 0 else segments.add())"#;
pub fn read_ec_point_from_address(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let not_on_curve = get_integer_from_var_name(vars::ids::NOT_ON_CURVE, vm, ids_data, _ap_tracking)?;
    if not_on_curve == Felt252::ZERO {
        let response = get_ptr_from_var_name(vars::ids::RESPONSE, vm, ids_data, _ap_tracking)?;
        let ec_point = vm.get_relocatable((response + SecpNewResponse::ec_point_offset())?)?;
        insert_value_into_ap(vm, ec_point)?;
    } else {
        let segment = vm.add_memory_segment();
        insert_value_into_ap(vm, segment)?;
    }
    Ok(())
}

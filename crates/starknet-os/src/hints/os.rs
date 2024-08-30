use std::collections::HashMap;

use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use indoc::indoc;

use crate::hints::vars;
use crate::io::input::StarknetOsInput;
use crate::utils::set_variable_in_root_exec_scope;

pub const WRITE_FULL_OUTPUT_TO_MEM: &str = indoc! {r#"memory[fp + 19] = to_felt_or_relocatable(os_input.full_output)"#};

pub fn write_full_output_to_mem(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let os_input: &StarknetOsInput = exec_scopes.get_ref(vars::scopes::OS_INPUT)?;
    let full_output = os_input.full_output;

    vm.insert_value((vm.get_fp() + 19)?, Felt252::from(full_output)).map_err(HintError::Memory)
}

pub const CONFIGURE_KZG_MANAGER: &str = indoc! {r#"__serialize_data_availability_create_pages__ = True
kzg_manager = execution_helper.kzg_manager"#};

pub fn configure_kzg_manager(
    _vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    set_variable_in_root_exec_scope(exec_scopes, vars::scopes::SERIALIZE_DATA_AVAILABILITY_CREATE_PAGES, true);
    // TODO: set kzg_manager

    Ok(())
}

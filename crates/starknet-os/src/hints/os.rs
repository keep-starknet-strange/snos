use std::collections::HashMap;

use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{
    get_integer_from_var_name, get_reference_from_var_name, insert_value_into_ap,
};
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::hint_processor::hint_processor_utils::get_integer_from_reference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use indoc::indoc;

use crate::execution::helper::ExecutionHelperWrapper;
use crate::hints::vars;
use crate::io::input::StarknetOsInput;
use crate::starknet::core::os::kzg_manager::KzgManager;
use crate::starknet::starknet_storage::PerContractStorage;
use crate::utils::{execute_coroutine, set_variable_in_root_exec_scope};

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

pub fn configure_kzg_manager<PCS>(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    constants: &HashMap<String, Felt252>,
) -> Result<(), HintError>
where
    PCS: PerContractStorage + 'static,
{
    execute_coroutine(configure_kzg_manager_async::<PCS>(vm, exec_scopes, ids_data, ap_tracking, constants))?
}
pub async fn configure_kzg_manager_async<PCS>(
    _vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError>
where
    PCS: PerContractStorage + 'static,
{
    set_variable_in_root_exec_scope(exec_scopes, vars::scopes::SERIALIZE_DATA_AVAILABILITY_CREATE_PAGES, true);

    // We don't leave kzg_manager in scope here, it can be obtained through execution_helper later

    Ok(())
}

pub const SET_AP_TO_PREV_BLOCK_HASH: &str = indoc! {r#"memory[ap] = to_felt_or_relocatable(os_input.prev_block_hash)"#};

pub fn set_ap_to_prev_block_hash(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let os_input: &StarknetOsInput = exec_scopes.get_ref(vars::scopes::OS_INPUT)?;
    insert_value_into_ap(vm, os_input.prev_block_hash)?;

    Ok(())
}

pub const SET_AP_TO_NEW_BLOCK_HASH: &str = "memory[ap] = to_felt_or_relocatable(os_input.new_block_hash)";

pub fn set_ap_to_new_block_hash(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let os_input: &StarknetOsInput = exec_scopes.get_ref(vars::scopes::OS_INPUT)?;
    insert_value_into_ap(vm, os_input.new_block_hash)?;

    Ok(())
}

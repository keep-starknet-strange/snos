use std::collections::HashMap;

use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::get_ptr_from_var_name;
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;

use crate::execution::deprecated_syscall_handler::DeprecatedOsSyscallHandlerWrapper;

pub const CALL_CONTRACT: &str = "syscall_handler.call_contract(segments=segments, syscall_ptr=ids.syscall_ptr)";
pub fn call_contract(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let syscall_handler = exec_scopes.get::<DeprecatedOsSyscallHandlerWrapper>("syscall_handler")?;
    let syscall_ptr = get_ptr_from_var_name("syscall_ptr", vm, ids_data, ap_tracking)?;

    syscall_handler.call_contract(syscall_ptr);

    Ok(())
}

pub const DELEGATE_CALL: &str = "syscall_handler.delegate_call(segments=segments, syscall_ptr=ids.syscall_ptr)";
pub fn delegate_call(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let syscall_handler = exec_scopes.get::<DeprecatedOsSyscallHandlerWrapper>("syscall_handler")?;
    let syscall_ptr = get_ptr_from_var_name("syscall_ptr", vm, ids_data, ap_tracking)?;

    syscall_handler.storage_write(syscall_ptr);

    Ok(())
}

pub const DELEGATE_L1_HANDLER: &str =
    "syscall_handler.delegate_l1_handler(segments=segments, syscall_ptr=ids.syscall_ptr)";
pub fn delegate_l1_handler(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let syscall_handler = exec_scopes.get::<DeprecatedOsSyscallHandlerWrapper>("syscall_handler")?;
    let syscall_ptr = get_ptr_from_var_name("syscall_ptr", vm, ids_data, ap_tracking)?;

    syscall_handler.delegate_l1_handler(syscall_ptr);

    Ok(())
}

pub const DEPLOY: &str = "syscall_handler.deploy(segments=segments, syscall_ptr=ids.syscall_ptr)";
pub fn deploy(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let syscall_handler = exec_scopes.get::<DeprecatedOsSyscallHandlerWrapper>("syscall_handler")?;
    let syscall_ptr = get_ptr_from_var_name("syscall_ptr", vm, ids_data, ap_tracking)?;

    syscall_handler.deploy(syscall_ptr);

    Ok(())
}

pub const EMIT_EVENT: &str = "syscall_handler.emit_event(segments=segments, syscall_ptr=ids.syscall_ptr)";
pub fn emit_event(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let syscall_handler = exec_scopes.get::<DeprecatedOsSyscallHandlerWrapper>("syscall_handler")?;
    let syscall_ptr = get_ptr_from_var_name("syscall_ptr", vm, ids_data, ap_tracking)?;

    syscall_handler.emit_event(syscall_ptr);

    Ok(())
}

pub const GET_BLOCK_NUMBER: &str = "syscall_handler.get_block_number(segments=segments, syscall_ptr=ids.syscall_ptr)";
pub fn get_block_number(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let syscall_handler = exec_scopes.get::<DeprecatedOsSyscallHandlerWrapper>("syscall_handler")?;
    let syscall_ptr = get_ptr_from_var_name("syscall_ptr", vm, ids_data, ap_tracking)?;

    syscall_handler.get_block_number(syscall_ptr);

    Ok(())
}

pub const GET_BLOCK_TIMESTAMP: &str =
    "syscall_handler.get_block_timestamp(segments=segments, syscall_ptr=ids.syscall_ptr)";
pub fn get_block_timestamp(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let syscall_handler = exec_scopes.get::<DeprecatedOsSyscallHandlerWrapper>("syscall_handler")?;
    let syscall_ptr = get_ptr_from_var_name("syscall_ptr", vm, ids_data, ap_tracking)?;

    syscall_handler.get_block_timestamp(syscall_ptr);

    Ok(())
}

pub const GET_CALLER_ADDRESS: &str =
    "syscall_handler.get_caller_address(segments=segments, syscall_ptr=ids.syscall_ptr)";
pub fn get_caller_address(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let syscall_handler = exec_scopes.get::<DeprecatedOsSyscallHandlerWrapper>("syscall_handler")?;
    let syscall_ptr = get_ptr_from_var_name("syscall_ptr", vm, ids_data, ap_tracking)?;

    syscall_handler.get_caller_address(syscall_ptr);

    Ok(())
}

pub const GET_CONTRACT_ADDRESS: &str =
    "syscall_handler.get_contract_address(segments=segments, syscall_ptr=ids.syscall_ptr)";
pub fn get_contract_address(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let syscall_handler = exec_scopes.get::<DeprecatedOsSyscallHandlerWrapper>("syscall_handler")?;
    let syscall_ptr = get_ptr_from_var_name("syscall_ptr", vm, ids_data, ap_tracking)?;

    syscall_handler.get_contract_address(syscall_ptr);

    Ok(())
}

pub const GET_SEQUENCER_ADDRESS: &str =
    "syscall_handler.get_sequencer_address(segments=segments, syscall_ptr=ids.syscall_ptr)";
pub fn get_sequencer_address(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let syscall_handler = exec_scopes.get::<DeprecatedOsSyscallHandlerWrapper>("syscall_handler")?;
    let syscall_ptr = get_ptr_from_var_name("syscall_ptr", vm, ids_data, ap_tracking)?;

    syscall_handler.get_sequencer_address(syscall_ptr);

    Ok(())
}

pub const GET_TX_INFO: &str = "syscall_handler.get_tx_info(segments=segments, syscall_ptr=ids.syscall_ptr)";
pub fn get_tx_info(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let syscall_handler = exec_scopes.get::<DeprecatedOsSyscallHandlerWrapper>("syscall_handler")?;
    let syscall_ptr = get_ptr_from_var_name("syscall_ptr", vm, ids_data, ap_tracking)?;

    syscall_handler.get_tx_info(syscall_ptr);

    Ok(())
}

pub const GET_TX_SIGNATURE: &str = "syscall_handler.get_tx_signature(segments=segments, syscall_ptr=ids.syscall_ptr)";
pub fn get_tx_signature(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let syscall_handler = exec_scopes.get::<DeprecatedOsSyscallHandlerWrapper>("syscall_handler")?;
    let syscall_ptr = get_ptr_from_var_name("syscall_ptr", vm, ids_data, ap_tracking)?;

    syscall_handler.get_tx_signature(syscall_ptr);

    Ok(())
}

pub const LIBRARY: &str = "syscall_handler.library_call(segments=segments, syscall_ptr=ids.syscall_ptr)";
pub fn library_call(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let syscall_handler = exec_scopes.get::<DeprecatedOsSyscallHandlerWrapper>("syscall_handler")?;
    let syscall_ptr = get_ptr_from_var_name("syscall_ptr", vm, ids_data, ap_tracking)?;

    syscall_handler.library_call(syscall_ptr);

    Ok(())
}

pub const LIBRARY_CALL_L1_HANDLER: &str =
    "syscall_handler.library_call_l1_handler(segments=segments, syscall_ptr=ids.syscall_ptr)";
pub fn library_call_l1_handler(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let syscall_handler = exec_scopes.get::<DeprecatedOsSyscallHandlerWrapper>("syscall_handler")?;
    let syscall_ptr = get_ptr_from_var_name("syscall_ptr", vm, ids_data, ap_tracking)?;

    syscall_handler.library_call_l1_handler(syscall_ptr);

    Ok(())
}

pub const REPLACE_CLASS: &str = "syscall_handler.replace_class(segments=segments, syscall_ptr=ids.syscall_ptr)";
pub fn replace_class(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let syscall_handler = exec_scopes.get::<DeprecatedOsSyscallHandlerWrapper>("syscall_handler")?;
    let syscall_ptr = get_ptr_from_var_name("syscall_ptr", vm, ids_data, ap_tracking)?;

    syscall_handler.replace_class(syscall_ptr);

    Ok(())
}

pub const SEND_MESSAGE_TO_L1: &str =
    "syscall_handler.send_message_to_l1(segments=segments, syscall_ptr=ids.syscall_ptr)";
pub fn send_message_to_l1(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let syscall_handler = exec_scopes.get::<DeprecatedOsSyscallHandlerWrapper>("syscall_handler")?;
    let syscall_ptr = get_ptr_from_var_name("syscall_ptr", vm, ids_data, ap_tracking)?;

    syscall_handler.send_message_to_l1(syscall_ptr);

    Ok(())
}

pub const STORAGE_READ: &str = "syscall_handler.storage_read(segments=segments, syscall_ptr=ids.syscall_ptr)";
pub fn storage_read(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let syscall_handler = exec_scopes.get::<DeprecatedOsSyscallHandlerWrapper>("syscall_handler")?;
    let syscall_ptr = get_ptr_from_var_name("syscall_ptr", vm, ids_data, ap_tracking)?;

    syscall_handler.storage_read(syscall_ptr);

    Ok(())
}

pub const STORAGE_WRITE: &str = "syscall_handler.storage_write(segments=segments, syscall_ptr=ids.syscall_ptr)";
pub fn storage_write(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let syscall_handler = exec_scopes.get::<DeprecatedOsSyscallHandlerWrapper>("syscall_handler")?;
    let syscall_ptr = get_ptr_from_var_name("syscall_ptr", vm, ids_data, ap_tracking)?;

    syscall_handler.storage_write(syscall_ptr);

    Ok(())
}

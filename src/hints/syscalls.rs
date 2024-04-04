use std::collections::HashMap;

use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{
    get_integer_from_var_name, get_ptr_from_var_name, insert_value_from_var_name,
};
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::hint_processor::hint_processor_utils::felt_to_usize;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::relocatable::Relocatable;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use indoc::indoc;

use crate::cairo_types::entry_point::EntryPointReturnValues;
use crate::cairo_types::syscalls::{NewDeployResponse, NewSyscallContractResponse, SyscallContractResponse};
use crate::execution::deprecated_syscall_handler::DeprecatedOsSyscallHandlerWrapper;
use crate::execution::helper::ExecutionHelperWrapper;
use crate::execution::syscall_handler::OsSyscallHandlerWrapper;
use crate::hints::vars;

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

pub const SET_SYSCALL_PTR: &str = indoc! {r#"
	ids.os_context = segments.add()
	ids.syscall_ptr = segments.add()

	syscall_handler.set_syscall_ptr(syscall_ptr=ids.syscall_ptr)"#
};

pub fn set_syscall_ptr(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let os_context = vm.add_memory_segment();
    let syscall_ptr = vm.add_memory_segment();

    insert_value_from_var_name(vars::ids::OS_CONTEXT, os_context, vm, ids_data, ap_tracking)?;
    insert_value_from_var_name(vars::ids::SYSCALL_PTR, syscall_ptr, vm, ids_data, ap_tracking)?;

    let syscall_handler: OsSyscallHandlerWrapper = exec_scopes.get(vars::scopes::SYSCALL_HANDLER)?;
    syscall_handler.set_syscall_ptr(syscall_ptr);

    Ok(())
}

fn assert_memory_ranges_equal(
    vm: &VirtualMachine,
    expected_ptr: Relocatable,
    expected_size: usize,
    actual_ptr: Relocatable,
    actual_size: usize,
) -> Result<(), HintError> {
    let expected = vm.get_range(expected_ptr, expected_size);
    let actual = vm.get_range(actual_ptr, actual_size);

    if expected != actual {
        return Err(HintError::AssertionFailed(
            format!("Return value mismatch expected={expected:?}, actual={actual:?}.").into_boxed_str(),
        ));
    }

    Ok(())
}

pub const CHECK_SYSCALL_RESPONSE: &str = indoc! {r#"
	# Check that the actual return value matches the expected one.
	expected = memory.get_range(
	    addr=ids.call_response.retdata, size=ids.call_response.retdata_size
	)
	actual = memory.get_range(addr=ids.retdata, size=ids.retdata_size)

	assert expected == actual, f'Return value mismatch expected={expected}, actual={actual}.'"#
};

pub fn check_syscall_response(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let call_response_ptr = get_ptr_from_var_name(vars::ids::CALL_RESPONSE, vm, ids_data, ap_tracking)?;
    let call_response_retdata = vm.get_relocatable((call_response_ptr + SyscallContractResponse::retdata_offset())?)?;
    let call_response_retdata_size =
        felt_to_usize(vm.get_integer((call_response_ptr + SyscallContractResponse::retdata_size_offset())?)?.as_ref())?;

    let retdata = get_ptr_from_var_name(vars::ids::RETDATA, vm, ids_data, ap_tracking)?;
    let retdata_size =
        felt_to_usize(get_integer_from_var_name(vars::ids::RETDATA_SIZE, vm, ids_data, ap_tracking)?.as_ref())?;

    assert_memory_ranges_equal(vm, call_response_retdata, call_response_retdata_size, retdata, retdata_size)?;

    Ok(())
}

pub const CHECK_NEW_SYSCALL_RESPONSE: &str = indoc! {r#"
	# Check that the actual return value matches the expected one.
	expected = memory.get_range(
	    addr=ids.response.retdata_start,
	    size=ids.response.retdata_end - ids.response.retdata_start,
	)
	actual = memory.get_range(addr=ids.retdata, size=ids.retdata_size)

	assert expected == actual, f'Return value mismatch; expected={expected}, actual={actual}.'"#
};

pub fn check_new_syscall_response(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let response_ptr = get_ptr_from_var_name(vars::ids::RESPONSE, vm, ids_data, ap_tracking)?;
    let response_retdata_start =
        vm.get_relocatable((response_ptr + NewSyscallContractResponse::retdata_start_offset())?)?;
    let response_retdata_end =
        vm.get_relocatable((response_ptr + NewSyscallContractResponse::retdata_end_offset())?)?;
    let response_retdata_size = (response_retdata_end - response_retdata_start)?;

    let retdata = get_ptr_from_var_name(vars::ids::RETDATA, vm, ids_data, ap_tracking)?;
    let retdata_size =
        felt_to_usize(get_integer_from_var_name(vars::ids::RETDATA_SIZE, vm, ids_data, ap_tracking)?.as_ref())?;

    assert_memory_ranges_equal(vm, response_retdata_start, response_retdata_size, retdata, retdata_size)?;

    Ok(())
}

pub const CHECK_NEW_DEPLOY_RESPONSE: &str = indoc! {r#"
	# Check that the actual return value matches the expected one.
	expected = memory.get_range(
	    addr=ids.response.constructor_retdata_start,
	    size=ids.response.constructor_retdata_end - ids.response.constructor_retdata_start,
	)
	actual = memory.get_range(addr=ids.retdata, size=ids.retdata_size)
	assert expected == actual, f'Return value mismatch; expected={expected}, actual={actual}.'"#
};

pub fn check_new_deploy_response(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let response_ptr = get_ptr_from_var_name(vars::ids::RESPONSE, vm, ids_data, ap_tracking)?;
    let constructor_retdata_start =
        vm.get_relocatable((response_ptr + NewDeployResponse::constructor_retdata_start_offset())?)?;
    let constructor_retdata_end =
        vm.get_relocatable((response_ptr + NewDeployResponse::constructor_retdata_end_offset())?)?;
    let response_retdata_size = (constructor_retdata_end - constructor_retdata_start)?;

    let retdata = get_ptr_from_var_name(vars::ids::RETDATA, vm, ids_data, ap_tracking)?;
    let retdata_size =
        felt_to_usize(get_integer_from_var_name(vars::ids::RETDATA_SIZE, vm, ids_data, ap_tracking)?.as_ref())?;

    assert_memory_ranges_equal(vm, constructor_retdata_start, response_retdata_size, retdata, retdata_size)?;

    Ok(())
}

pub const VALIDATE_AND_DISCARD_SYSCALL_PTR: &str = indoc! {r#"
	syscall_handler.validate_and_discard_syscall_ptr(
	    syscall_ptr_end=ids.entry_point_return_values.syscall_ptr
	)
	execution_helper.exit_call()"#
};

pub fn validate_and_discard_syscall_ptr(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let syscall_handler: OsSyscallHandlerWrapper = exec_scopes.get(vars::scopes::SYSCALL_HANDLER)?;
    let mut execution_helper: ExecutionHelperWrapper = exec_scopes.get(vars::scopes::EXECUTION_HELPER)?;

    let entry_point_return_values =
        get_ptr_from_var_name(vars::ids::ENTRY_POINT_RETURN_VALUES, vm, ids_data, ap_tracking)?;
    let syscall_ptr =
        vm.get_relocatable((entry_point_return_values + EntryPointReturnValues::syscall_ptr_offset())?)?;

    syscall_handler.validate_and_discard_syscall_ptr(syscall_ptr)?;

    execution_helper.exit_call();

    Ok(())
}

#[cfg(test)]
mod tests {
    use blockifier::block_context::BlockContext;
    use cairo_vm::types::relocatable::Relocatable;
    use rstest::{fixture, rstest};

    use super::*;
    use crate::hints::tests::tests::block_context;
    use crate::ExecutionHelperWrapper;

    #[fixture]
    fn exec_scopes(block_context: BlockContext) -> ExecutionScopes {
        let syscall_ptr = Relocatable::from((0, 0));
        let execution_infos = vec![];
        let exec_helper = ExecutionHelperWrapper::new(execution_infos, &block_context);
        let syscall_handler = OsSyscallHandlerWrapper::new(exec_helper, syscall_ptr);

        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.insert_value(vars::scopes::SYSCALL_HANDLER, syscall_handler);

        exec_scopes
    }

    #[rstest]
    fn test_set_syscall_ptr(mut exec_scopes: ExecutionScopes) {
        let mut vm = VirtualMachine::new(false);

        let ids_data = HashMap::from([
            (vars::ids::OS_CONTEXT.to_string(), HintReference::new_simple(-2)),
            (vars::ids::SYSCALL_PTR.to_string(), HintReference::new_simple(-1)),
        ]);
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.set_fp(2);

        let ap_tracking = ApTracking::new();
        let constants = HashMap::new();

        set_syscall_ptr(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants).unwrap();

        let os_context = get_ptr_from_var_name(vars::ids::OS_CONTEXT, &vm, &ids_data, &ap_tracking).unwrap();
        let syscall_ptr = get_ptr_from_var_name(vars::ids::SYSCALL_PTR, &vm, &ids_data, &ap_tracking).unwrap();

        assert_eq!(os_context, Relocatable::from((2, 0)));
        assert_eq!(syscall_ptr, Relocatable::from((3, 0)));

        let syscall_handler: OsSyscallHandlerWrapper = exec_scopes.get(vars::scopes::SYSCALL_HANDLER).unwrap();
        assert_eq!(syscall_handler.syscall_ptr(), Some(syscall_ptr));
    }
}

pub mod block_context;
pub mod hints_raw;

use std::collections::HashMap;
use std::rc::Rc;

use cairo_vm::felt::Felt252;
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
    BuiltinHintProcessor, HintFunc,
};
use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::*;
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;

use crate::io::StarknetOsInput;

pub fn sn_hint_processor() -> BuiltinHintProcessor {
    let mut hint_processor = BuiltinHintProcessor::new_empty();

    let sn_os_input = HintFunc(Box::new(starknet_os_input));
    hint_processor.add_hint(String::from(hints_raw::STARKNET_OS_INPUT), Rc::new(sn_os_input));

    let load_class_facts = HintFunc(Box::new(block_context::load_class_facts));
    hint_processor.add_hint(String::from(hints_raw::LOAD_CLASS_FACTS), Rc::new(load_class_facts));

    let load_deprecated_class_facts = HintFunc(Box::new(block_context::load_deprecated_class_facts));
    hint_processor.add_hint(String::from(hints_raw::LOAD_DEPRECATED_CLASS_FACTS), Rc::new(load_deprecated_class_facts));

    let load_deprecated_class_inner = HintFunc(Box::new(block_context::load_deprecated_inner));
    hint_processor.add_hint(String::from(hints_raw::LOAD_DEPRECATED_CLASS_INNER), Rc::new(load_deprecated_class_inner));

    let check_deprecated_class_hash_hint = HintFunc(Box::new(check_deprecated_class_hash));
    hint_processor
        .add_hint(String::from(hints_raw::CHECK_DEPRECATED_CLASS_HASH), Rc::new(check_deprecated_class_hash_hint));

    hint_processor
}

// Implements hint:
//
// from starkware.starknet.core.os.os_input import StarknetOsInput
//
// os_input = StarknetOsInput.load(data=program_input)
//
// ids.initial_carried_outputs.messages_to_l1 = segments.add_temp_segment()
// ids.initial_carried_outputs.messages_to_l2 = segments.add_temp_segment()
pub fn starknet_os_input(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let os_input = Box::new(StarknetOsInput::load("tests/common/os_input.json"));
    exec_scopes.assign_or_update_variable("os_input", os_input);

    let initial_carried_outputs_ptr = get_ptr_from_var_name("initial_carried_outputs", vm, ids_data, ap_tracking)?;

    let messages_to_l1 = initial_carried_outputs_ptr;
    let temp_segment = vm.add_temporary_segment();
    vm.insert_value(messages_to_l1, temp_segment)?;

    let messages_to_l2 = (initial_carried_outputs_ptr + 1_i32)?;
    let temp_segment = vm.add_temporary_segment();
    vm.insert_value(messages_to_l2, temp_segment)?;

    Ok(())
}

// Implements hint:
//
// from starkware.python.utils import from_bytes
//
// computed_hash = ids.compiled_class_fact.hash
// expected_hash = compiled_class_hash
// assert computed_hash == expected_hash, (
// "Computed compiled_class_hash is inconsistent with the hash in the os_input. "
// f"Computed hash = {computed_hash}, Expected hash = {expected_hash}.")
//
// vm_load_program(compiled_class.program, ids.compiled_class.bytecode_ptr)
pub fn check_deprecated_class_hash(
    _vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    // TODO: decide if we really need to check this deprecated hash moving forward
    // TODO: check w/ LC for `vm_load_program` impl

    Ok(())
}

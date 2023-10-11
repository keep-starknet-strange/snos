use std::collections::HashMap;

use cairo_vm::felt::Felt252;
use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::get_ptr_from_var_name;
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
mod hints_raw;

use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::vm::{errors::hint_errors::HintError, vm_core::VirtualMachine};
use std::rc::Rc;

use crate::io::StarknetOsInput;

use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
    BuiltinHintProcessor, HintFunc,
};

pub fn sn_hint_processor() -> BuiltinHintProcessor {
    let mut hint_processor = BuiltinHintProcessor::new_empty();

    let sn_input = HintFunc(Box::new(starknet_os_input));

    hint_processor.add_hint(String::from(hints_raw::SN_INPUT_RAW), Rc::new(sn_input));

    hint_processor
}

/*
Implements hint:
%{ from starkware.starknet.core.os.os_input import StarknetOsInput

os_input = StarknetOsInput.load(data=program_input)

ids.initial_carried_outputs.messages_to_l1 = segments.add_temp_segment()
ids.initial_carried_outputs.messages_to_l2 = segments.add_temp_segment()  %}
*/
pub fn starknet_os_input(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    println!("Running hint {:?} {:?}", ids_data, _exec_scopes);

    // Deserialize the program_input
    let _os_input = StarknetOsInput::load("tests/common/os_input.json");

    let initial_carried_outputs_ptr =
        get_ptr_from_var_name("initial_carried_outputs", vm, ids_data, ap_tracking)?;
    // We now have a pointer to a struct with the fields (messages_to_l1, messages_to_l2)
    // initial_carried_outputs_ptr + 1 will be equal to initial_carried_outputs.messages_to_l1
    // initial_carried_outputs_ptr + 2 will be equal to initial_carried_outputs.messages_to_l2
    let messages_to_l1 = (initial_carried_outputs_ptr + 1_i32)?;
    let messages_to_l2 = (initial_carried_outputs_ptr + 2_i32)?;

    let temp_segment = vm.add_temporary_segment();
    vm.insert_value(messages_to_l1, temp_segment)?;
    let temp_segment = vm.add_temporary_segment();
    vm.insert_value(messages_to_l2, temp_segment)?;

    Ok(())
}

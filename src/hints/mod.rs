use std::any::Any;
use std::collections::HashMap;

use cairo_vm::felt::Felt252;
use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{
    get_ptr_from_var_name, insert_value_from_var_name,
};
use cairo_vm::hint_processor::hint_processor_definition::HintReference;

use crate::io::StarknetOsInput;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::relocatable::MaybeRelocatable;
use cairo_vm::vm::{errors::hint_errors::HintError, vm_core::VirtualMachine};

use std::rc::Rc;

use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
    BuiltinHintProcessor, HintFunc,
};

pub mod hints_raw;

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
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    println!("Running hint {:?} {:?}", ids_data, exec_scopes);

    // Deserialize the program_input
    let os_input = Box::new(StarknetOsInput::load("tests/common/os_input.json"));
    exec_scopes.assign_or_update_variable("os_input", os_input);

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

/*
Implements hint:
 %{
       ids.compiled_class_facts = segments.add()
       ids.n_compiled_class_facts = len(os_input.compiled_classes)
       vm_enter_scope({
           'compiled_class_facts': iter(os_input.compiled_classes.items()),
       })
  %}
*/
pub fn load_compiled_class_facts(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    //  ids.compiled_class_facts = segments.add()
    insert_value_from_var_name(
        "compiled_class_facts",
        vm.add_memory_segment(),
        vm,
        ids_data,
        ap_tracking,
    )?;
    // Access the value of os_input which was loaded in a previous hint like that
    // %{ os_input = ... %}
    // Can't directly get os_input.compiled_classes so we need to get the whole os_input
    let compiled_class_facts = exec_scopes
        .get_ref::<StarknetOsInput>("os_input")?
        .compiled_classes()
        .clone();
    // ids.n_compiled_class_facts = len(os_input.compiled_classes)
    insert_value_from_var_name(
        "n_compiled_class_facts",
        MaybeRelocatable::Int(Felt252::new(compiled_class_facts.len())),
        vm,
        ids_data,
        ap_tracking,
    )?;
    // vm_enter_scope({
    //     'compiled_class_facts': iter(os_input.compiled_classes.items()),
    // })
    let boxed_compiled_classes: Box<dyn Any> = Box::new(compiled_class_facts.into_iter());
    exec_scopes.enter_scope(HashMap::from_iter(vec![(
        "compiled_class_facts".to_string(),
        boxed_compiled_classes,
    )]));
    Ok(())
}

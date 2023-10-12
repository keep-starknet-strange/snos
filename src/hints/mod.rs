use std::collections::HashMap;

use cairo_vm::felt::Felt252;
use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{
    get_ptr_from_var_name, insert_value_from_var_name,
};
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
mod hints_raw;

use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::vm::{errors::hint_errors::HintError, vm_core::VirtualMachine};
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedContractClass;
use std::any::Any;
use std::collections::hash_map::IntoIter;
use std::rc::Rc;

use crate::io::StarknetOsInput;

use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
    BuiltinHintProcessor, HintFunc,
};

pub fn sn_hint_processor() -> BuiltinHintProcessor {
    let mut hint_processor = BuiltinHintProcessor::new_empty();

    let sn_input = HintFunc(Box::new(starknet_os_input));
    hint_processor.add_hint(String::from(hints_raw::SN_INPUT_RAW), Rc::new(sn_input));

    let load_class_facts = HintFunc(Box::new(load_compiled_class_facts));
    hint_processor.add_hint(
        String::from(hints_raw::LOAD_COMPILED_CLASS_FACTS),
        Rc::new(load_class_facts),
    );

    let load_deprecated_class_facts = HintFunc(Box::new(load_deprecated_compiled_class_facts));
    hint_processor.add_hint(
        String::from(hints_raw::LOAD_DEPRECATED_CLASS_FACTS),
        Rc::new(load_deprecated_class_facts),
    );

    let load_deprecated_class_inner = HintFunc(Box::new(load_deprecated_compiled_inner));
    hint_processor.add_hint(
        String::from(hints_raw::LOAD_DEPRECATED_CLASS_INNER),
        Rc::new(load_deprecated_class_inner),
    );

    hint_processor
}

/*
Implements hint:

from starkware.starknet.core.os.os_input import StarknetOsInput

os_input = StarknetOsInput.load(data=program_input)

ids.initial_carried_outputs.messages_to_l1 = segments.add_temp_segment()
ids.initial_carried_outputs.messages_to_l2 = segments.add_temp_segment()
*/
pub fn starknet_os_input(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    // println!("Running hint {:?} {:?}", ids_data, exec_scopes);

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

ids.compiled_class_facts = segments.add()
ids.n_compiled_class_facts = len(os_input.compiled_classes)
vm_enter_scope({
    'compiled_class_facts': iter(os_input.compiled_classes.items()),
})
*/
pub fn load_compiled_class_facts(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let os_input = exec_scopes.get::<StarknetOsInput>("os_input")?;
    let compiled_class_facts_ptr = vm.add_memory_segment();
    insert_value_from_var_name(
        "compiled_class_facts",
        compiled_class_facts_ptr,
        vm,
        ids_data,
        ap_tracking,
    )?;

    insert_value_from_var_name(
        "n_compiled_class_facts",
        os_input.compiled_classes.len(),
        vm,
        ids_data,
        ap_tracking,
    )?;

    let scoped_classes: Box<dyn Any> = Box::new(os_input.compiled_classes.into_iter());
    exec_scopes.enter_scope(HashMap::from([(
        String::from("compiled_class_facts"),
        scoped_classes,
    )]));

    Ok(())
}

/*
Implements hint:

# Creates a set of deprecated class hashes to distinguish calls to deprecated entry points.
__deprecated_class_hashes=set(os_input.deprecated_compiled_classes.keys())
ids.compiled_class_facts = segments.add()
ids.n_compiled_class_facts = len(os_input.deprecated_compiled_classes)
vm_enter_scope({
    'compiled_class_facts': iter(os_input.deprecated_compiled_classes.items()),
})
*/
pub fn load_deprecated_compiled_class_facts(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let os_input = exec_scopes.get::<StarknetOsInput>("os_input")?;
    let compiled_class_facts_ptr = vm.add_memory_segment();
    insert_value_from_var_name(
        "compiled_class_facts",
        compiled_class_facts_ptr,
        vm,
        ids_data,
        ap_tracking,
    )?;

    insert_value_from_var_name(
        "n_compiled_class_facts",
        os_input.deprecated_compiled_classes.len(),
        vm,
        ids_data,
        ap_tracking,
    )?;
    let scoped_classes: Box<dyn Any> = Box::new(os_input.deprecated_compiled_classes.into_iter());
    exec_scopes.enter_scope(HashMap::from([(
        String::from("compiled_class_facts"),
        scoped_classes,
    )]));

    Ok(())
}

/*
Implements hint:

from starkware.starknet.core.os.contract_class.deprecated_class_hash import (
    get_deprecated_contract_class_struct,
)

compiled_class_hash, compiled_class = next(compiled_class_facts)

cairo_contract = get_deprecated_contract_class_struct(
    identifiers=ids._context.identifiers, contract_class=compiled_class)
ids.compiled_class = segments.gen_arg(cairo_contract)
*/
pub fn load_deprecated_compiled_inner(
    _vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let deprecated_class_iter = exec_scopes
        .get_mut_ref::<IntoIter<Felt252, DeprecatedContractClass>>("compiled_class_facts")
        .unwrap();

    let (class_hash, _class) = deprecated_class_iter.next().unwrap();
    println!("Deprecated Class Hash: {:?}", class_hash);

    // TODO: insert parsed deprecated contract

    Ok(())
}

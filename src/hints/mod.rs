pub mod hints_raw;

use std::any::Any;
use std::collections::hash_map::IntoIter;
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
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedContractClass;

use crate::io::classes::write_deprecated_class;
use crate::io::StarknetOsInput;

pub fn sn_hint_processor() -> BuiltinHintProcessor {
    let mut hint_processor = BuiltinHintProcessor::new_empty();

    let sn_os_input = HintFunc(Box::new(starknet_os_input));
    hint_processor.add_hint(String::from(hints_raw::STARKNET_OS_INPUT), Rc::new(sn_os_input));

    let load_class_facts = HintFunc(Box::new(load_class_facts));
    hint_processor.add_hint(String::from(hints_raw::LOAD_CLASS_FACTS), Rc::new(load_class_facts));

    let load_deprecated_class_facts = HintFunc(Box::new(load_deprecated_class_facts));
    hint_processor.add_hint(String::from(hints_raw::LOAD_DEPRECATED_CLASS_FACTS), Rc::new(load_deprecated_class_facts));

    let load_deprecated_class_inner = HintFunc(Box::new(load_deprecated_inner));
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
// ids.compiled_class_facts = segments.add()
// ids.n_compiled_class_facts = len(os_input.compiled_classes)
// vm_enter_scope({
// 'compiled_class_facts': iter(os_input.compiled_classes.items()),
// })
pub fn load_class_facts(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let os_input = exec_scopes.get::<StarknetOsInput>("os_input")?;
    let compiled_class_facts_ptr = vm.add_memory_segment();
    insert_value_from_var_name("compiled_class_facts", compiled_class_facts_ptr, vm, ids_data, ap_tracking)?;

    insert_value_from_var_name("n_compiled_class_facts", os_input.compiled_classes.len(), vm, ids_data, ap_tracking)?;

    let scoped_classes: Box<dyn Any> = Box::new(os_input.compiled_classes.into_iter());
    exec_scopes.enter_scope(HashMap::from([(String::from("compiled_class_facts"), scoped_classes)]));

    Ok(())
}

// Implements hint:
//
// # Creates a set of deprecated class hashes to distinguish calls to deprecated entry points.
// __deprecated_class_hashes=set(os_input.deprecated_compiled_classes.keys())
// ids.compiled_class_facts = segments.add()
// ids.n_compiled_class_facts = len(os_input.deprecated_compiled_classes)
// vm_enter_scope({
// 'compiled_class_facts': iter(os_input.deprecated_compiled_classes.items()),
// })
pub fn load_deprecated_class_facts(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let os_input = exec_scopes.get::<StarknetOsInput>("os_input")?;
    let compiled_class_facts_ptr = vm.add_memory_segment();
    insert_value_from_var_name("compiled_class_facts", compiled_class_facts_ptr, vm, ids_data, ap_tracking)?;

    insert_value_from_var_name(
        "n_compiled_class_facts",
        os_input.deprecated_compiled_classes.len(),
        vm,
        ids_data,
        ap_tracking,
    )?;
    let scoped_classes: Box<dyn Any> = Box::new(os_input.deprecated_compiled_classes.into_iter());
    exec_scopes.enter_scope(HashMap::from([(String::from("compiled_class_facts"), scoped_classes)]));

    Ok(())
}

// Implements hint:
//
// from starkware.starknet.core.os.contract_class.deprecated_class_hash import (
// get_deprecated_contract_class_struct,
// )
//
// compiled_class_hash, compiled_class = next(compiled_class_facts)
//
// cairo_contract = get_deprecated_contract_class_struct(
// identifiers=ids._context.identifiers, contract_class=compiled_class)
// ids.compiled_class = segments.gen_arg(cairo_contract)
pub fn load_deprecated_inner(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let deprecated_class_iter =
        exec_scopes.get_mut_ref::<IntoIter<Felt252, DeprecatedContractClass>>("compiled_class_facts").unwrap();

    let (class_hash, deprecated_class) = deprecated_class_iter.next().unwrap();

    exec_scopes.insert_value("compiled_class_hash", class_hash);

    let dep_class_base = vm.add_memory_segment();
    write_deprecated_class(vm, dep_class_base, deprecated_class)?;

    insert_value_from_var_name("compiled_class", dep_class_base, vm, ids_data, ap_tracking)?;

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

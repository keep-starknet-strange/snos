use std::any::Any;
use std::collections::hash_map::IntoIter;
use std::collections::HashMap;

use cairo_felt::Felt252;
use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{insert_value_from_var_name, insert_value_into_ap};
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::relocatable::MaybeRelocatable;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedContractClass;

use crate::io::classes::write_deprecated_class;
use crate::io::StarknetOsInput;
use crate::utils::felt_api2vm;

/// Implements hint:
///
/// ids.compiled_class_facts = segments.add()
/// ids.n_compiled_class_facts = len(os_input.compiled_classes)
/// vm_enter_scope({
/// 'compiled_class_facts': iter(os_input.compiled_classes.items()),
/// })
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

/// Implements hint:
///
/// # Creates a set of deprecated class hashes to distinguish calls to deprecated entry points.
/// __deprecated_class_hashes=set(os_input.deprecated_compiled_classes.keys())
/// ids.compiled_class_facts = segments.add()
/// ids.n_compiled_class_facts = len(os_input.deprecated_compiled_classes)
/// vm_enter_scope({
/// 'compiled_class_facts': iter(os_input.deprecated_compiled_classes.items()),
/// })
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

/// Implements hint:
///
/// from starkware.starknet.core.os.contract_class.deprecated_class_hash import (
/// get_deprecated_contract_class_struct,
/// )
///
/// compiled_class_hash, compiled_class = next(compiled_class_facts)
///
/// cairo_contract = get_deprecated_contract_class_struct(
/// identifiers=ids._context.identifiers, contract_class=compiled_class)
/// ids.compiled_class = segments.gen_arg(cairo_contract)
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

/// Implements hint:
///
/// memory[ap] = to_felt_or_relocatable(deprecated_syscall_handler.block_info.block_number)
pub fn deprecated_block_number(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    // TODO: replace w/ block context from syscall handler
    insert_value_into_ap(vm, Felt252::from(1))?;

    Ok(())
}

/// Implements hint:
///
/// memory[ap] = to_felt_or_relocatable(deprecated_syscall_handler.block_info.block_timestamp)
pub fn deprecated_block_timestamp(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    // TODO: replace w/ block context from syscall handler
    insert_value_into_ap(vm, Felt252::from(1000))?;

    Ok(())
}

/// Implements hint:
///
/// memory[ap] = to_felt_or_relocatable(os_input.general_config.chain_id.value)
pub fn chain_id(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let os_input = exec_scopes.get::<StarknetOsInput>("os_input")?;
    let chain_id =
        Felt252::from(u128::from_str_radix(&os_input.general_config.starknet_os_config.chain_id.0, 16).unwrap());
    insert_value_into_ap(vm, chain_id)?;

    Ok(())
}

/// Implements hint:
///
/// memory[ap] = to_felt_or_relocatable(os_input.general_config.fee_token_address)
pub fn fee_token_address(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let os_input = exec_scopes.get::<StarknetOsInput>("os_input")?;
    insert_value_into_ap(vm, felt_api2vm(*os_input.general_config.starknet_os_config.fee_token_address.0.key()))?;

    Ok(())
}

/// Implements hint:
///
/// os_input.general_config.sequencer_address
pub fn sequencer_address(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let os_input = exec_scopes.get::<StarknetOsInput>("os_input")?;
    insert_value_into_ap(
        vm,
        MaybeRelocatable::Int(Felt252::from_bytes_be(os_input.general_config.sequencer_address.0.key().bytes())),
    )
}

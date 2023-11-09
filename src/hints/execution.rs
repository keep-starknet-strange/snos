use std::collections::{HashMap, HashSet};

use cairo_felt::Felt252;
use cairo_vm::hint_processor::builtin_hint_processor::dict_manager::Dictionary;
use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{
    get_integer_from_var_name, get_ptr_from_var_name, get_relocatable_from_var_name, insert_value_from_var_name,
    insert_value_into_ap,
};
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::relocatable::MaybeRelocatable;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;

use crate::io::execution_helper::OsExecutionHelper;
use crate::state::storage::TrieStorage;
use crate::state::trie::PedersenHash;

/// Implements hint:
///
/// execution_helper.start_tx(
///     tx_info_ptr=ids.constructor_execution_context.deprecated_tx_info.address_
/// )
pub fn start_execute_deploy_transaction(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let execution_helper =
        exec_scopes.get_mut_ref::<OsExecutionHelper<PedersenHash, TrieStorage>>("execution_helper").unwrap();
    let constructor_execution_context =
        get_relocatable_from_var_name("constructor_execution_context", vm, ids_data, ap_tracking)?;
    let deprecated_tx_info_ptr = (constructor_execution_context + 5usize).unwrap();

    execution_helper.start_tx(Some(deprecated_tx_info_ptr));
    Ok(())
}

/// Implements hint:
///
/// # Fetch a state_entry in this hint and validate it in the update at the end
/// # of this function.
/// ids.state_entry = __dict_manager.get_dict(ids.contract_state_changes)[ids.contract_address]
pub fn get_state_entry(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let key = get_integer_from_var_name("contract_address", vm, ids_data, ap_tracking)?;
    let dict_ptr = get_ptr_from_var_name("contract_state_changes", vm, ids_data, ap_tracking)?;
    let val = match exec_scopes.get_dict_manager()?.borrow().get_tracker(dict_ptr)?.data.clone() {
        Dictionary::SimpleDictionary(dict) => dict
            .get(&MaybeRelocatable::Int(key.into_owned()))
            .expect("State changes dictionnary shouldn't be None")
            .clone(),
        Dictionary::DefaultDictionary { dict: _d, default_value: _v } => {
            panic!("State changes dict shouldn't be a default dict")
        }
    };
    insert_value_from_var_name("state_entry", val, vm, ids_data, ap_tracking)?;
    Ok(())
}

/// Implements hint:
///
/// is_deprecated = 1 if ids.execution_context.class_hash in __deprecated_class_hashes else 0
pub fn check_is_deprecated(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let execution_context = get_ptr_from_var_name("execution_context", vm, ids_data, ap_tracking)?;
    let class_hash = vm.get_integer((execution_context + 1usize)?).map_err(|_| {
        HintError::IdentifierHasNoMember(Box::new(("execution_context".to_string(), "class_hash".to_string())))
    })?;
    let is_deprecated_class =
        exec_scopes.get_ref::<HashSet<Felt252>>("__deprecated_class_hashes")?.contains(&class_hash);
    exec_scopes.insert_value("is_deprecated", if is_deprecated_class { 1u8 } else { 0u8 });
    Ok(())
}

/// Implements hint:
///
/// memory[ap] = to_felt_or_relocatable(is_deprecated)
pub fn is_deprecated(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    insert_value_into_ap(vm, Felt252::from(exec_scopes.get::<u8>("is_deprecated")?))?;
    Ok(())
}

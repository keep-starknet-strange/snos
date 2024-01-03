use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::ops::AddAssign;
use std::vec::IntoIter;

use cairo_vm::felt::Felt252;
use cairo_vm::hint_processor::builtin_hint_processor::dict_manager::Dictionary;
use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{
    get_integer_from_var_name, get_ptr_from_var_name, insert_value_from_var_name, insert_value_into_ap,
};
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::relocatable::MaybeRelocatable;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use indoc::indoc;
use num_traits::{One, Zero};

use crate::io::input::StarknetOsInput;
use crate::io::InternalTransaction;

pub const LOAD_NEXT_TX: &str = indoc! {r#"
    tx = next(transactions)
    tx_type_bytes = tx.tx_type.name.encode("ascii")
    ids.tx_type = int.from_bytes(tx_type_bytes, "big")"#
};
pub fn load_next_tx(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let mut transactions = exec_scopes.get::<IntoIter<InternalTransaction>>("transactions")?;
    // Safe to unwrap because the remaining number of txs is checked in the cairo code.
    let tx = transactions.next().unwrap();
    exec_scopes.insert_value("transactions", transactions);
    exec_scopes.insert_value("tx", tx.clone());
    insert_value_from_var_name("tx_type", Felt252::from_bytes_be(tx.r#type.as_bytes()), vm, ids_data, ap_tracking)
}

pub const PREPARE_CONSTRUCTOR_EXECUTION: &str = indoc! {r#"
    ids.contract_address_salt = tx.contract_address_salt
    ids.class_hash = tx.class_hash
    ids.constructor_calldata_size = len(tx.constructor_calldata)
    ids.constructor_calldata = segments.gen_arg(arg=tx.constructor_calldata)"#
};
pub fn prepare_constructor_execution(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let tx = exec_scopes.get::<InternalTransaction>("tx")?;
    insert_value_from_var_name(
        "contract_address_salt",
        tx.contract_address_salt.expect("`contract_address_salt` must be present"),
        vm,
        ids_data,
        ap_tracking,
    )?;
    insert_value_from_var_name(
        "class_hash",
        // using `contract_hash` instead of `class_hash` as the that's how the
        // input.json is structured
        tx.contract_hash.expect("`contract_hash` must be present"),
        vm,
        ids_data,
        ap_tracking,
    )?;

    let constructor_calldata_size = match &tx.constructor_calldata {
        None => 0,
        Some(calldata) => calldata.len(),
    };
    insert_value_from_var_name("constructor_calldata_size", constructor_calldata_size, vm, ids_data, ap_tracking)?;

    let constructor_calldata = tx.constructor_calldata.unwrap_or_default().iter().map(|felt| felt.into()).collect();
    let constructor_calldata_base = vm.add_memory_segment();
    vm.load_data(constructor_calldata_base, &constructor_calldata)?;
    insert_value_from_var_name("constructor_calldata", constructor_calldata_base, vm, ids_data, ap_tracking)
}

pub const TRANSACTION_VERSION: &str = "memory[ap] = to_felt_or_relocatable(tx.version)";
pub fn transaction_version(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let tx = exec_scopes.get::<InternalTransaction>("tx")?;
    insert_value_into_ap(vm, tx.version.expect("Transaction version should be set"))
}

pub const ASSERT_TRANSACTION_HASH: &str = indoc! {r#"
    assert ids.transaction_hash == tx.hash_value, (
    "Computed transaction_hash is inconsistent with the hash in the transaction. "
    f"Computed hash = {ids.transaction_hash}, Expected hash = {tx.hash_value}.")"#
};
pub fn assert_transaction_hash(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let tx = exec_scopes.get::<InternalTransaction>("tx")?;
    let transaction_hash = get_integer_from_var_name("transaction_hash", vm, ids_data, ap_tracking)?.into_owned();

    assert_eq!(
        tx.hash_value, transaction_hash,
        "Computed transaction_hash is inconsistent with the hash in the transaction. Computed hash = {}, Expected \
         hash = {}.",
        transaction_hash, tx.hash_value
    );
    Ok(())
}

pub const ENTER_SCOPE_SYSCALL_HANDLER: &str = "vm_enter_scope({'syscall_handler': deprecated_syscall_handler})";
pub fn enter_scope_syscall_handler(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let _jump_dest = get_ptr_from_var_name("contract_entry_point", vm, ids_data, ap_tracking)?;
    Ok(())
}

pub const GET_STATE_ENTRY: &str = indoc! {r##"
    # Fetch a state_entry in this hint and validate it in the update at the end
    # of this function.
    ids.state_entry = __dict_manager.get_dict(ids.contract_state_changes)[ids.contract_address]"##
};
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

pub const CHECK_IS_DEPRECATED: &str =
    "is_deprecated = 1 if ids.execution_context.class_hash in __deprecated_class_hashes else 0";
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

pub const IS_DEPRECATED: &str = "memory[ap] = to_felt_or_relocatable(is_deprecated)";
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

pub const OS_CONTEXT_SEGMENTS: &str = "ids.os_context = segments.add()\nids.syscall_ptr = segments.add()";
pub fn os_context_segments(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    insert_value_from_var_name("os_context", vm.add_memory_segment(), vm, ids_data, ap_tracking)?;
    insert_value_from_var_name("syscall_ptr", vm.add_memory_segment(), vm, ids_data, ap_tracking)?;
    Ok(())
}

pub const SELECTED_BUILTINS: &str = "vm_enter_scope({'n_selected_builtins': ids.n_selected_builtins})";
pub fn selected_builtins(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let n_selected_builtins: Box<dyn Any> =
        Box::new(get_integer_from_var_name("n_selected_builtins", vm, ids_data, ap_tracking)?.into_owned());
    exec_scopes.enter_scope(HashMap::from_iter([(String::from("n_selected_builtins"), n_selected_builtins)]));
    Ok(())
}

pub const SELECT_BUILTIN: &str = indoc! {r##"
    # A builtin should be selected iff its encoding appears in the selected encodings list
    # and the list wasn't exhausted.
    # Note that testing inclusion by a single comparison is possible since the lists are sorted.
    ids.select_builtin = int(
      n_selected_builtins > 0 and memory[ids.selected_encodings] == memory[ids.all_encodings])
    if ids.select_builtin:
      n_selected_builtins = n_selected_builtins - 1"##
};
pub fn select_builtin(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let selected_encodings = get_ptr_from_var_name("selected_encodings", vm, ids_data, ap_tracking)?;
    let all_encodings = get_ptr_from_var_name("all_encodings", vm, ids_data, ap_tracking)?;
    let n_selected_builtins = exec_scopes.get_mut_ref::<Felt252>("n_selected_builtins")?;
    let select_builtin = n_selected_builtins > &mut Felt252::zero()
        && vm.get_maybe(&selected_encodings).unwrap() == vm.get_maybe(&all_encodings).unwrap();
    insert_value_from_var_name(
        "select_builtin",
        if select_builtin { Felt252::one() } else { Felt252::zero() },
        vm,
        ids_data,
        ap_tracking,
    )?;
    if select_builtin {
        n_selected_builtins.add_assign(-Felt252::one());
    }

    Ok(())
}

pub const ENTER_SYSCALL_SCOPES: &str = indoc! {r#"
    vm_enter_scope({
        '__deprecated_class_hashes': __deprecated_class_hashes,
        'transactions': iter(os_input.transactions),
        'execution_helper': execution_helper,
        'deprecated_syscall_handler': deprecated_syscall_handler,
        'syscall_handler': syscall_handler,
         '__dict_manager': __dict_manager,
    })"#
};
pub fn enter_syscall_scopes(
    _vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let os_input = exec_scopes.get::<StarknetOsInput>("os_input").unwrap();
    let transactions: Box<dyn Any> = Box::new(os_input.transactions.into_iter());
    let dict_manager = Box::new(exec_scopes.get_dict_manager()?);
    let deprecated_class_hashes = Box::new(exec_scopes.get::<HashSet<Felt252>>("__deprecated_class_hashes")?);

    exec_scopes.enter_scope(HashMap::from_iter([
        (String::from("transactions"), transactions),
        (String::from("dict_manager"), dict_manager),
        (String::from("__deprecated_class_hashes"), deprecated_class_hashes),
    ]));
    Ok(())
}

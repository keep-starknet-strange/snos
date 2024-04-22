use std::any::Any;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::vec::IntoIter;

use cairo_vm::hint_processor::builtin_hint_processor::dict_manager::Dictionary;
use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{
    get_integer_from_var_name, get_ptr_from_var_name, get_relocatable_from_var_name, insert_value_from_var_name,
    insert_value_into_ap,
};
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::hint_processor::hint_processor_utils::felt_to_usize;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::errors::math_errors::MathError;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::{any_box, Felt252};
use indoc::indoc;
use num_bigint::BigUint;
use num_traits::ToPrimitive;

use crate::cairo_types::structs::{CallContractResponse, EntryPointReturnValues, ExecutionContext};
use crate::cairo_types::syscalls::{
    NewDeployResponse, NewStorageRead, NewStorageWriteRequest, NewSyscallContractResponse, StorageRead,
    StorageReadRequest, StorageWrite, SyscallContractResponse, TxInfo,
};
use crate::execution::deprecated_syscall_handler::DeprecatedOsSyscallHandlerWrapper;
use crate::execution::helper::ExecutionHelperWrapper;
use crate::execution::syscall_handler::OsSyscallHandlerWrapper;
use crate::execution::syscall_utils::SyscallSelector;
use crate::hints::types::{PatriciaSkipValidationRunner, Preimage};
use crate::hints::vars;
use crate::hints::vars::ids::{
    ENTRY_POINT_RETURN_VALUES, EXECUTION_CONTEXT, INITIAL_GAS, SELECTOR, SIGNATURE_LEN, SIGNATURE_START,
};
use crate::hints::vars::scopes::{EXECUTION_HELPER, SYSCALL_HANDLER};
use crate::io::input::StarknetOsInput;
use crate::io::InternalTransaction;
use crate::starknet::starknet_storage::StorageLeaf;
use crate::starkware_utils::commitment_tree::base_types::DescentMap;
use crate::starkware_utils::commitment_tree::update_tree::{DecodeNodeCase, TreeUpdate, UpdateTree};
use crate::utils::get_constant;

pub const LOAD_NEXT_TX: &str = indoc! {r#"
        tx = next(transactions)
        assert tx.tx_type.name in ('INVOKE_FUNCTION', 'L1_HANDLER', 'DEPLOY_ACCOUNT', 'DECLARE'), (
            f"Unexpected transaction type: {tx.type.name}."
        )

        tx_type_bytes = tx.tx_type.name.encode("ascii")
        ids.tx_type = int.from_bytes(tx_type_bytes, "big")
        execution_helper.os_logger.enter_tx(
            tx=tx,
            n_steps=current_step,
            builtin_ptrs=ids.builtin_ptrs,
            range_check_ptr=ids.range_check_ptr,
        )

        # Prepare a short callable to save code duplication.
        exit_tx = lambda: execution_helper.os_logger.exit_tx(
            n_steps=current_step,
            builtin_ptrs=ids.builtin_ptrs,
            range_check_ptr=ids.range_check_ptr,
        )"#
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
    println!("executing {} on: {}", tx.r#type, tx.sender_address.unwrap());
    exec_scopes.insert_value("transactions", transactions);
    exec_scopes.insert_value("tx", tx.clone());
    insert_value_from_var_name("tx_type", Felt252::from_bytes_be_slice(tx.r#type.as_bytes()), vm, ids_data, ap_tracking)
    // TODO: add logger
}

pub const EXIT_TX: &str = "exit_tx()";
pub fn exit_tx(
    _vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    // TODO: add logger
    Ok(())
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
    let transaction_hash = get_integer_from_var_name("transaction_hash", vm, ids_data, ap_tracking)?;

    assert_eq!(
        tx.hash_value,
        transaction_hash,
        "Computed transaction_hash is inconsistent with the hash in the transaction. Computed hash = {}, Expected \
         hash = {}.",
        transaction_hash.to_hex_string(),
        tx.hash_value.to_hex_string()
    );
    Ok(())
}

pub const ENTER_SCOPE_DEPRECATED_SYSCALL_HANDLER: &str =
    "vm_enter_scope({'syscall_handler': deprecated_syscall_handler})";
pub fn enter_scope_deprecated_syscall_handler(
    _vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let dep_sys = exec_scopes.get::<DeprecatedOsSyscallHandlerWrapper>("deprecated_syscall_handler")?;
    let deprecated_syscall_handler: Box<dyn Any> = Box::new(dep_sys);
    exec_scopes.enter_scope(HashMap::from_iter([(String::from("syscall_handler"), deprecated_syscall_handler)]));
    Ok(())
}

pub const ENTER_SCOPE_SYSCALL_HANDLER: &str = "vm_enter_scope({'syscall_handler': syscall_handler})";
pub fn enter_scope_syscall_handler(
    _vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let sys = exec_scopes.get::<OsSyscallHandlerWrapper>("syscall_handler")?;
    let syscall_handler: Box<dyn Any> = Box::new(sys);
    exec_scopes.enter_scope(HashMap::from_iter([(String::from("syscall_handler"), syscall_handler)]));
    Ok(())
}

fn set_state_entry(
    dict_ptr: Relocatable,
    key: Felt252,
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), HintError> {
    let val = match exec_scopes.get_dict_manager()?.borrow().get_tracker(dict_ptr)?.data.clone() {
        Dictionary::SimpleDictionary(dict) => dict.get(&MaybeRelocatable::Int(key)).cloned(),
        Dictionary::DefaultDictionary { dict: _d, default_value: _v } => {
            return Err(HintError::CustomHint(
                "State changes dictionary should not be a default dict".to_string().into_boxed_str(),
            ));
        }
    };
    let val =
        val.ok_or(HintError::CustomHint("State changes dictionary should not be None".to_string().into_boxed_str()))?;

    insert_value_from_var_name(vars::ids::STATE_ENTRY, val, vm, ids_data, ap_tracking)?;
    Ok(())
}

pub const GET_CONTRACT_ADDRESS_STATE_ENTRY: &str = indoc! {r#"
    # Fetch a state_entry in this hint and validate it in the update at the end
    # of this function.
    ids.state_entry = __dict_manager.get_dict(ids.contract_state_changes)[ids.contract_address]"#
};

pub fn get_contract_address_state_entry(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let dict_ptr = get_ptr_from_var_name(vars::ids::CONTRACT_STATE_CHANGES, vm, ids_data, ap_tracking)?;
    let key = get_integer_from_var_name(vars::ids::CONTRACT_ADDRESS, vm, ids_data, ap_tracking)?;

    set_state_entry(dict_ptr, key, vm, exec_scopes, ids_data, ap_tracking)?;

    Ok(())
}

pub const SET_STATE_ENTRY_TO_ACCOUNT_CONTRACT_ADDRESS: &str = indoc! {r#"
    # Fetch a state_entry in this hint and validate it in the update that comes next.
    ids.state_entry = __dict_manager.get_dict(ids.contract_state_changes)[
        ids.tx_info.account_contract_address
    ]"#
};

pub fn set_state_entry_to_account_contract_address(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let dict_ptr = get_ptr_from_var_name(vars::ids::CONTRACT_STATE_CHANGES, vm, ids_data, ap_tracking)?;
    let tx_info_ptr = get_ptr_from_var_name(vars::ids::TX_INFO, vm, ids_data, ap_tracking)?;
    let account_contract_address =
        vm.get_integer((tx_info_ptr + TxInfo::account_contract_address_offset())?)?.into_owned();

    set_state_entry(dict_ptr, account_contract_address, vm, exec_scopes, ids_data, ap_tracking)?;

    Ok(())
}

fn get_state_entry_and_set_new_state_entry(
    dict_ptr: Relocatable,
    key: Felt252,
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), HintError> {
    set_state_entry(dict_ptr, key, vm, exec_scopes, ids_data, ap_tracking)?;

    let new_segment = vm.add_memory_segment();
    insert_value_from_var_name(vars::ids::NEW_STATE_ENTRY, new_segment, vm, ids_data, ap_tracking)?;

    Ok(())
}

pub const GET_BLOCK_HASH_CONTRACT_ADDRESS_STATE_ENTRY_AND_SET_NEW_STATE_ENTRY: &str = indoc! {r#"
	# Fetch a state_entry in this hint. Validate it in the update that comes next.
	ids.state_entry = __dict_manager.get_dict(ids.contract_state_changes)[
	    ids.BLOCK_HASH_CONTRACT_ADDRESS]
	ids.new_state_entry = segments.add()"#
};

pub fn get_block_hash_contract_address_state_entry_and_set_new_state_entry(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let dict_ptr = get_ptr_from_var_name(vars::ids::CONTRACT_STATE_CHANGES, vm, ids_data, ap_tracking)?;
    let key = get_constant(vars::constants::BLOCK_HASH_CONTRACT_ADDRESS, constants)?;

    get_state_entry_and_set_new_state_entry(dict_ptr, *key, vm, exec_scopes, ids_data, ap_tracking)?;

    Ok(())
}

pub const GET_CONTRACT_ADDRESS_STATE_ENTRY_AND_SET_NEW_STATE_ENTRY: &str = indoc! {r#"
    # Fetch a state_entry in this hint and validate it in the update that comes next.
    ids.state_entry = __dict_manager.get_dict(ids.contract_state_changes)[ids.contract_address]
    ids.new_state_entry = segments.add()"#
};
pub const GET_CONTRACT_ADDRESS_STATE_ENTRY_AND_SET_NEW_STATE_ENTRY_2: &str = indoc! {r#"
	# Fetch a state_entry in this hint and validate it in the update that comes next.
	ids.state_entry = __dict_manager.get_dict(ids.contract_state_changes)[
	    ids.contract_address
	]

	ids.new_state_entry = segments.add()"#
};

pub fn get_contract_address_state_entry_and_set_new_state_entry(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let dict_ptr = get_ptr_from_var_name(vars::ids::CONTRACT_STATE_CHANGES, vm, ids_data, ap_tracking)?;
    let key = get_integer_from_var_name(vars::ids::CONTRACT_ADDRESS, vm, ids_data, ap_tracking)?;

    get_state_entry_and_set_new_state_entry(dict_ptr, key, vm, exec_scopes, ids_data, ap_tracking)?;

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

    let execution_into_ptr = vm.get_relocatable((execution_context + 4usize)?).unwrap();
    let contract_address = vm.get_integer((execution_into_ptr + 3usize)?).unwrap();

    println!(
        "about to call contract_address: {}, class_hash: {}, is_deprecated: {}",
        contract_address,
        class_hash,
        if is_deprecated_class { 1u8 } else { 0u8 }
    );

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

pub const OS_CONTEXT_SEGMENTS: &str = indoc! {r#"
    ids.os_context = segments.add()
    ids.syscall_ptr = segments.add()"#
};
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

// TODO(#66): fix syscall entry
// DROP THE ADDED VARIABLES
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
    let os_input = exec_scopes.get::<StarknetOsInput>("os_input")?;
    let deprecated_class_hashes: Box<dyn Any> =
        Box::new(exec_scopes.get::<HashSet<Felt252>>("__deprecated_class_hashes")?);
    let transactions: Box<dyn Any> = Box::new(os_input.transactions.into_iter());
    let execution_helper: Box<dyn Any> = Box::new(exec_scopes.get::<ExecutionHelperWrapper>("execution_helper")?);
    let deprecated_syscall_handler: Box<dyn Any> =
        Box::new(exec_scopes.get::<DeprecatedOsSyscallHandlerWrapper>("deprecated_syscall_handler")?);
    let syscall_handler: Box<dyn Any> = Box::new(exec_scopes.get::<OsSyscallHandlerWrapper>("syscall_handler")?);
    let dict_manager: Box<dyn Any> = Box::new(exec_scopes.get_dict_manager()?);
    exec_scopes.enter_scope(HashMap::from_iter([
        (String::from("__deprecated_class_hashes"), deprecated_class_hashes),
        (String::from("transactions"), transactions),
        (String::from("execution_helper"), execution_helper),
        (String::from("deprecated_syscall_handler"), deprecated_syscall_handler),
        (String::from("syscall_handler"), syscall_handler),
        (String::from("dict_manager"), dict_manager),
    ]));
    Ok(())
}

// pub const START_DEPLOY_TX: &str = indoc! {r#"
//     execution_helper.start_tx(
//         tx_info_ptr=ids.constructor_execution_context.deprecated_tx_info.address_
//     )"#
// };
pub fn start_deploy_tx(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let constructor_execution_context =
        get_relocatable_from_var_name("constructor_execution_context", vm, ids_data, ap_tracking)?;
    let deprecated_tx_info_ptr = (constructor_execution_context + 5usize).unwrap();

    let execution_helper = exec_scopes.get::<ExecutionHelperWrapper>("execution_helper").unwrap();
    execution_helper.start_tx(Some(deprecated_tx_info_ptr));
    Ok(())
}

pub const END_TX: &str = "execution_helper.end_tx()";
pub fn end_tx(
    _vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let execution_helper = exec_scopes.get::<ExecutionHelperWrapper>("execution_helper")?;
    execution_helper.end_tx();
    Ok(())
}

pub const ENTER_CALL: &str = indoc! {r#"
    execution_helper.enter_call(
        execution_info_ptr=ids.execution_context.execution_info.address_)"#
};
pub fn enter_call(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let execution_info_ptr =
        vm.get_relocatable((get_ptr_from_var_name("execution_context", vm, ids_data, ap_tracking)? + 4i32).unwrap())?;

    let execution_helper = exec_scopes.get::<ExecutionHelperWrapper>("execution_helper")?;
    execution_helper.enter_call(Some(execution_info_ptr));
    Ok(())
}

pub const EXIT_CALL: &str = "execution_helper.exit_call()";
pub fn exit_call(
    _vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let mut execution_helper = exec_scopes.get::<ExecutionHelperWrapper>("execution_helper")?;
    execution_helper.exit_call();
    Ok(())
}

pub const CONTRACT_ADDRESS: &str = indoc! {r#"
    from starkware.starknet.business_logic.transaction.deprecated_objects import (
        InternalL1Handler,
    )
    ids.contract_address = (
        tx.contract_address if isinstance(tx, InternalL1Handler) else tx.sender_address
    )"#
};

pub fn contract_address(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let tx = exec_scopes.get::<InternalTransaction>("tx")?;
    let contract_address = if tx.r#type == "L1_HANDLER" {
        tx.contract_address
            .ok_or(HintError::CustomHint("tx.contract_address is None".to_string().into_boxed_str()))
            .unwrap()
    } else {
        tx.sender_address
            .ok_or(HintError::CustomHint("tx.sender_address is None".to_string().into_boxed_str()))
            .unwrap()
    };
    insert_value_from_var_name("contract_address", contract_address, vm, ids_data, ap_tracking)
}

pub const TX_CALLDATA_LEN: &str = "memory[ap] = to_felt_or_relocatable(len(tx.calldata))";

pub fn tx_calldata_len(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let tx = exec_scopes.get::<InternalTransaction>("tx")?;
    let len = tx.calldata.unwrap_or_default().len();
    insert_value_into_ap(vm, Felt252::from(len))
}

pub const TX_CALLDATA: &str = "memory[ap] = to_felt_or_relocatable(segments.gen_arg(tx.calldata))";

pub fn tx_calldata(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let tx = exec_scopes.get::<InternalTransaction>("tx")?;
    let calldata = tx.calldata.unwrap_or_default().iter().map(|felt| felt.into()).collect();
    let calldata_base = vm.add_memory_segment();
    vm.load_data(calldata_base, &calldata)?;
    insert_value_into_ap(vm, calldata_base)
}

pub const TX_ENTRY_POINT_SELECTOR: &str = "memory[ap] = to_felt_or_relocatable(tx.entry_point_selector)";
pub fn tx_entry_point_selector(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let tx = exec_scopes.get::<InternalTransaction>("tx")?;
    let entry_point_selector = tx
        .entry_point_selector
        .ok_or(HintError::CustomHint("tx.entry_point_selector is None".to_string().into_boxed_str()))
        .unwrap_or_default();
    insert_value_into_ap(vm, entry_point_selector)
}

pub const RESOURCE_BOUNDS: &str = indoc! {r#"
    from src.starkware.starknet.core.os.transaction_hash.transaction_hash import (
        create_resource_bounds_list,
    )

    ids.resource_bounds = (
        0
        if tx.version < 3
        else segments.gen_arg(create_resource_bounds_list(tx.resource_bounds))
    )"#
};

pub fn resource_bounds(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let tx = exec_scopes.get::<InternalTransaction>("tx")?;
    let version = tx.version.unwrap_or_default();
    assert!(version < 3.into(), "tx.version >= 3 is not supported yet");

    // TODO: implement resource_bounds for tx.version >= 3
    // let resource_bounds = if tx.version < 3 {
    //     0
    // } else {
    //     let resource_bounds = tx.resource_bounds.unwrap_or_default().iter().map(|felt|
    // felt.into()).collect();     let resource_bounds_base = vm.add_memory_segment();
    //     vm.load_data(resource_bounds_base, &resource_bounds)?;
    //     resource_bounds_base
    // };

    let resource_bounds = 0;
    insert_value_from_var_name("resource_bounds", resource_bounds, vm, ids_data, ap_tracking)
}

pub const TX_MAX_FEE: &str = "memory[ap] = to_felt_or_relocatable(tx.max_fee if tx.version < 3 else 0)";
pub fn tx_max_fee(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let tx = exec_scopes.get::<InternalTransaction>("tx")?;
    // TODO: implement tx.version >= 3
    assert!(tx.version.unwrap_or_default() < 3.into(), "tx.version >= 3 is not supported yet");

    // let max_fee = if tx.version.unwrap_or_default() < 3.into() {
    //     tx.max_fee.unwrap_or_default()
    // } else {
    //     0
    // };

    let max_fee = tx.max_fee.unwrap();

    insert_value_into_ap(vm, max_fee)
}

pub const TX_NONCE: &str = "memory[ap] = to_felt_or_relocatable(0 if tx.nonce is None else tx.nonce)";
pub fn tx_nonce(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let tx = exec_scopes.get::<InternalTransaction>("tx")?;
    let nonce = if tx.nonce.is_none() { 0.into() } else { tx.nonce.unwrap() };
    insert_value_into_ap(vm, nonce)
}

pub const TX_TIP: &str = "memory[ap] = to_felt_or_relocatable(0 if tx.version < 3 else tx.tip)";
pub fn tx_tip(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let tx = exec_scopes.get::<InternalTransaction>("tx")?;
    // TODO: implement tx.version >= 3
    assert!(tx.version.unwrap_or_default() < 3.into(), "tx.version >= 3 is not supported yet");

    // let tip = if tx.version.unwrap_or_default() < 3.into() {
    //     0.into()
    // } else {
    //     tx.tip.unwrap_or_default()
    // };

    let tip = Felt252::ZERO;

    insert_value_into_ap(vm, tip)
}

pub const TX_RESOURCE_BOUNDS_LEN: &str =
    "memory[ap] = to_felt_or_relocatable(0 if tx.version < 3 else len(tx.resource_bounds))";
pub fn tx_resource_bounds_len(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let tx = exec_scopes.get::<InternalTransaction>("tx")?;
    // TODO: implement tx.version >= 3
    assert!(tx.version.unwrap_or_default() < 3.into(), "tx.version >= 3 is not supported yet");

    // let len = if tx.version.unwrap_or_default() < 3.into() {
    //     0.into()
    // } else {
    //     tx.resource_bounds.unwrap_or_default().len().into()
    // };

    let len = Felt252::ZERO;
    insert_value_into_ap(vm, len)
}

pub const TX_PAYMASTER_DATA_LEN: &str =
    "memory[ap] = to_felt_or_relocatable(0 if tx.version < 3 else len(tx.paymaster_data))";
pub fn tx_paymaster_data_len(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let tx = exec_scopes.get::<InternalTransaction>("tx")?;
    // TODO: implement tx.version >= 3
    assert!(tx.version.unwrap_or_default() < 3.into(), "tx.version >= 3 is not supported yet");

    // let len = if tx.version.unwrap_or_default() < 3.into() {
    //     0.into()
    // } else {
    //     tx.paymaster_data.unwrap_or_default().len().into()
    // };

    let len = Felt252::ZERO;
    insert_value_into_ap(vm, len)
}

pub const TX_PAYMASTER_DATA: &str =
    "memory[ap] = to_felt_or_relocatable(0 if tx.version < 3 else segments.gen_arg(tx.paymaster_data))";
pub fn tx_paymaster_data(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let tx = exec_scopes.get::<InternalTransaction>("tx")?;
    // TODO: implement tx.version >= 3
    assert!(tx.version.unwrap_or_default() < 3.into(), "tx.version >= 3 is not supported yet");

    // let paymaster_data = if tx.version.unwrap_or_default() < 3.into() {
    //     0.into()
    // } else {
    //     let paymaster_data = tx.paymaster_data.unwrap_or_default().iter().map(|felt|
    // felt.into()).collect();     let paymaster_data_base = vm.add_memory_segment();
    //     vm.load_data(paymaster_data_base, &paymaster_data)?;
    //     paymaster_data_base
    // };
    let paymaster_data = Felt252::ZERO;
    insert_value_into_ap(vm, paymaster_data)
}

pub const TX_NONCE_DATA_AVAILABILITY_MODE: &str =
    "memory[ap] = to_felt_or_relocatable(0 if tx.version < 3 else tx.nonce_data_availability_mode)";
pub fn tx_nonce_data_availability_mode(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let tx = exec_scopes.get::<InternalTransaction>("tx")?;
    // TODO: implement tx.version >= 3
    assert!(tx.version.unwrap_or_default() < 3.into(), "tx.version >= 3 is not supported yet");

    // let nonce_data_availability_mode = if tx.version.unwrap_or_default() < 3.into() {
    //     0.into()
    // } else {
    //     tx.nonce_data_availability_mode.unwrap_or_default()
    // };

    let nonce_data_availability_mode = Felt252::ZERO;
    insert_value_into_ap(vm, nonce_data_availability_mode)
}

pub const TX_FEE_DATA_AVAILABILITY_MODE: &str =
    "memory[ap] = to_felt_or_relocatable(0 if tx.version < 3 else tx.fee_data_availability_mode)";
pub fn tx_fee_data_availability_mode(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let tx = exec_scopes.get::<InternalTransaction>("tx")?;
    // TODO: implement tx.version >= 3
    assert!(tx.version.unwrap_or_default() < 3.into(), "tx.version >= 3 is not supported yet");

    // let fee_data_availability_mode = if tx.version.unwrap_or_default() < 3.into() {
    //     0.into()
    // } else {
    //     tx.fee_data_availability_mode.unwrap_or_default()
    // };

    let fee_data_availability_mode = Felt252::ZERO;
    insert_value_into_ap(vm, fee_data_availability_mode)
}

pub const TX_ACCOUNT_DEPLOYMENT_DATA_LEN: &str =
    "memory[ap] = to_felt_or_relocatable(0 if tx.version < 3 else len(tx.account_deployment_data))";
pub fn tx_account_deployment_data_len(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let tx = exec_scopes.get::<InternalTransaction>("tx")?;
    // TODO: implement tx.version >= 3
    assert!(tx.version.unwrap_or_default() < 3.into(), "tx.version >= 3 is not supported yet");

    // let len = if tx.version.unwrap_or_default() < 3.into() {
    //     0.into()
    // } else {
    //     tx.account_deployment_data.unwrap_or_default().len().into()
    // };

    let len = Felt252::ZERO;
    insert_value_into_ap(vm, len)
}

pub const TX_ACCOUNT_DEPLOYMENT_DATA: &str =
    "memory[ap] = to_felt_or_relocatable(0 if tx.version < 3 else segments.gen_arg(tx.account_deployment_data))";
pub fn tx_account_deployment_data(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let tx = exec_scopes.get::<InternalTransaction>("tx")?;
    // TODO: implement tx.version >= 3
    assert!(tx.version.unwrap_or_default() < 3.into(), "tx.version >= 3 is not supported yet");

    // let account_deployment_data = if tx.version.unwrap_or_default() < 3.into() {
    //     0.into()
    // } else {
    //     let account_deployment_data =
    // tx.account_deployment_data.unwrap_or_default().iter().map(|felt| felt.into()).collect();
    //     let account_deployment_data_base = vm.add_memory_segment();
    //     vm.load_data(account_deployment_data_base, &account_deployment_data)?;
    //     account_deployment_data_base
    // };

    let account_deployment_data = Felt252::ZERO;
    insert_value_into_ap(vm, account_deployment_data)
}

pub const GEN_SIGNATURE_ARG: &str = indoc! {r#"
	ids.signature_start = segments.gen_arg(arg=tx.signature)
	ids.signature_len = len(tx.signature)"#
};
pub fn gen_signature_arg(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let tx = exec_scopes.get::<InternalTransaction>("tx")?;
    let signature = tx.signature.ok_or(HintError::CustomHint("tx.signature is none".to_owned().into_boxed_str()))?;
    let signature_start_base = vm.add_memory_segment();
    let signature = signature.iter().map(|f| MaybeRelocatable::Int(*f)).collect();
    vm.load_data(signature_start_base, &signature)?;

    insert_value_from_var_name(SIGNATURE_START, signature_start_base, vm, ids_data, ap_tracking)?;
    insert_value_from_var_name(SIGNATURE_LEN, signature.len(), vm, ids_data, ap_tracking)?;

    Ok(())
}

pub const START_TX: &str = indoc! {r#"
    tx_info_ptr = ids.tx_execution_context.deprecated_tx_info.address_
    execution_helper.start_tx(tx_info_ptr=tx_info_ptr)"#
};
pub fn start_tx(
    _vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let tx_execution_context = get_relocatable_from_var_name("tx_execution_context", _vm, ids_data, _ap_tracking)?;
    let execution_helper = exec_scopes.get::<ExecutionHelperWrapper>("execution_helper")?;
    let tx_info_ptr = (tx_execution_context + ExecutionContext::deprecated_tx_info_offset())?;
    execution_helper.start_tx(Some(tx_info_ptr));
    Ok(())
}

pub const IS_REVERTED: &str = "memory[ap] = to_felt_or_relocatable(execution_helper.tx_execution_info.is_reverted)";
pub fn is_reverted(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    // TODO: implement is_reverted when tx_execution_info abstraction is ready
    // let execution_helper = exec_scopes.get::<ExecutionHelperWrapper>("execution_helper")?;
    // insert_value_into_ap(vm, Felt252::from(execution_helper. tx_execution_info.is_reverted))
    insert_value_into_ap(vm, Felt252::ZERO)
}

pub const CHECK_EXECUTION: &str = indoc! {r#"
    return_values = ids.entry_point_return_values
    if return_values.failure_flag != 0:
        # Fetch the error, up to 100 elements.
        retdata_size = return_values.retdata_end - return_values.retdata_start
        error = memory.get_range(return_values.retdata_start, max(0, min(100, retdata_size)))

        print("Invalid return value in execute_entry_point:")
        print(f"  Class hash: {hex(ids.execution_context.class_hash)}")
        print(f"  Selector: {hex(ids.execution_context.execution_info.selector)}")
        print(f"  Size: {retdata_size}")
        print(f"  Error (at most 100 elements): {error}")

    if execution_helper.debug_mode:
        # Validate the predicted gas cost.
        actual = ids.remaining_gas - ids.entry_point_return_values.gas_builtin
        predicted = execution_helper.call_info.gas_consumed
        assert actual == predicted, (
            "Predicted gas costs are inconsistent with the actual execution; "
            f"{predicted=}, {actual=}."
        )

    # Exit call.
    syscall_handler.validate_and_discard_syscall_ptr(
        syscall_ptr_end=ids.entry_point_return_values.syscall_ptr
    )
    execution_helper.exit_call()"#
};

// implement check_execution according to the pythonic version given in the CHECK_EXECUTION const
// above
pub fn check_execution(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let return_values_ptr = get_ptr_from_var_name(ENTRY_POINT_RETURN_VALUES, vm, ids_data, ap_tracking)?;

    let failure_flag = vm.get_integer((return_values_ptr + EntryPointReturnValues::failure_flag_offset())?)?;
    if failure_flag.into_owned() != Felt252::ZERO {
        let retdata_end = vm.get_relocatable((return_values_ptr + EntryPointReturnValues::retdata_end_offset())?)?;
        let retdata_start =
            vm.get_relocatable((return_values_ptr + EntryPointReturnValues::retdata_start_offset())?)?;
        let retdata_size = (retdata_end - retdata_start)?;
        let error = vm.get_range(retdata_start, std::cmp::min(100, retdata_size as usize));
        let execution_context = get_relocatable_from_var_name(EXECUTION_CONTEXT, vm, ids_data, ap_tracking)?;
        let class_hash = vm.get_integer((execution_context + ExecutionContext::class_hash_offset())?)?;
        let selector = vm.get_integer((execution_context + ExecutionContext::execution_info_offset())?)?;
        println!("Invalid return value in execute_entry_point:");
        println!("  Class hash: {}", class_hash.to_hex_string());
        println!("  Selector: {}", selector.to_hex_string());
        println!("  Size: {}", retdata_size);
        println!("  Error (at most 100 elements): {:?}", error);
    }

    let mut execution_helper = exec_scopes.get::<ExecutionHelperWrapper>(EXECUTION_HELPER)?;
    // TODO: make sure it is necessary to check the gas costs
    // if execution_helper.debug_mode {
    //     let actual = get_integer_from_var_name("remaining_gas", vm, ids_data, ap_tracking)?;
    //     let predicted = get_integer_from_var_name("gas_consumed", vm, ids_data, ap_tracking)?;
    //     assert_eq!(
    //         actual,
    //         predicted,
    //         "Predicted gas costs are inconsistent with the actual execution; predicted={},
    // actual={}.",         predicted,
    //         actual
    //     );
    // }

    let syscall_ptr_end = vm.get_relocatable((return_values_ptr + EntryPointReturnValues::syscall_ptr_offset())?)?;
    let syscall_handler = exec_scopes.get::<OsSyscallHandlerWrapper>(SYSCALL_HANDLER)?;
    syscall_handler.validate_and_discard_syscall_ptr(syscall_ptr_end)?;
    execution_helper.exit_call();

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

pub const LOG_ENTER_SYSCALL: &str = indoc! {r#"
    execution_helper.os_logger.enter_syscall(
        n_steps=current_step,
        builtin_ptrs=ids.builtin_ptrs,
        range_check_ptr=ids.range_check_ptr,
        deprecated=False,
        selector=ids.selector,
    )

    # Prepare a short callable to save code duplication.
    exit_syscall = lambda selector: execution_helper.os_logger.exit_syscall(
        n_steps=current_step,
        builtin_ptrs=ids.builtin_ptrs,
        range_check_ptr=ids.range_check_ptr,
        selector=selector,
    )"#
};

pub fn log_enter_syscall(
    _vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let selector = get_integer_from_var_name(SELECTOR, _vm, ids_data, _ap_tracking)?;
    println!("entering syscall: {:?} execution", SyscallSelector::try_from(selector)?);
    // TODO: implement logging
    Ok(())
}

pub const INITIAL_GE_REQUIRED_GAS: &str = "memory[ap] = to_felt_or_relocatable(ids.initial_gas >= ids.required_gas)";
pub fn initial_ge_required_gas(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    // line below fails with: UnknownIdentifier("required_gas"):
    // let required_gas = get_integer_from_var_name(REQUIRED_GAS, vm, ids_data, ap_tracking)?;

    // the reason for this is: hint reference for `required_gas` is cast([fp + (-4)] + (-10000), felt)
    // in our case [fp-4] contains a felt  to `get_integer_from_var_name` assumes that [fp-4] contains a
    // pointer not a felt below is a temporary workaround, until the problem is solved in the vm

    // workaround
    let required_gas = *vm.get_integer((vm.get_fp() - 4)?)? - 10000;

    let initial_gas = get_integer_from_var_name(INITIAL_GAS, vm, ids_data, ap_tracking)?;
    insert_value_into_ap(vm, Felt252::from(initial_gas.as_ref() >= &required_gas))
}

pub const CHECK_RESPONSE_RETURN_VALUE: &str = indoc! {r#"
    # Check that the actual return value matches the expected one.
    expected = memory.get_range(
        addr=ids.response.retdata_start,
        size=ids.response.retdata_end - ids.response.retdata_start,
    )
    actual = memory.get_range(addr=ids.retdata, size=ids.retdata_size)

    assert expected == actual, f'Return value mismatch; expected={expected}, actual={actual}.'"#
};

pub fn check_response_return_value(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let retdata = get_ptr_from_var_name("retdata", vm, ids_data, ap_tracking)?;
    let retdata_size = get_integer_from_var_name("retdata_size", vm, ids_data, ap_tracking)?;

    let response = get_ptr_from_var_name("response", vm, ids_data, ap_tracking)?;
    let response_retdata_start = vm.get_relocatable((response + CallContractResponse::retdata_start_offset())?)?;
    let response_retdata_end = vm.get_relocatable((response + CallContractResponse::retdata_end_offset())?)?;

    let expected = vm.get_range(response_retdata_start, (response_retdata_end - response_retdata_start)?);
    let actual = vm.get_range(
        retdata,
        retdata_size
            .as_ref()
            .to_usize()
            .ok_or(HintError::CustomHint("retdata_size is not usize".to_string().into_boxed_str()))?,
    );

    assert_eq!(expected, actual, "Return value mismatch; expected={:?}, actual={:?}", expected, actual);

    // relocate_segment(src_ptr=response.retdata_start, dest_ptr=retdata);
    println!("response_retdata_start: {}, retdata: {}", response_retdata_start, retdata);

    Ok(())
}

fn cache_contract_storage(
    key: Felt252,
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), HintError> {
    let mut execution_helper = exec_scopes.get::<ExecutionHelperWrapper>(vars::scopes::EXECUTION_HELPER)?;

    let contract_address = get_integer_from_var_name(vars::ids::CONTRACT_ADDRESS, vm, ids_data, ap_tracking)?;

    let value = execution_helper.read_storage_for_address(contract_address, key).map_err(|_| {
        HintError::CustomHint(format!("No storage found for contract {}", contract_address).into_boxed_str())
    })?;

    let ids_value = get_integer_from_var_name(vars::ids::VALUE, vm, ids_data, ap_tracking)?;
    if ids_value != value {
        return Err(HintError::AssertionFailed(
            format!("Inconsistent storage value (expected {}, got {})", ids_value, value).into_boxed_str(),
        ));
    }

    exec_scopes.insert_value(vars::scopes::VALUE, value);

    Ok(())
}

pub const ADD_RELOCATION_RULE: &str = "memory.add_relocation_rule(src_ptr=ids.src_ptr, dest_ptr=ids.dest_ptr)";

pub fn add_relocation_rule(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let src_ptr = get_ptr_from_var_name(vars::ids::SRC_PTR, vm, ids_data, ap_tracking)?;
    let dest_ptr = get_ptr_from_var_name(vars::ids::DEST_PTR, vm, ids_data, ap_tracking)?;
    vm.add_relocation_rule(src_ptr, dest_ptr)?;

    Ok(())
}
pub const SET_AP_TO_TX_NONCE: &str = "memory[ap] = to_felt_or_relocatable(tx.nonce)";

pub fn set_ap_to_tx_nonce(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let tx: &InternalTransaction = exec_scopes.get_ref(vars::scopes::TX)?;
    let nonce = tx.nonce.ok_or(HintError::AssertionFailed("tx.nonce should be set".to_string().into_boxed_str()))?;
    insert_value_into_ap(vm, nonce)?;

    Ok(())
}

pub const SET_FP_PLUS_4_TO_TX_NONCE: &str = "memory[fp + 4] = to_felt_or_relocatable(tx.nonce)";

pub fn set_fp_plus_4_to_tx_nonce(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let tx: &InternalTransaction = exec_scopes.get_ref(vars::scopes::TX)?;
    let nonce = tx.nonce.ok_or(HintError::AssertionFailed("tx.nonce should be set".to_string().into_boxed_str()))?;
    vm.insert_value((vm.get_fp() + 4)?, nonce)?;

    Ok(())
}

pub fn enter_node_scope(node: UpdateTree<StorageLeaf>, exec_scopes: &mut ExecutionScopes) -> Result<(), HintError> {
    // vm_enter_scope(dict(node=new_node, **common_args))"#
    // In this implementation we assume that `common_args` is unpacked, having a
    // `HashMap<String, Box<dyn Any>>` as scope variable is unpractical.
    // `common_args` contains the 3 variables below and is never modified.
    let new_scope = {
        let preimage: Preimage = exec_scopes.get(vars::scopes::PREIMAGE)?;
        let descent_map: DescentMap = exec_scopes.get(vars::scopes::DESCENT_MAP)?;
        let patricia_skip_validation_runner: Option<PatriciaSkipValidationRunner> =
            exec_scopes.get(vars::scopes::PATRICIA_SKIP_VALIDATION_RUNNER)?;

        HashMap::from([
            (vars::scopes::NODE.to_string(), any_box!(node)),
            (vars::scopes::PREIMAGE.to_string(), any_box!(preimage)),
            (vars::scopes::DESCENT_MAP.to_string(), any_box!(descent_map)),
            (vars::scopes::PATRICIA_SKIP_VALIDATION_RUNNER.to_string(), any_box!(patricia_skip_validation_runner)),
        ])
    };
    exec_scopes.enter_scope(new_scope);

    Ok(())
}

pub const ENTER_SCOPE_NODE: &str = "vm_enter_scope(dict(node=node, **common_args))";

pub fn enter_scope_node_hint(
    _vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let node: UpdateTree<StorageLeaf> = exec_scopes.get(vars::scopes::NODE)?;
    enter_node_scope(node, exec_scopes)
}

pub const ENTER_SCOPE_NEW_NODE: &str = indoc! {r#"
	ids.child_bit = 0 if case == 'left' else 1
	new_node = left_child if case == 'left' else right_child
	vm_enter_scope(dict(node=new_node, **common_args))"#
};

pub fn enter_scope_new_node(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let left_child: UpdateTree<StorageLeaf> = exec_scopes.get(vars::scopes::LEFT_CHILD)?;
    let right_child: UpdateTree<StorageLeaf> = exec_scopes.get(vars::scopes::RIGHT_CHILD)?;
    let case: DecodeNodeCase = exec_scopes.get(vars::scopes::CASE)?;

    let (child_bit, new_node) = match case {
        DecodeNodeCase::Left => (Felt252::ZERO, left_child),
        _ => (Felt252::ONE, right_child),
    };

    insert_value_from_var_name(vars::ids::CHILD_BIT, child_bit, vm, ids_data, ap_tracking)?;

    enter_node_scope(new_node, exec_scopes)?;

    Ok(())
}

fn enter_scope_next_node(
    bit_value: Felt252,
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), HintError> {
    let left_child: UpdateTree<StorageLeaf> = exec_scopes.get(vars::scopes::LEFT_CHILD)?;
    let right_child: UpdateTree<StorageLeaf> = exec_scopes.get(vars::scopes::RIGHT_CHILD)?;

    let bit = get_integer_from_var_name(vars::ids::BIT, vm, ids_data, ap_tracking)?;

    let next_node = if bit.as_ref() == &bit_value { left_child } else { right_child };

    enter_node_scope(next_node, exec_scopes)?;

    Ok(())
}

pub const ENTER_SCOPE_NEXT_NODE_BIT_0: &str = indoc! {r#"
	new_node = left_child if ids.bit == 0 else right_child
	vm_enter_scope(dict(node=new_node, **common_args))"#
};

pub fn enter_scope_next_node_bit_0(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    enter_scope_next_node(Felt252::ZERO, vm, exec_scopes, ids_data, ap_tracking)
}

pub const ENTER_SCOPE_NEXT_NODE_BIT_1: &str = indoc! {r#"
	new_node = left_child if ids.bit == 1 else right_child
	vm_enter_scope(dict(node=new_node, **common_args))"#
};

pub fn enter_scope_next_node_bit_1(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    enter_scope_next_node(Felt252::ONE, vm, exec_scopes, ids_data, ap_tracking)
}

pub const ENTER_SCOPE_LEFT_CHILD: &str = "vm_enter_scope(dict(node=left_child, **common_args))";

pub fn enter_scope_left_child(
    _vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let left_child: UpdateTree<StorageLeaf> = exec_scopes.get(vars::scopes::LEFT_CHILD)?;
    enter_node_scope(left_child, exec_scopes)
}

pub const ENTER_SCOPE_RIGHT_CHILD: &str = "vm_enter_scope(dict(node=right_child, **common_args))";

pub fn enter_scope_right_child(
    _vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let right_child: UpdateTree<StorageLeaf> = exec_scopes.get(vars::scopes::RIGHT_CHILD)?;
    enter_node_scope(right_child, exec_scopes)
}

pub const ENTER_SCOPE_DESCEND_EDGE: &str = indoc! {r#"
	new_node = node
	for i in range(ids.length - 1, -1, -1):
	    new_node = new_node[(ids.word >> i) & 1]
	vm_enter_scope(dict(node=new_node, **common_args))"#
};

pub fn enter_scope_descend_edge(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let mut new_node: UpdateTree<StorageLeaf> = exec_scopes.get(vars::scopes::NODE)?;
    let length = {
        let length = get_integer_from_var_name(vars::ids::LENGTH, vm, ids_data, ap_tracking)?;
        length.to_u64().ok_or(MathError::Felt252ToU64Conversion(Box::new(length)))?
    };
    let word = get_integer_from_var_name(vars::ids::WORD, vm, ids_data, ap_tracking)?.to_biguint();

    for i in (0..length).rev() {
        match new_node {
            None => {
                return Err(HintError::CustomHint("Expected a node".to_string().into_boxed_str()));
            }
            Some(TreeUpdate::Leaf(_)) => {
                return Err(HintError::CustomHint("Did not expect a leaf node".to_string().into_boxed_str()));
            }
            Some(TreeUpdate::Tuple(left_child, right_child)) => {
                // new_node = new_node[(ids.word >> i) & 1]
                let one_biguint = BigUint::from(1u64);
                let descend_right = ((&word >> i) & &one_biguint) == one_biguint;
                if descend_right {
                    new_node = *right_child;
                } else {
                    new_node = *left_child;
                }
            }
        }
    }

    enter_node_scope(new_node, exec_scopes)
}

pub const WRITE_SYSCALL_RESULT_DEPRECATED: &str = indoc! {r#"
	storage = execution_helper.storage_by_address[ids.contract_address]
	ids.prev_value = storage.read(key=ids.syscall_ptr.address)
	storage.write(key=ids.syscall_ptr.address, value=ids.syscall_ptr.value)

	# Fetch a state_entry in this hint and validate it in the update that comes next.
	ids.state_entry = __dict_manager.get_dict(ids.contract_state_changes)[ids.contract_address]

	ids.new_state_entry = segments.add()"#
};

pub fn write_syscall_result_deprecated(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let mut execution_helper: ExecutionHelperWrapper = exec_scopes.get(vars::scopes::EXECUTION_HELPER)?;

    let contract_address = get_integer_from_var_name(vars::ids::CONTRACT_ADDRESS, vm, ids_data, ap_tracking)?;
    let syscall_ptr = get_ptr_from_var_name(vars::ids::SYSCALL_PTR, vm, ids_data, ap_tracking)?;

    // ids.prev_value = storage.read(key=ids.syscall_ptr.address)
    let storage_write_address = vm.get_integer((syscall_ptr + StorageWrite::address_offset())?)?.into_owned();
    let prev_value =
        execution_helper.read_storage_for_address(contract_address, storage_write_address).map_err(|_| {
            HintError::CustomHint(format!("Storage not found for contract {}", contract_address).into_boxed_str())
        })?;
    insert_value_from_var_name(vars::ids::PREV_VALUE, prev_value, vm, ids_data, ap_tracking)?;

    // storage.write(key=ids.syscall_ptr.address, value=ids.syscall_ptr.value)
    let storage_write_value = vm.get_integer((syscall_ptr + StorageWrite::value_offset())?)?.into_owned();
    execution_helper.write_storage_for_address(contract_address, storage_write_address, storage_write_value).map_err(
        |_| HintError::CustomHint(format!("Storage not found for contract {}", contract_address).into_boxed_str()),
    )?;

    let contract_state_changes = get_ptr_from_var_name(vars::ids::CONTRACT_STATE_CHANGES, vm, ids_data, ap_tracking)?;
    get_state_entry_and_set_new_state_entry(
        contract_state_changes,
        contract_address,
        vm,
        exec_scopes,
        ids_data,
        ap_tracking,
    )?;

    Ok(())
}
pub const WRITE_SYSCALL_RESULT: &str = indoc! {r#"
    storage = execution_helper.storage_by_address[ids.contract_address]
    ids.prev_value = storage.read(key=ids.request.key)
    storage.write(key=ids.request.key, value=ids.request.value)

    # Fetch a state_entry in this hint and validate it in the update that comes next.
    ids.state_entry = __dict_manager.get_dict(ids.contract_state_changes)[ids.contract_address]
    ids.new_state_entry = segments.add()"#
};

pub fn write_syscall_result(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let mut execution_helper: ExecutionHelperWrapper = exec_scopes.get(vars::scopes::EXECUTION_HELPER)?;

    let contract_address = get_integer_from_var_name(vars::ids::CONTRACT_ADDRESS, vm, ids_data, ap_tracking)?;
    let request = get_ptr_from_var_name(vars::ids::REQUEST, vm, ids_data, ap_tracking)?;
    let storage_write_address = *vm.get_integer((request + NewStorageWriteRequest::key_offset())?)?;
    let storage_write_value = vm.get_integer((request + NewStorageWriteRequest::value_offset())?)?.into_owned();

    // ids.prev_value = storage.read(key=ids.request.key)
    let prev_value =
        execution_helper.read_storage_for_address(contract_address, storage_write_address).unwrap_or_default();
    insert_value_from_var_name(vars::ids::PREV_VALUE, prev_value, vm, ids_data, ap_tracking)?;

    // storage.write(key=ids.request.key, value=ids.request.value)
    execution_helper.write_storage_for_address(contract_address, storage_write_address, storage_write_value).map_err(
        |_| HintError::CustomHint(format!("Storage not found for contract {}", contract_address).into_boxed_str()),
    )?;

    let contract_state_changes = get_ptr_from_var_name(vars::ids::CONTRACT_STATE_CHANGES, vm, ids_data, ap_tracking)?;
    get_state_entry_and_set_new_state_entry(
        contract_state_changes,
        contract_address,
        vm,
        exec_scopes,
        ids_data,
        ap_tracking,
    )?;

    Ok(())
}

pub const GEN_CLASS_HASH_ARG: &str = indoc! {r#"
    ids.tx_version = tx.version
    ids.sender_address = tx.sender_address
    ids.class_hash_ptr = segments.gen_arg([tx.class_hash])
    if tx.version <= 1:
        assert tx.compiled_class_hash is None, (
            "Deprecated declare must not have compiled_class_hash."
        )
        ids.compiled_class_hash = 0
    else:
        assert tx.compiled_class_hash is not None, (
            "Declare must have a concrete compiled_class_hash."
        )
        ids.compiled_class_hash = tx.compiled_class_hash"#
};

pub fn gen_class_hash_arg(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let tx: InternalTransaction = exec_scopes.get(vars::scopes::TX)?;

    let tx_version = tx.version.ok_or(HintError::CustomHint("tx.version is not set".to_string().into_boxed_str()))?;
    let sender_address =
        tx.sender_address.ok_or(HintError::CustomHint("tx.sender_address is not set".to_string().into_boxed_str()))?;
    let class_hash =
        tx.class_hash.ok_or(HintError::CustomHint("tx.class_hash is not set".to_string().into_boxed_str()))?;

    insert_value_from_var_name(vars::ids::TX_VERSION, tx_version, vm, ids_data, ap_tracking)?;
    insert_value_from_var_name(vars::ids::SENDER_ADDRESS, sender_address, vm, ids_data, ap_tracking)?;

    let class_hash_ptr_arg = vm.gen_arg(&vec![class_hash])?;
    insert_value_from_var_name(vars::ids::CLASS_HASH_PTR, class_hash_ptr_arg, vm, ids_data, ap_tracking)?;

    let compiled_class_hash = if tx_version <= Felt252::ONE {
        if tx.compiled_class_hash.is_some() {
            return Err(HintError::AssertionFailed(
                "Deprecated declare must not have compiled_class_hash.".to_string().into_boxed_str(),
            ));
        }
        Felt252::ZERO
    } else {
        tx.compiled_class_hash.ok_or(HintError::AssertionFailed(
            "Declare must have a concrete compiled_class_hash.".to_string().into_boxed_str(),
        ))?
    };

    insert_value_from_var_name(vars::ids::COMPILED_CLASS_HASH, compiled_class_hash, vm, ids_data, ap_tracking)?;

    Ok(())
}

pub const WRITE_OLD_BLOCK_TO_STORAGE: &str = indoc! {r#"
	storage = execution_helper.storage_by_address[ids.BLOCK_HASH_CONTRACT_ADDRESS]
	storage.write(key=ids.old_block_number, value=ids.old_block_hash)"#
};

pub fn write_old_block_to_storage(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let mut execution_helper: ExecutionHelperWrapper = exec_scopes.get(vars::scopes::EXECUTION_HELPER)?;

    let block_hash_contract_address = get_constant(vars::constants::BLOCK_HASH_CONTRACT_ADDRESS, constants)?;
    let old_block_number = get_integer_from_var_name(vars::ids::OLD_BLOCK_NUMBER, vm, ids_data, ap_tracking)?;
    let old_block_hash = get_integer_from_var_name(vars::ids::OLD_BLOCK_HASH, vm, ids_data, ap_tracking)?;

    println!("writing block number: {} -> block hash: {}", old_block_number, old_block_hash);
    execution_helper
        .write_storage_for_address(*block_hash_contract_address, old_block_number, old_block_hash)
        .map_err(|_| {
            HintError::CustomHint(
                format!("Storage not found for contract {}", block_hash_contract_address).into_boxed_str(),
            )
        })?;

    Ok(())
}

pub const CACHE_CONTRACT_STORAGE_REQUEST_KEY: &str = indoc! {r#"
	# Make sure the value is cached (by reading it), to be used later on for the
	# commitment computation.
	value = execution_helper.storage_by_address[ids.contract_address].read(key=ids.request.key)
	assert ids.value == value, "Inconsistent storage value.""#
};

pub fn cache_contract_storage_request_key(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let request_ptr = get_ptr_from_var_name(vars::ids::REQUEST, vm, ids_data, ap_tracking)?;
    let key = vm.get_integer((request_ptr + NewStorageRead::key_offset())?)?.into_owned();

    cache_contract_storage(key, vm, exec_scopes, ids_data, ap_tracking)
}

pub const CACHE_CONTRACT_STORAGE_SYSCALL_REQUEST_ADDRESS: &str = indoc! {r#"
	# Make sure the value is cached (by reading it), to be used later on for the
	# commitment computation.
	value = execution_helper.storage_by_address[ids.contract_address].read(
	    key=ids.syscall_ptr.request.address
	)
	assert ids.value == value, "Inconsistent storage value.""#
};

pub fn cache_contract_storage_syscall_request_address(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let syscall_ptr = get_ptr_from_var_name(vars::ids::SYSCALL_PTR, vm, ids_data, ap_tracking)?;
    let offset = StorageRead::request_offset() + StorageReadRequest::address_offset();
    let key = vm.get_integer((syscall_ptr + offset)?)?.into_owned();

    cache_contract_storage(key, vm, exec_scopes, ids_data, ap_tracking)
}
pub const GET_OLD_BLOCK_NUMBER_AND_HASH: &str = indoc! {r#"
	(
	    old_block_number, old_block_hash
	) = execution_helper.get_old_block_number_and_hash()
	assert old_block_number == ids.old_block_number,(
	    "Inconsistent block number. "
	    "The constant STORED_BLOCK_HASH_BUFFER is probably out of sync."
	)
	ids.old_block_hash = old_block_hash"#
};

pub fn get_old_block_number_and_hash(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let execution_helper: ExecutionHelperWrapper = exec_scopes.get(vars::scopes::EXECUTION_HELPER)?;
    let (old_block_number, old_block_hash) = execution_helper.get_old_block_number_and_hash()?;

    let ids_old_block_number = get_integer_from_var_name(vars::ids::OLD_BLOCK_NUMBER, vm, ids_data, ap_tracking)?;
    if old_block_number != ids_old_block_number {
        return Err(HintError::AssertionFailed(
            "Inconsistent block number. The constant STORED_BLOCK_HASH_BUFFER is probably out of sync."
                .to_string()
                .into_boxed_str(),
        ));
    }

    insert_value_from_var_name(vars::ids::OLD_BLOCK_HASH, old_block_hash, vm, ids_data, ap_tracking)?;

    Ok(())
}

pub const FETCH_RESULT: &str = indoc! {r#"
    # Fetch the result, up to 100 elements.
    result = memory.get_range(ids.retdata, min(100, ids.retdata_size))

    if result != [ids.VALIDATED]:
        print("Invalid return value from __validate__:")
        print(f"  Size: {ids.retdata_size}")
        print(f"  Result (at most 100 elements): {result}")"#
};

pub fn fetch_result(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    // Fetch the result, up to 100 elements.
    let retdata = get_ptr_from_var_name(vars::ids::RETDATA, vm, ids_data, ap_tracking)?;
    let retdata_size = get_integer_from_var_name(vars::ids::RETDATA_SIZE, vm, ids_data, ap_tracking)?;

    // validated is the string "VALID" translated to a felt.
    let validated = get_constant(vars::constants::VALIDATED, constants)?;

    let n_elements = std::cmp::min(felt_to_usize(&retdata_size)?, 100usize);

    let result = vm.get_range(retdata, n_elements);

    // This hint is weird, there is absolutely no need to fetch 100 elements to do this.
    // Nonetheless, we implement it 1-1 with the Python version.
    if n_elements != 1 || result[0] != Some(Cow::Borrowed(&MaybeRelocatable::Int(*validated))) {
        println!("Invalid return value from __validate__:");
        println!("  Size: {n_elements}");
        println!("  Result (at most 100 elements): {:?}", result);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use blockifier::block_context::BlockContext;
    use cairo_vm::hint_processor::builtin_hint_processor::dict_manager::DictManager;
    use cairo_vm::types::relocatable::Relocatable;
    use num_bigint::BigUint;
    use rstest::{fixture, rstest};
    use starknet_api::block::BlockNumber;

    use super::*;
    use crate::config::STORED_BLOCK_HASH_BUFFER;
    use crate::crypto::pedersen::PedersenHash;
    use crate::execution::helper::ContractStorageMap;
    use crate::starknet::starknet_storage::{execute_coroutine_threadsafe, OsSingleStarknetStorage, StorageLeaf};
    use crate::starkware_utils::commitment_tree::base_types::Height;
    use crate::starkware_utils::commitment_tree::binary_fact_tree::BinaryFactTree;
    use crate::starkware_utils::commitment_tree::patricia_tree::patricia_tree::PatriciaTree;
    use crate::starkware_utils::commitment_tree::update_tree::TreeUpdate;
    use crate::storage::dict_storage::DictStorage;
    use crate::storage::storage::FactFetchingContext;

    #[fixture]
    pub fn block_context() -> BlockContext {
        BlockContext { block_number: BlockNumber(0), ..BlockContext::create_for_account_testing() }
    }

    #[fixture]
    fn old_block_number_and_hash(block_context: BlockContext) -> (Felt252, Felt252) {
        (Felt252::from(block_context.block_number.0 - STORED_BLOCK_HASH_BUFFER), Felt252::from(66_u64))
    }

    #[fixture]
    fn execution_helper(
        block_context: BlockContext,
        old_block_number_and_hash: (Felt252, Felt252),
    ) -> ExecutionHelperWrapper {
        ExecutionHelperWrapper::new(ContractStorageMap::default(), vec![], &block_context, old_block_number_and_hash)
    }

    #[fixture]
    fn contract_address() -> Felt252 {
        Felt252::from(300)
    }

    #[fixture]
    fn execution_helper_with_storage(
        execution_helper: ExecutionHelperWrapper,
        contract_address: Felt252,
    ) -> ExecutionHelperWrapper {
        let storage = DictStorage::default();
        let mut ffc = FactFetchingContext::<_, PedersenHash>::new(storage);

        // Run async functions in a dedicated runtime to keep the test functions sync.
        // Otherwise, we run into "cannot spawn a runtime from another runtime" issues.
        let os_single_starknet_storage = execute_coroutine_threadsafe(async {
            let mut tree = PatriciaTree::empty_tree(&mut ffc, Height(251), StorageLeaf::empty()).await.unwrap();
            let modifications = vec![(BigUint::from(42u32), StorageLeaf::new(Felt252::from(8000)))];
            let mut facts = None;
            let tree = tree.update(&mut ffc, modifications, &mut facts).await.unwrap();
            // We pass the same tree as previous and updated tree as this is enough for the tests.
            OsSingleStarknetStorage::new(tree.clone(), tree, &vec![], ffc).await.unwrap()
        });

        {
            let storage_by_address = &mut execution_helper.execution_helper.as_ref().borrow_mut().storage_by_address;
            storage_by_address.insert(contract_address, os_single_starknet_storage);
        }

        execution_helper
    }

    #[rstest]
    #[ignore] // TODO: reenable when the stoge in execution helper is fixed
    fn test_cache_contract_storage_request_key(
        execution_helper_with_storage: ExecutionHelperWrapper,
        contract_address: Felt252,
    ) {
        let mut vm = VirtualMachine::new(false);
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.set_fp(5);

        let ap_tracking = ApTracking::new();
        let constants = HashMap::new();

        let ids_data = HashMap::from([
            (vars::ids::SYSCALL_PTR.to_string(), HintReference::new_simple(-3)),
            (vars::ids::CONTRACT_ADDRESS.to_string(), HintReference::new_simple(-2)),
            (vars::ids::VALUE.to_string(), HintReference::new_simple(-1)),
        ]);

        // Make ids.request point to (1, 0)
        insert_value_from_var_name(vars::ids::SYSCALL_PTR, (1, 0), &mut vm, &ids_data, &ap_tracking).unwrap();
        let key = Felt252::from(42);
        // request.key is at offset 1 in the structure
        vm.insert_value(Relocatable::from((1, 1)), key).unwrap();

        insert_value_from_var_name(vars::ids::CONTRACT_ADDRESS, contract_address, &mut vm, &ids_data, &ap_tracking)
            .unwrap();
        insert_value_from_var_name(vars::ids::VALUE, Felt252::from(8000), &mut vm, &ids_data, &ap_tracking).unwrap();

        let mut exec_scopes: ExecutionScopes = Default::default();
        exec_scopes.insert_value(vars::scopes::EXECUTION_HELPER, execution_helper_with_storage);

        // Just make sure that the hint goes through, all meaningful assertions are
        // in the implementation of the hint
        cache_contract_storage_request_key(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants)
            .expect("Hint should not fail");
    }

    #[test]
    fn test_enter_scope_new_node() {
        let preimage: Preimage = HashMap::new();
        let descent_map: DescentMap = HashMap::new();
        let patricia_skip_validation_runner: Option<PatriciaSkipValidationRunner> = None;
        let left_child = Some(TreeUpdate::Leaf(StorageLeaf::new(Felt252::ZERO)));
        let right_child: Option<TreeUpdate<StorageLeaf>> = None;
        let case = DecodeNodeCase::Left;

        let mut vm = VirtualMachine::new(false);
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.set_fp(1);

        let ids_data = HashMap::from([(vars::ids::CHILD_BIT.to_string(), HintReference::new_simple(-1))]);

        let mut exec_scopes: ExecutionScopes = Default::default();
        exec_scopes.insert_value(vars::scopes::PREIMAGE, preimage.clone());
        exec_scopes.insert_value(vars::scopes::DESCENT_MAP, descent_map.clone());
        exec_scopes
            .insert_value(vars::scopes::PATRICIA_SKIP_VALIDATION_RUNNER, patricia_skip_validation_runner.clone());
        exec_scopes.insert_value(vars::scopes::LEFT_CHILD, left_child.clone());
        exec_scopes.insert_value(vars::scopes::RIGHT_CHILD, right_child);
        exec_scopes.insert_value(vars::scopes::CASE, case);

        let ap_tracking = ApTracking::new();
        let constants = HashMap::new();

        enter_scope_new_node(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants)
            .expect("Hint should succeed");

        assert_eq!(exec_scopes.data.len(), 2, "A new scope should have been created");
        assert_eq!(exec_scopes.data[1].len(), 4, "The new scope should contain 4 items");
        assert_eq!(exec_scopes.get::<Preimage>(vars::scopes::PREIMAGE).unwrap(), preimage);
        assert_eq!(exec_scopes.get::<DescentMap>(vars::scopes::DESCENT_MAP).unwrap(), descent_map);
        assert_eq!(
            exec_scopes
                .get::<Option<PatriciaSkipValidationRunner>>(vars::scopes::PATRICIA_SKIP_VALIDATION_RUNNER)
                .unwrap(),
            patricia_skip_validation_runner
        );
        assert_eq!(exec_scopes.get::<UpdateTree<StorageLeaf>>(vars::scopes::NODE).unwrap(), left_child);

        let child_bit = get_integer_from_var_name(vars::ids::CHILD_BIT, &mut vm, &ids_data, &ap_tracking).unwrap();
        assert_eq!(child_bit, Felt252::ZERO);
    }

    #[rstest]
    #[ignore] // TODO: reenable when the stoge in execution helper is fixed
    fn test_write_syscall_result(mut execution_helper_with_storage: ExecutionHelperWrapper, contract_address: Felt252) {
        let mut vm = VirtualMachine::new(false);
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.set_fp(9);

        let ap_tracking = ApTracking::new();
        let constants = HashMap::new();

        let ids_data = HashMap::from([
            (vars::ids::SYSCALL_PTR.to_string(), HintReference::new_simple(-6)),
            (vars::ids::PREV_VALUE.to_string(), HintReference::new_simple(-5)),
            (vars::ids::CONTRACT_ADDRESS.to_string(), HintReference::new_simple(-4)),
            (vars::ids::CONTRACT_STATE_CHANGES.to_string(), HintReference::new_simple(-3)),
            (vars::ids::STATE_ENTRY.to_string(), HintReference::new_simple(-2)),
            (vars::ids::NEW_STATE_ENTRY.to_string(), HintReference::new_simple(-1)),
        ]);

        let key = Felt252::from(42);
        let value = Felt252::from(777);
        insert_value_from_var_name(vars::ids::SYSCALL_PTR, Relocatable::from((1, 0)), &mut vm, &ids_data, &ap_tracking)
            .unwrap();
        // syscall_ptr.address is at offset 1 in the structure
        vm.insert_value(Relocatable::from((1, 1)), key).unwrap();
        // syscall_ptr.value is at offset 1 in the structure
        vm.insert_value(Relocatable::from((1, 2)), value).unwrap();

        insert_value_from_var_name(vars::ids::CONTRACT_ADDRESS, contract_address, &mut vm, &ids_data, &ap_tracking)
            .unwrap();

        let mut exec_scopes: ExecutionScopes = Default::default();
        exec_scopes.insert_value(vars::scopes::EXECUTION_HELPER, execution_helper_with_storage.clone());

        // Prepare the dict manager for `get_state_entry()`
        let mut dict_manager = DictManager::new();
        let contract_state_changes = dict_manager
            .new_dict(&mut vm, HashMap::from([(contract_address.into(), MaybeRelocatable::from(123))]))
            .unwrap();
        exec_scopes.insert_value(vars::scopes::DICT_MANAGER, Rc::new(RefCell::new(dict_manager)));

        insert_value_from_var_name(
            vars::ids::CONTRACT_STATE_CHANGES,
            contract_state_changes,
            &mut vm,
            &ids_data,
            &ap_tracking,
        )
        .unwrap();

        // Just make sure that the hint goes through, all meaningful assertions are
        // in the implementation of the hint
        write_syscall_result_deprecated(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants)
            .expect("Hint should not fail");

        // Check that the storage was updated
        let prev_value = get_integer_from_var_name(vars::ids::PREV_VALUE, &mut vm, &ids_data, &ap_tracking).unwrap();
        assert_eq!(prev_value, Felt252::from(8000));
        let stored_value = execution_helper_with_storage.read_storage_for_address(contract_address, key).unwrap();
        assert_eq!(stored_value, Felt252::from(777));

        // Check the state entry
        let state_entry = get_integer_from_var_name(vars::ids::STATE_ENTRY, &mut vm, &ids_data, &ap_tracking).unwrap();
        assert_eq!(state_entry, Felt252::from(123));
    }

    #[test]
    fn test_set_fp_plus_4_to_tx_nonce() {
        let mut vm = VirtualMachine::new(false);
        vm.add_memory_segment();
        vm.add_memory_segment();

        let ap_tracking = ApTracking::new();
        let constants = HashMap::new();

        let ids_data = HashMap::new();

        // insert tx with a nonce
        let mut tx = InternalTransaction::default();
        tx.nonce = Some(Felt252::THREE);
        let mut exec_scopes: ExecutionScopes = Default::default();
        exec_scopes.insert_value(vars::scopes::TX, tx);

        set_fp_plus_4_to_tx_nonce(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants).unwrap();

        let address: Relocatable = (vm.get_fp() + 4usize).unwrap();
        let value = vm.get_integer(address).unwrap().into_owned();
        assert_eq!(value, Felt252::THREE);
    }
}

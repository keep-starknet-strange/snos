use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::vec::IntoIter;

use cairo_vm::hint_processor::builtin_hint_processor::dict_manager::Dictionary;
use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{
    get_integer_from_var_name, get_ptr_from_var_name, get_relocatable_from_var_name, insert_value_from_var_name,
    insert_value_into_ap,
};
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::{any_box, Felt252};
use indoc::indoc;

use crate::cairo_types::structs::ExecutionContext;
use crate::execution::deprecated_syscall_handler::DeprecatedOsSyscallHandlerWrapper;
use crate::execution::helper::ExecutionHelperWrapper;
use crate::execution::syscall_handler::OsSyscallHandlerWrapper;
use crate::hints::types::{DescentMap, PatriciaSkipValidationRunner, Preimage};
use crate::hints::vars;
use crate::hints::vars::ids::{SIGNATURE_LEN, SIGNATURE_START};
use crate::io::input::StarknetOsInput;
use crate::io::InternalTransaction;
use crate::starknet::starknet_storage::StorageLeaf;
use crate::starkware_utils::commitment_tree::update_tree::{DecodeNodeCase, UpdateTree};

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

fn get_state_entry(
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
        val.ok_or(HintError::CustomHint("State changes dictionnary should not be None".to_string().into_boxed_str()))?;

    insert_value_from_var_name("state_entry", val, vm, ids_data, ap_tracking)?;
    Ok(())
}

pub const GET_CONTRACT_ADDRESS_STATE_ENTRY: &str = indoc! {r##"
    # Fetch a state_entry in this hint and validate it in the update at the end
    # of this function.
    ids.state_entry = __dict_manager.get_dict(ids.contract_state_changes)[ids.contract_address]"##
};

pub const GET_CONTRACT_ADDRESS_STATE_ENTRY_2: &str = indoc! {r#"
	# Fetch a state_entry in this hint and validate it in the update that comes next.
	ids.state_entry = __dict_manager.get_dict(ids.contract_state_changes)[
	    ids.contract_address
	]"#
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

    get_state_entry(dict_ptr, key.into_owned(), vm, exec_scopes, ids_data, ap_tracking)?;

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
    get_state_entry(dict_ptr, key, vm, exec_scopes, ids_data, ap_tracking)?;

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
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let dict_ptr = get_ptr_from_var_name(vars::ids::CONTRACT_STATE_CHANGES, vm, ids_data, ap_tracking)?;
    let key = get_integer_from_var_name(vars::ids::BLOCK_HASH_CONTRACT_ADDRESS, vm, ids_data, ap_tracking)?;

    get_state_entry_and_set_new_state_entry(dict_ptr, key.into_owned(), vm, exec_scopes, ids_data, ap_tracking)?;

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

    get_state_entry_and_set_new_state_entry(dict_ptr, key.into_owned(), vm, exec_scopes, ids_data, ap_tracking)?;

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

pub const CACHE_CONTRACT_STORAGE: &str = indoc! {r#"
	# Make sure the value is cached (by reading it), to be used later on for the
	# commitment computation.
	value = execution_helper.storage_by_address[ids.contract_address].read(key=ids.request.key)
	assert ids.value == value, "Inconsistent storage value.""#
};

pub fn cache_contract_storage(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let mut execution_helper = exec_scopes.get::<ExecutionHelperWrapper>(vars::scopes::EXECUTION_HELPER)?;

    let contract_address =
        get_integer_from_var_name(vars::ids::CONTRACT_ADDRESS, vm, ids_data, ap_tracking)?.into_owned();
    let request_ptr = get_relocatable_from_var_name(vars::ids::REQUEST, vm, ids_data, ap_tracking)?;
    let key = vm.get_integer(&request_ptr + 1)?.into_owned();

    let value = execution_helper
        .read_storage_by_address(contract_address, key)
        .ok_or(HintError::CustomHint(format!("No storage found for contract {}", contract_address).into_boxed_str()))?;

    let ids_value = get_integer_from_var_name(vars::ids::VALUE, vm, ids_data, ap_tracking)?.into_owned();
    if ids_value != value {
        return Err(HintError::AssertionFailed(
            format!("Inconsistent storage value (expected {}, got {})", ids_value, value).into_boxed_str(),
        ));
    }

    exec_scopes.insert_value(vars::scopes::VALUE, value);

    Ok(())
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
            (vars::scopes::NODE.to_string(), any_box!(new_node)),
            (vars::scopes::PREIMAGE.to_string(), any_box!(preimage)),
            (vars::scopes::DESCENT_MAP.to_string(), any_box!(descent_map)),
            (vars::scopes::PATRICIA_SKIP_VALIDATION_RUNNER.to_string(), any_box!(patricia_skip_validation_runner)),
        ])
    };
    exec_scopes.enter_scope(new_scope);

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
    let nonce = tx.nonce.ok_or(HintError::AssertionFailed("tx.nonce should be set".into_string().into_boxed_str()))?;
    insert_value_into_ap(vm, Felt252::from(nonce))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use blockifier::block_context::BlockContext;
    use cairo_vm::types::relocatable::Relocatable;
    use num_bigint::BigUint;
    use rstest::{fixture, rstest};
    use starknet_api::block::BlockNumber;

    use super::*;
    use crate::crypto::pedersen::PedersenHash;
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
    fn execution_helper(block_context: BlockContext) -> ExecutionHelperWrapper {
        ExecutionHelperWrapper::new(vec![], &block_context)
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
        let patricia_tree = execute_coroutine_threadsafe(async {
            let mut tree = PatriciaTree::empty_tree(&mut ffc, Height(251), StorageLeaf::empty()).await.unwrap();
            let modifications = vec![(BigUint::from(42u32), StorageLeaf::new(Felt252::from(8000)))];
            let mut facts = None;
            tree.update(&mut ffc, modifications, &mut facts).await.unwrap()
        });
        let os_single_starknet_storage = OsSingleStarknetStorage::new::<StorageLeaf>(patricia_tree, ffc);

        {
            let storage_by_address = &mut execution_helper.execution_helper.as_ref().borrow_mut().storage_by_address;
            storage_by_address.insert(contract_address, os_single_starknet_storage);
        }

        execution_helper
    }

    #[rstest]
    fn test_cache_contract_storage(execution_helper_with_storage: ExecutionHelperWrapper, contract_address: Felt252) {
        let mut vm = VirtualMachine::new(false);
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.set_fp(4);

        let ap_tracking = ApTracking::new();
        let constants = HashMap::new();

        let ids_data = HashMap::from([
            (vars::ids::REQUEST.to_string(), HintReference::new_simple(-4)),
            (vars::ids::CONTRACT_ADDRESS.to_string(), HintReference::new_simple(-2)),
            (vars::ids::VALUE.to_string(), HintReference::new_simple(-1)),
        ]);

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
        cache_contract_storage(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants)
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
        assert_eq!(*child_bit, Felt252::ZERO);
    }
}

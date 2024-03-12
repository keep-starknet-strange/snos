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
use cairo_vm::types::relocatable::MaybeRelocatable;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use indoc::indoc;
use starknet_crypto::sign;

use crate::execution::deprecated_syscall_handler::DeprecatedOsSyscallHandlerWrapper;
use crate::execution::helper::ExecutionHelperWrapper;
use crate::io::input::StarknetOsInput;
use crate::io::InternalTransaction;

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
    exec_scopes.insert_value("transactions", transactions);
    exec_scopes.insert_value("tx", tx.clone());
    println!("tx.type: {}", tx.r#type);
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
        tx.hash_value, transaction_hash,
        "Computed transaction_hash is inconsistent with the hash in the transaction. Computed hash = {}, Expected \
         hash = {}.",
        transaction_hash, tx.hash_value
    );
    Ok(())
}

pub const ENTER_SCOPE_SYSCALL_HANDLER: &str = "vm_enter_scope({'syscall_handler': deprecated_syscall_handler})";
pub fn enter_scope_syscall_handler(
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
    let dict_manager: Box<dyn Any> = Box::new(exec_scopes.get_dict_manager()?);
    exec_scopes.enter_scope(HashMap::from_iter([
        (String::from("__deprecated_class_hashes"), deprecated_class_hashes),
        (String::from("transactions"), transactions),
        (String::from("execution_helper"), execution_helper),
        (String::from("deprecated_syscall_handler"), deprecated_syscall_handler),
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

// copilot prompt:
// implement rust hints for the following python hints:
// - %{ tx.max_fee if tx.version < 3 else 0 %},
// - %{ 0 if tx.nonce is None else tx.nonce %},
// - %{ 0 if tx.version < 3 else tx.tip %},
// - %{ 0 if tx.version < 3 else len(tx.resource_bounds) %},
// - %{ 0 if tx.version < 3 else len(tx.paymaster_data) %},
// - %{ 0 if tx.version < 3 else segments.gen_arg(tx.paymaster_data) %}, felt*
// - %{ 0 if tx.version < 3 else tx.nonce_data_availability_mode %}
// - %{ 0 if tx.version < 3 else tx.fee_data_availability_mode %}
// - %{ 0 if tx.version < 3 else len(tx.account_deployment_data) %}
// use exact same logic as in the python hints

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

    let max_fee = Felt252::ZERO;

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
    let signature = tx.signature.ok_or(
        HintError::CustomHint("tx.signature is none".to_owned().into_boxed_str())
    )?;
    let signature_start_base = vm.add_memory_segment();
    let signature = signature.iter().map(|f| MaybeRelocatable::Int(*f)).collect();
    vm.load_data(signature_start_base, &signature)?;

    insert_value_from_var_name("signature_start", signature_start_base, vm, &ids_data, &ap_tracking)?;
    insert_value_from_var_name("signature_len", signature.len(), vm, &ids_data, &ap_tracking)?;

    Ok(())
}
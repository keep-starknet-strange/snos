use std::collections::HashMap;

use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{
    get_integer_from_var_name, get_ptr_from_var_name, get_relocatable_from_var_name, insert_value_from_var_name,
};
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use indoc::indoc;

use crate::cairo_types::contract_class::ContractClassComponentHashes;
use crate::cairo_types::structs::ExecutionContext;
use crate::execution::helper::ExecutionHelperWrapper;
use crate::execution::syscall_handler::OsSyscallHandlerWrapper;
use crate::hints::vars;
use crate::io::InternalTransaction;
use crate::starknet::starknet_storage::PerContractStorage;
use crate::utils::execute_coroutine;

pub const START_TX_VALIDATE_DECLARE_EXECUTION_CONTEXT: &str = indoc! {r#"
    execution_helper.start_tx(
        tx_info_ptr=ids.validate_declare_execution_context.deprecated_tx_info.address_
    )"#
};
pub async fn start_tx_validate_declare_execution_context_async<PCS>(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), HintError>
where
    PCS: PerContractStorage + 'static,
{
    let execution_helper: ExecutionHelperWrapper<PCS> = exec_scopes.get(vars::scopes::EXECUTION_HELPER)?;
    let execution_context_ptr =
        get_relocatable_from_var_name(vars::ids::VALIDATE_DECLARE_EXECUTION_CONTEXT, vm, ids_data, ap_tracking)?;
    let deprecated_tx_info_ptr = (execution_context_ptr + ExecutionContext::deprecated_tx_info_offset())?;

    execution_helper.start_tx(Some(deprecated_tx_info_ptr)).await;

    Ok(())
}

pub fn start_tx_validate_declare_execution_context<PCS>(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError>
where
    PCS: PerContractStorage + 'static,
{
    execute_coroutine(start_tx_validate_declare_execution_context_async::<PCS>(vm, exec_scopes, ids_data, ap_tracking))?
}

pub const SET_SHA256_SEGMENT_IN_SYSCALL_HANDLER: &str = indoc! {r#"syscall_handler.sha256_segment = ids.sha256_ptr"#};

pub async fn set_sha256_segment_in_syscall_handler_async<PCS>(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), HintError>
where
    PCS: PerContractStorage + 'static,
{
    let sha256_ptr = get_ptr_from_var_name(vars::ids::SHA256_PTR, vm, ids_data, ap_tracking)?;

    let syscall_handler: OsSyscallHandlerWrapper<PCS> = exec_scopes.get(vars::scopes::SYSCALL_HANDLER)?;
    syscall_handler.set_sha256_segment(sha256_ptr).await;

    Ok(())
}

pub fn set_sha256_segment_in_syscall_handler<PCS>(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError>
where
    PCS: PerContractStorage + 'static,
{
    execute_coroutine(set_sha256_segment_in_syscall_handler_async::<PCS>(vm, exec_scopes, ids_data, ap_tracking))?
}

pub const LOG_REMAINING_TXS: &str =
    indoc! {r#"print(f"execute_transactions_inner: {ids.n_txs} transactions remaining.")"#};

pub fn log_remaining_txs(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let n_txs = get_integer_from_var_name(vars::ids::N_TXS, vm, ids_data, ap_tracking)?;
    log::debug!("{} transactions remaining.", n_txs);

    Ok(())
}

#[rustfmt::skip]
pub const FILL_HOLES_IN_RC96_SEGMENT: &str = indoc! {r#"
rc96_ptr = ids.range_check96_ptr
segment_size = rc96_ptr.offset
base = rc96_ptr - segment_size

for i in range(segment_size):
    memory.setdefault(base + i, 0)"#};

pub fn fill_holes_in_rc96_segment(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let rc96_ptr = get_ptr_from_var_name(vars::ids::RANGE_CHECK96_PTR, vm, ids_data, ap_tracking)?;
    let segment_size = rc96_ptr.offset;
    let base = Relocatable::from((rc96_ptr.segment_index, 0));

    for i in 0..segment_size {
        let address = (base + i)?;
        if vm.get_maybe(&address).is_none() {
            vm.insert_value(address, Felt252::ZERO)?;
        }
    }

    Ok(())
}

#[allow(unused)]
pub const SET_COMPONENT_HASHES: &str = indoc! {r#"
class_component_hashes = component_hashes[tx.class_hash]
assert (
    len(class_component_hashes) == ids.ContractClassComponentHashes.SIZE
), "Wrong number of class component hashes."
ids.contract_class_component_hashes = segments.gen_arg(class_component_hashes)"#
};

pub fn set_component_hashes(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let tx: &InternalTransaction = exec_scopes.get_ref(vars::scopes::TX)?;
    let tx_class_hash =
        tx.class_hash.ok_or(HintError::CustomHint("tx.class_hash is None".to_string().into_boxed_str()))?;
    let component_hashes: &HashMap<Felt252, Vec<Felt252>> = exec_scopes.get_ref(vars::scopes::COMPONENT_HASHES)?;

    let class_component_hashes = component_hashes.get(&tx_class_hash).ok_or_else(|| {
        HintError::CustomHint(
            format!("No component hashes found for class {}", tx_class_hash.to_hex_string()).into_boxed_str(),
        )
    })?;

    if class_component_hashes.len() != ContractClassComponentHashes::cairo_size() {
        return Err(HintError::AssertionFailed(
            format!(
                "Wrong number of class component hashes: got {}, expected {}",
                ContractClassComponentHashes::cairo_size(),
                class_component_hashes.len()
            )
            .into_boxed_str(),
        ));
    }

    let class_component_hashes: Vec<_> = class_component_hashes.iter().map(|x| MaybeRelocatable::from(x)).collect();

    let arg_segment = vm.gen_arg(&class_component_hashes)?;
    insert_value_from_var_name(vars::ids::CONTRACT_CLASS_COMPONENT_HASHES, arg_segment, vm, ids_data, ap_tracking)?;

    Ok(())
}

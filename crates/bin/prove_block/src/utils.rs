use std::collections::{HashMap, HashSet};

use blockifier::execution::call_info::CallInfo;
use blockifier::transaction::objects::TransactionExecutionInfo;
use cairo_vm::Felt252;
use starknet::core::types::{ExecuteInvocation, FunctionInvocation, TransactionTrace, TransactionTraceWithHash};
use starknet_api::core::ContractAddress;
use starknet_api::state::StorageKey;

/// Receives the transaction traces of a given block
/// And extract the contracts addresses that where subcalled
// TODO: check if we can handle this just reexecuting tx using blockifier
//
// Returns a HashSet of contracts and a HashSet of classes encountered along the way.
pub(crate) fn get_subcalled_contracts_from_tx_traces(
    traces: &[TransactionTraceWithHash],
) -> (HashSet<Felt252>, HashSet<Felt252>) {
    let mut contracts_subcalled: HashSet<Felt252> = HashSet::new();
    let mut classes_subcalled: HashSet<Felt252> = HashSet::new();
    for trace in traces {
        match &trace.trace_root {
            TransactionTrace::Invoke(invoke_trace) => {
                if let Some(inv) = &invoke_trace.validate_invocation {
                    process_function_invocations(inv, &mut contracts_subcalled, &mut classes_subcalled);
                }
                if let ExecuteInvocation::Success(inv) = &invoke_trace.execute_invocation {
                    process_function_invocations(inv, &mut contracts_subcalled, &mut classes_subcalled);
                }
                if let Some(inv) = &invoke_trace.fee_transfer_invocation {
                    process_function_invocations(inv, &mut contracts_subcalled, &mut classes_subcalled);
                }
            }
            TransactionTrace::L1Handler(l1handler_trace) => {
                process_function_invocations(
                    &l1handler_trace.function_invocation,
                    &mut contracts_subcalled,
                    &mut classes_subcalled,
                );
            }

            _ => unimplemented!("process other txn traces"),
        }
    }
    (contracts_subcalled, classes_subcalled)
}

/// Utility to extract all contract address in a nested call structure. Any given call can have
/// nested calls, creating a tree structure of calls, so this fn traverses this structure and
/// returns a set of all contracts encountered along the way.
fn process_function_invocations(
    inv: &FunctionInvocation,
    contracts: &mut HashSet<Felt252>,
    classes: &mut HashSet<Felt252>,
) {
    contracts.insert(inv.contract_address);
    classes.insert(inv.class_hash);
    for call in &inv.calls {
        process_function_invocations(call, contracts, classes);
    }
}

/// Utility to get all the accesed keys from TxexecutionInfo resulted from
/// Reexecuting all block tx using blockifier
/// We need this as the OS require proofs for all the accessed values
pub(crate) fn get_all_accessed_keys(
    tx_execution_infos: &[TransactionExecutionInfo],
) -> HashMap<ContractAddress, HashSet<StorageKey>> {
    let mut accessed_keys_by_address: HashMap<ContractAddress, HashSet<StorageKey>> = HashMap::new();

    for tx_execution_info in tx_execution_infos {
        let accessed_keys_in_tx = get_accessed_keys_in_tx(tx_execution_info);
        for (contract_address, storage_keys) in accessed_keys_in_tx {
            accessed_keys_by_address.entry(contract_address).or_default().extend(storage_keys);
        }
    }

    accessed_keys_by_address
}

fn get_accessed_keys_in_tx(
    tx_execution_info: &TransactionExecutionInfo,
) -> HashMap<ContractAddress, HashSet<StorageKey>> {
    let mut accessed_keys_by_address: HashMap<ContractAddress, HashSet<StorageKey>> = HashMap::new();

    for call_info in [
        &tx_execution_info.validate_call_info,
        &tx_execution_info.execute_call_info,
        &tx_execution_info.fee_transfer_call_info,
    ]
    .into_iter()
    .flatten()
    {
        let call_storage_keys = get_accessed_storage_keys(call_info);
        for (contract_address, storage_keys) in call_storage_keys {
            accessed_keys_by_address.entry(contract_address).or_default().extend(storage_keys);
        }
    }

    accessed_keys_by_address
}

fn get_accessed_storage_keys(call_info: &CallInfo) -> HashMap<ContractAddress, HashSet<StorageKey>> {
    let mut accessed_keys_by_address: HashMap<ContractAddress, HashSet<StorageKey>> = HashMap::new();

    let contract_address = &call_info.call.storage_address;
    accessed_keys_by_address
        .entry(*contract_address)
        .or_default()
        .extend(call_info.accessed_storage_keys.iter().copied());

    let storage_keys: Vec<_> = call_info.accessed_storage_keys.iter().map(|x| x.key().to_hex_string()).collect();
    log::debug!("{}: {:?}", contract_address.to_string(), storage_keys);

    for inner_call in &call_info.inner_calls {
        let inner_call_storage_keys = get_accessed_storage_keys(inner_call);
        for (contract_address, storage_keys) in inner_call_storage_keys {
            accessed_keys_by_address.entry(contract_address).or_default().extend(storage_keys);
        }
    }

    accessed_keys_by_address
}

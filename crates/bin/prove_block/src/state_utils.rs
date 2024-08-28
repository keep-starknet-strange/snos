use std::collections::{HashMap, HashSet};

use cairo_vm::Felt252;
use starknet::core::types::{BlockId, MaybePendingStateUpdate, StateDiff};
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Provider};
use starknet_os::io::InternalTransaction;

use crate::utils::get_subcalled_contracts_from_tx_traces;

#[derive(Clone)]
pub struct FormattedStateUpdate {
    // TODO: Use more descriptive types
    #[allow(unused)]
    pub address_to_class_hash: HashMap<Felt252, Felt252>,
    #[allow(unused)]
    pub address_to_nonce: HashMap<Felt252, Felt252>,
    pub class_hash_to_compiled_class_hash: HashMap<Felt252, Felt252>,
    #[allow(unused)]
    pub storage_updates: HashMap<Felt252, HashMap<Felt252, Felt252>>,
    pub accessed_addresses: HashSet<Felt252>,
}

/// Given the `block_id` of the target block to prove, it:
/// - Fetches the state update using the `starknet_getStateUpdate` RPC call.
/// - Fetches block transaction traces to obtain all accessed contract addresses in that block.
/// - Formats the RPC state updates to be "SharedState compatible."
/// - Consolidates that information into a `FormattedStateUpdate`.
pub(crate) async fn get_processed_state_update(
    provider: &JsonRpcClient<HttpTransport>,
    block_id: BlockId,
    transactions: &[InternalTransaction],
) -> FormattedStateUpdate {
    let state_update = match provider.get_state_update(block_id).await.expect("Failed to get state update") {
        MaybePendingStateUpdate::Update(update) => update,
        MaybePendingStateUpdate::PendingUpdate(_) => {
            panic!("Block is still pending!")
        }
    };
    let state_diff = state_update.state_diff;

    // Extract other contracts used in our block from the block trace
    // We need this to get all the class hashes used and correctly feed address_to_class_hash
    let traces = provider.trace_block_transactions(block_id).await.expect("Failed to get block tx traces");
    let contracts_subcalled: HashSet<Felt252> = get_subcalled_contracts_from_tx_traces(&traces);

    let address_to_class_hash: HashMap<Felt252, Felt252> =
        format_deployed_contracts(&state_diff, &contracts_subcalled, provider, block_id).await;
    let address_to_nonce: HashMap<Felt252, Felt252> = format_state_update_nonces(&state_diff, transactions);
    let class_hash_to_compiled_class_hash: HashMap<Felt252, Felt252> = format_declared_classes(&state_diff);
    let storage_updates: HashMap<Felt252, HashMap<Felt252, Felt252>> = format_storage_updates(&state_diff);

    // Collect keys without consuming the HashMaps by borrowing and cloning the keys
    let accessed_addresses: HashSet<Felt252> = address_to_class_hash
        .keys()
        .copied()
        .chain(address_to_nonce.keys().cloned())
        .chain(storage_updates.keys().cloned())
        .collect();

    FormattedStateUpdate {
        address_to_class_hash,
        address_to_nonce,
        class_hash_to_compiled_class_hash,
        storage_updates,
        accessed_addresses,
    }
}

/// Format StateDiff's NonceUpdate to a HashMap<contract_address, nonce>
fn format_state_update_nonces(
    state_diff: &StateDiff,
    transactions: &[InternalTransaction],
) -> HashMap<Felt252, Felt252> {
    let address_to_nonce: HashMap<Felt252, Felt252> = state_diff
        .nonces
        .iter()
        .map(|nonce_update| {
            // derive original nonce
            // TODO: understand what is going on here XD
            let num_nonce_bumps =
                Felt252::from(transactions.iter().fold(0, |acc, tx| {
                    acc + if tx.sender_address == Some(nonce_update.contract_address) { 1 } else { 0 }
                }));
            assert!(nonce_update.nonce > num_nonce_bumps);
            let previous_nonce = nonce_update.nonce - num_nonce_bumps;
            (nonce_update.contract_address, previous_nonce)
        })
        .collect();
    address_to_nonce
}

/// Format StateDiff's DeclaredClassItem to a HashMap<class_hash, compiled_class_hash>
fn format_declared_classes(state_diff: &StateDiff) -> HashMap<Felt252, Felt252> {
    let class_hash_to_compiled_class_hash =
        state_diff.declared_classes.iter().map(|class| (class.class_hash, class.compiled_class_hash)).collect();
    class_hash_to_compiled_class_hash
}

/// Format StateDiff's ContractStorageDiffItem to a HashMap<contract_address, HashMap<key, value>>
fn format_storage_updates(state_diff: &StateDiff) -> HashMap<Felt252, HashMap<Felt252, Felt252>> {
    let storage_updates: HashMap<Felt252, HashMap<Felt252, Felt252>> = state_diff
        .storage_diffs
        .iter()
        .map(|diffs| {
            let storage_entries = diffs.storage_entries.iter().map(|e| (e.key, e.value)).collect();
            (diffs.address, storage_entries)
        })
        .collect();
    storage_updates
}

/// Formats `StateDiff`'s `DeployedContractItem` into a `HashMap<contract_address, class_hash>`.
/// It also takes all subcalled contract addresses (which may or may not have diffs)
/// and fetches the class hash if it wasn't included in the `StateDiff`.
async fn format_deployed_contracts(
    state_diff: &StateDiff,
    contracts_subcalled: &HashSet<Felt252>,
    provider: &JsonRpcClient<HttpTransport>,
    block_id: BlockId,
) -> HashMap<Felt252, Felt252> {
    let mut address_to_class_hash: HashMap<_, _> =
        state_diff.deployed_contracts.iter().map(|contract| (contract.address, contract.class_hash)).collect();

    for address in contracts_subcalled {
        if !address_to_class_hash.contains_key(address) {
            let class_hash = provider.get_class_hash_at(block_id, address).await.unwrap();
            address_to_class_hash.insert(*address, class_hash);
        }
    }
    address_to_class_hash
}

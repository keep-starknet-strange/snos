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
    pub class_hash_to_compiled_class_hash: HashMap<Felt252, Felt252>,
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

    let accessed_address: HashSet<Felt252> = HashSet::new(); 
    let address_to_class_hash: HashSet<Felt252> = get_deployed_contract_address(&state_diff);
    let address_to_nonce: HashSet<Felt252> = get_nonce_updated_contract_address(&state_diff);
    let class_hash_to_compiled_class_hash: HashMap<Felt252, Felt252> = format_declared_classes(&state_diff);
    let storage_updates: HashSet<Felt252> = get_storage_updated_contract_address(&state_diff);

    // Collect keys without consuming the HashMaps by borrowing and cloning the keys
    accessed_address.extend(address_to_nonce);
    accessed_address.extend(storage_updates);
    
    let accessed_addresses = contracts_subcalled;

    FormattedStateUpdate {
        class_hash_to_compiled_class_hash,
        accessed_addresses,
    }
}

/// Format StateDiff's NonceUpdate to a HashMap<contract_address, nonce>
fn get_nonce_updated_contract_address(
    state_diff: &StateDiff,
) -> HashSet<Felt252> {
    let address_updated = state_diff
        .nonces
        .iter()
        .map(|nonce_update| nonce_update.contract_address)
        .collect();
    address_updated
}

/// Format StateDiff's DeclaredClassItem to a HashMap<class_hash, compiled_class_hash>
fn format_declared_classes(state_diff: &StateDiff) -> HashMap<Felt252, Felt252> {
    let class_hash_to_compiled_class_hash =
        state_diff.declared_classes.iter().map(|class| (class.class_hash, class.compiled_class_hash)).collect();
    class_hash_to_compiled_class_hash
}

/// Format StateDiff's ContractStorageDiffItem to a HashMap<contract_address, HashMap<key, value>>
fn get_storage_updated_contract_address(state_diff: &StateDiff) -> HashSet<Felt252> {
    let storage_updates: HashSet<Felt252> = state_diff
        .storage_diffs
        .iter()
        .map(|diffs| diffs.address)
        .collect();
    storage_updates
}

/// Formats `StateDiff`'s `DeployedContractItem` into a `HashMap<contract_address, class_hash>`.
/// It also takes all subcalled contract addresses (which may or may not have diffs)
/// and fetches the class hash if it wasn't included in the `StateDiff`.
async fn get_deployed_contract_address(
    state_diff: &StateDiff,
) -> HashSet<Felt252> {
    let address_to_class_hash =
        state_diff.deployed_contracts.iter().map(|contract| contract.address).collect();
    address_to_class_hash
}

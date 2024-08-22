use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::hash::Hash;

use cairo_vm::Felt252;
use pathfinder_crypto::Felt;
use starknet::core::types::{BlockId, MaybePendingStateUpdate, StateDiff};
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Provider};
use starknet_os::crypto::pedersen::PedersenHash;
use starknet_os::io::InternalTransaction;
use starknet_os::starknet::business_logic::fact_state::contract_class_objects::{
    get_ffc_for_contract_class_facts, ContractClassLeaf,
};
use starknet_os::starknet::business_logic::fact_state::contract_state_objects::ContractState;
use starknet_os::starknet::business_logic::fact_state::state::SharedState;
use starknet_os::starkware_utils::commitment_tree::base_types::TreeIndex;
// trait for Patricia Tree
use starknet_os::starkware_utils::commitment_tree::binary_fact_tree::BinaryFactTree;
use starknet_os::storage::storage::FactFetchingContext;

use crate::rpc_utils::{CachedRpcStorage, RpcStorage};
use crate::utils::get_subcalled_contracts_from_tx_traces;

struct ProcessedStateUpdate {
    // TODO: Use more descriptive types
    address_to_class_hash: HashMap<Felt252, Felt252>,
    address_to_nonce: HashMap<Felt252, Felt252>,
    class_hash_to_compiled_class_hash: HashMap<Felt252, Felt252>,
    storage_updates: HashMap<Felt252, HashMap<Felt252, Felt252>>
}

// build state representing the end of the previous block on which the current
// block can be built.
// inspiration: TestSharedState::apply_state_updates_starknet_api()
//
// Returns:
// * a set of all contracts accessed
// * a SharedState object representing storage for the changes provided
pub(crate) async fn build_initial_state(
    provider: &JsonRpcClient<HttpTransport>,
    block_number: u64,
    address_to_class_hash: HashMap<Felt252, Felt252>,
    address_to_nonce: HashMap<Felt252, Felt252>,
    class_hash_to_compiled_class_hash: HashMap<Felt252, Felt252>,
    storage_updates: HashMap<Felt252, HashMap<Felt252, Felt252>>,
) -> Result<(HashSet<Felt252>, SharedState<CachedRpcStorage, PedersenHash>), Box<dyn Error>> {
    // initialize storage. We use a CachedStorage with a RcpStorage as the main storage, meaning
    // that a DictStorage serves as the cache layer and we will use Pathfinder RPC for cache misses
    let rpc_storage = RpcStorage::new();
    let cached_storage = CachedRpcStorage::new(Default::default(), rpc_storage);
    let ffc: FactFetchingContext<CachedRpcStorage, PedersenHash> = FactFetchingContext::new(cached_storage);
    let shared_state = SharedState::empty(ffc).await?;

    let accessed_addresses_felts: HashSet<_> =
        address_to_class_hash.keys().chain(address_to_nonce.keys()).chain(storage_updates.keys()).collect();
    let accessed_addresses: Vec<TreeIndex> = accessed_addresses_felts.iter().map(|x| x.to_biguint()).collect();

    let mut facts = None;
    let mut ffc = shared_state.ffc;
    let mut empty_contract_states: HashMap<TreeIndex, ContractState> =
        shared_state.contract_states.get_leaves(&mut ffc, &accessed_addresses, &mut facts).await?;

    // Update contract storage roots with cached changes.
    let empty_updates = HashMap::new();
    let mut updated_contract_states: HashMap<num_bigint::BigUint, ContractState> = HashMap::new();
    for address in accessed_addresses_felts {
        // unwrap() is safe as an entry is guaranteed to be present with `get_leaves()`.
        let tree_index = address.to_biguint();
        let updates = storage_updates.get(address).unwrap_or(&empty_updates);
        let nonce = address_to_nonce.get(address).cloned();
        let mut class_hash = address_to_class_hash.get(address).cloned();
        if class_hash.is_none() {
            let resp = provider.get_class_hash_at(BlockId::Number(block_number), address).await;
            class_hash = if let Ok(class_hash) = resp { Some(class_hash) } else { Some(Felt252::ZERO) };
        }
        let updated_contract_state =
            empty_contract_states.remove(&tree_index).unwrap().update(&mut ffc, updates, nonce, class_hash).await?;

        updated_contract_states.insert(tree_index, updated_contract_state);
    }

    // Apply contract changes on global root.
    log::debug!("Updating contract state tree with {} modifications...", accessed_addresses.len());
    let global_state_modifications: Vec<_> = updated_contract_states.into_iter().collect();

    let updated_global_contract_root =
        shared_state.contract_states.update(&mut ffc, global_state_modifications, &mut facts).await?;

    let mut ffc_for_contract_class = get_ffc_for_contract_class_facts(&ffc);

    let updated_contract_classes = match shared_state.contract_classes {
        Some(tree) => {
            log::debug!(
                "Updating contract class tree with {} modifications...",
                class_hash_to_compiled_class_hash.len()
            );
            let modifications: Vec<_> = class_hash_to_compiled_class_hash
                .into_iter()
                .map(|(key, value)| (key.to_biguint(), ContractClassLeaf::create(value)))
                .collect();
            Some(tree.update(&mut ffc_for_contract_class, modifications, &mut facts).await?)
        }
        None => {
            assert_eq!(class_hash_to_compiled_class_hash.len(), 0, "contract_classes must be concrete before update.");
            None
        }
    };

    let accessed_addresses: HashSet<_> = accessed_addresses.into_iter().map(Felt252::from).collect();

    Ok((
        accessed_addresses,
        SharedState {
            contract_states: updated_global_contract_root,
            contract_classes: updated_contract_classes,
            ffc,
            ffc_for_class_hash: ffc_for_contract_class,
            contract_addresses: Default::default(),
        },
    ))
}

async fn update_empty_state_with_block_incoming_changes(empty_contract_states: &HashMap<TreeIndex, ContractState>) -> Result<HashMap<TreeIndex, ContractState>, Box<dyn Error>> {
        // Update contract storage roots with cached changes.
        let empty_updates = HashMap::new();
        let mut updated_contract_states: HashMap<num_bigint::BigUint, ContractState> = HashMap::new();
        for address in accessed_addresses_felts {
            // unwrap() is safe as an entry is guaranteed to be present with `get_leaves()`.
            let tree_index = address.to_biguint();
            let updates = storage_updates.get(address).unwrap_or(&empty_updates);
            let nonce = address_to_nonce.get(address).cloned();
            let mut class_hash = address_to_class_hash.get(address).cloned();
            if class_hash.is_none() {
                let resp = provider.get_class_hash_at(BlockId::Number(block_number), address).await;
                class_hash = if let Ok(class_hash) = resp { Some(class_hash) } else { Some(Felt252::ZERO) };
            }
            let updated_contract_state =
                empty_contract_states.remove(&tree_index).unwrap().update(&mut ffc, updates, nonce, class_hash).await?;
    
            updated_contract_states.insert(tree_index, updated_contract_state);
        }
        Ok(updated_contract_states)
}

async fn get_processed_state_update(provider: &JsonRpcClient<HttpTransport>, block_id: BlockId, transactions: Vec<InternalTransaction>) -> ProcessedStateUpdate {
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

    let address_to_class_hash = process_deployed_contracts(&state_diff, &contracts_subcalled, provider, block_id).await;
    let address_to_nonce = process_state_update_nonces(&state_diff, &transactions);
    let class_hash_to_compiled_class_hash = process_declared_classes(&state_diff);
    let storage_updates = process_storage_updates(&state_diff);

    ProcessedStateUpdate {
        address_to_class_hash,
        address_to_nonce,
        class_hash_to_compiled_class_hash,
        storage_updates
    }
}

fn process_state_update_nonces(state_diff: &StateDiff, transactions: &[InternalTransaction]) -> HashMap<Felt252, Felt252> {
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

fn process_declared_classes(state_diff: &StateDiff) -> HashMap<Felt252, Felt252> {
    let class_hash_to_compiled_class_hash = state_diff 
        .declared_classes
        .iter()
        .map(|class| (class.class_hash, class.compiled_class_hash))
        .collect(); 
    class_hash_to_compiled_class_hash
}

fn process_storage_updates(state_diff: &StateDiff) -> HashMap<Felt252, HashMap<Felt252, Felt252>> {
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

async fn process_deployed_contracts(state_diff: &StateDiff, contracts_subcalled: &HashSet<Felt252>, provider: &JsonRpcClient<HttpTransport>, block_id: BlockId) -> HashMap<Felt252, Felt252> {
    let mut address_to_class_hash: HashMap<_, _> = state_diff
        .deployed_contracts
        .iter()
        .map(|contract| (contract.address, contract.class_hash))
        .collect();

    for address in contracts_subcalled {
        if !address_to_class_hash.contains_key(address) {
            let class_hash = provider.get_class_hash_at(block_id, address).await.unwrap();
            address_to_class_hash.insert(*address, class_hash);
        }
    }
    address_to_class_hash
}
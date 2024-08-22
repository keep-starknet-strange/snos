use std::collections::{HashMap, HashSet};
use std::error::Error;

use cairo_vm::Felt252;
use starknet::core::types::BlockId;
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Provider};
use starknet_os::crypto::pedersen::PedersenHash;
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
    let mut current_contract_states: HashMap<TreeIndex, ContractState> =
        shared_state.contract_states.get_leaves(&mut ffc, &accessed_addresses, &mut facts).await?;

    // Update contract storage roots with cached changes.
    let empty_updates = HashMap::new();
    let mut updated_contract_states = HashMap::new();
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
            current_contract_states.remove(&tree_index).unwrap().update(&mut ffc, updates, nonce, class_hash).await?;

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

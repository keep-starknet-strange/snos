use futures::stream::{self, StreamExt};
use log::info;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use starknet::core::types::BlockId;
use starknet::providers::Provider;
use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::state::StorageKey;
use starknet_os::io::os_input::CachedStateInput;
use starknet_types_core::felt::Felt;
use std::collections::{HashMap, HashSet};

use crate::constants::{MAX_CONCURRENT_GET_CLASS_REQUESTS, MAX_CONCURRENT_GET_STORAGE_AT_REQUESTS};
use rpc_client::state_reader::compute_compiled_class_hash;
use rpc_client::RpcClient;

// Constants for special contract addresses
const BLOCK_HASH_CONTRACT_ADDRESS: Felt = Felt::ONE;
const ALIAS_CONTRACT_ADDRESS: Felt = Felt::TWO;

// Initial storage value for alias contract at genesis (0x80 = 128 in decimal)
// This value represents the initial state for stateful compression.
// Reference: https://community.starknet.io/t/starknet-v0-13-4-pre-release-notes/115257#p-2358763-stateful-compression-11
const GENESIS_ALIAS_CONTRACT_STORAGE_VALUE: Felt = Felt::from_hex_unchecked("0x80");

/// Creates an empty cached state for block 0 (genesis block).
///
/// Block 0 has no previous state, but we need to initialize the alias
/// contract with its initial storage value.
fn create_genesis_cached_state() -> Result<CachedStateInput, Box<dyn std::error::Error + Send + Sync>> {
    info!("Creating genesis block cached state");

    // The alias contract (address 0x2) needs initial storage
    let alias_contract_address = ContractAddress::try_from(ALIAS_CONTRACT_ADDRESS)?;
    let alias_storage_key = StorageKey::try_from(Felt::ZERO)?;
    let alias_storage_value = GENESIS_ALIAS_CONTRACT_STORAGE_VALUE;

    Ok(CachedStateInput {
        storage: HashMap::from([(alias_contract_address, HashMap::from([(alias_storage_key, alias_storage_value)]))]),
        address_to_class_hash: HashMap::from([(alias_contract_address, ClassHash(Felt::ZERO))]),
        address_to_nonce: HashMap::from([(alias_contract_address, Nonce(Felt::ZERO))]),
        class_hash_to_compiled_class_hash: HashMap::new(),
    })
}

pub async fn generate_cached_state_input(
    rpc_client: &RpcClient,
    block_number: &u64,
    accessed_addresses: &HashSet<ContractAddress>,
    accessed_classes: &HashSet<ClassHash>,
    accessed_keys_by_address: &HashMap<ContractAddress, HashSet<StorageKey>>,
) -> Result<CachedStateInput, Box<dyn std::error::Error + Send + Sync>> {
    // For block 0, there's no previous state, so return genesis cached state
    if *block_number == 0 {
        return create_genesis_cached_state();
    }

    // For all other blocks, read state from the previous block (block_number - 1)
    let block_id = BlockId::Number(block_number - 1);
    info!("Generating cached state input for block {:?} (reading from previous block)", block_id);

    let mut storage = HashMap::new();
    let mut address_to_class_hash = HashMap::new();
    let mut address_to_nonce = HashMap::new();
    let mut class_hash_to_compiled_class_hash = HashMap::new();

    // Combine all addresses from accessed_addresses and accessed_keys_by_address
    let mut all_addresses: HashSet<ContractAddress> = accessed_addresses.clone();
    all_addresses.extend(accessed_keys_by_address.keys());

    info!("Processing {} total addresses...", all_addresses.len());

    // 1. Fill storage using accessed keys
    // Flatten all (contract_address, storage_key) pairs for concurrent fetching
    let storage_requests: Vec<(ContractAddress, StorageKey)> = accessed_keys_by_address
        .iter()
        .flat_map(|(contract_address, storage_keys)| {
            storage_keys.iter().map(move |storage_key| (*contract_address, *storage_key))
        })
        .collect();

    info!(
        "Fetching {} storage values across {} contracts with max {} concurrent requests",
        storage_requests.len(),
        accessed_keys_by_address.len(),
        MAX_CONCURRENT_GET_STORAGE_AT_REQUESTS
    );

    // Fetch all storage values concurrently
    let storage_results: Vec<(ContractAddress, StorageKey, Felt)> = stream::iter(storage_requests)
        .map(|(contract_address, storage_key)| async move {
            let storage_value = rpc_client
                .starknet_rpc()
                .get_storage_at(*contract_address.key(), *storage_key.0.key(), block_id)
                .await
                .unwrap_or(Felt::ZERO); // Default to zero if not found

            (contract_address, storage_key, storage_value)
        })
        .buffer_unordered(MAX_CONCURRENT_GET_STORAGE_AT_REQUESTS)
        .collect()
        .await;

    // Reconstruct the nested HashMap structure from results
    for (contract_address, storage_key, storage_value) in storage_results {
        storage.entry(contract_address).or_insert_with(HashMap::new).insert(storage_key, storage_value);
    }

    info!("Filled storage for {} contracts", storage.len());

    // 2. Get nonces for all addresses
    for contract_address in &all_addresses {
        let nonce = rpc_client.starknet_rpc().get_nonce(block_id, *contract_address.key()).await.unwrap_or(Felt::ZERO); // Default to zero if not found

        address_to_nonce.insert(*contract_address, Nonce(nonce));
    }

    info!("Retrieved nonces for {} addresses", address_to_nonce.len());

    // 3. Get class hashes for all addresses
    let mut all_class_hashes: HashSet<ClassHash> = accessed_classes.clone();

    for contract_address in &all_addresses {
        let class_hash = if *contract_address.key() == BLOCK_HASH_CONTRACT_ADDRESS
            || *contract_address.key() == ALIAS_CONTRACT_ADDRESS
        {
            // Special case for system contracts (block hash and alias contract)
            ClassHash(Felt::ZERO)
        } else {
            let class_hash_felt = rpc_client
                .starknet_rpc()
                .get_class_hash_at(block_id, *contract_address.key())
                .await
                .unwrap_or(Felt::ZERO); // Default to zero if not found
            ClassHash(class_hash_felt)
        };

        address_to_class_hash.insert(*contract_address, class_hash);
        all_class_hashes.insert(class_hash);
    }

    info!("Retrieved class hashes for {} addresses", address_to_class_hash.len());

    // 4. Get compiled class hashes for all class hashes (two-phase optimization)
    // Filter out zero class hashes
    let non_zero_class_hashes: Vec<ClassHash> =
        all_class_hashes.iter().filter(|ch| ch.0 != Felt::ZERO).copied().collect();

    info!(
        "Computing compiled class hashes for {} classes (fetching with max {} concurrent requests, then processing in parallel)",
        non_zero_class_hashes.len(),
        MAX_CONCURRENT_GET_CLASS_REQUESTS
    );

    // Phase 1: Fetch all contract classes concurrently (network I/O parallelization)
    let class_fetch_results: Vec<(ClassHash, Option<starknet::core::types::ContractClass>)> =
        stream::iter(non_zero_class_hashes.clone())
            .map(|class_hash| async move {
                let contract_class = rpc_client.starknet_rpc().get_class(block_id, class_hash.0).await.ok();
                (class_hash, contract_class)
            })
            .buffer_unordered(MAX_CONCURRENT_GET_CLASS_REQUESTS)
            .collect()
            .await;

    info!("Fetched {} contract classes, now computing hashes in parallel...", class_fetch_results.len());

    // Phase 2: Process contract classes in parallel using rayon (CPU parallelization)
    let compiled_class_hash_results: Vec<(ClassHash, CompiledClassHash)> = class_fetch_results
        .par_iter()
        .filter_map(|(class_hash, contract_class_opt)| {
            let contract_class = contract_class_opt.as_ref()?;
            let compiled_hash = compute_compiled_class_hash(contract_class).ok()?;
            Some((*class_hash, compiled_hash))
        })
        .collect();

    // Insert successful results into the map
    for (class_hash, compiled_class_hash) in compiled_class_hash_results {
        class_hash_to_compiled_class_hash.insert(class_hash, compiled_class_hash);
    }

    // Insert zero for classes that failed to compile
    for class_hash in &non_zero_class_hashes {
        class_hash_to_compiled_class_hash.entry(*class_hash).or_insert(CompiledClassHash(Felt::ZERO));
    }

    info!("Retrieved compiled class hashes for {} classes", class_hash_to_compiled_class_hash.len());

    let cached_state_input =
        CachedStateInput { storage, address_to_class_hash, address_to_nonce, class_hash_to_compiled_class_hash };

    info!("Generated cached state input successfully!");
    Ok(cached_state_input)
}

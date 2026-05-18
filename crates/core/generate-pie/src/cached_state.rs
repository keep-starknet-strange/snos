use futures::stream::{self, StreamExt};
use log::{info, warn};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use starknet::core::types::{BlockId, StarknetError};
use starknet::providers::ProviderError;
use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::state::StorageKey;
use starknet_os::io::os_input::CachedStateInput;
use starknet_types_core::felt::Felt;
use std::collections::{HashMap, HashSet};

use crate::constants::{MAX_CONCURRENT_GET_CLASS_REQUESTS, MAX_CONCURRENT_GET_STORAGE_AT_REQUESTS};
use rpc_client::state_reader::{compute_compiled_class_hash, compute_compiled_class_hash_v2};
use rpc_client::RpcClient;

// Constants for special contract addresses
const BLOCK_HASH_CONTRACT_ADDRESS: Felt = Felt::ONE;
const ALIAS_CONTRACT_ADDRESS: Felt = Felt::TWO;

fn is_expected_missing_state_error(error: &ProviderError) -> bool {
    matches!(error, ProviderError::StarknetError(StarknetError::ContractNotFound | StarknetError::ClassHashNotFound))
}

fn log_cached_state_zero_fallback(
    field_name: &str,
    block_id: BlockId,
    contract_address: ContractAddress,
    key: Option<Felt>,
    error: &ProviderError,
) {
    let key_suffix = key.map(|felt| format!(", key {:#x}", felt)).unwrap_or_default();
    let message = format!(
        "Cached state {} read failed at block {:?} for contract {:#x}{}: {}. Falling back to zero.",
        field_name,
        block_id,
        contract_address.0.key(),
        key_suffix,
        error
    );

    if is_expected_missing_state_error(error) {
        info!("{}", message);
    } else {
        warn!("{}", message);
    }
}

/// Creates an empty cached state for block 0 (genesis block).
///
/// Block 0 has no previous state, but we need to initialize the alias
/// contract with its initial storage value.
fn create_genesis_cached_state() -> Result<CachedStateInput, Box<dyn std::error::Error + Send + Sync>> {
    info!("Creating genesis block cached state");

    // The alias contract (address 0x2) needs initial storage
    let alias_contract_address = ContractAddress::try_from(ALIAS_CONTRACT_ADDRESS)?;
    let alias_storage_key = StorageKey::try_from(Felt::ZERO)?;

    Ok(CachedStateInput {
        // Counter is set to 0 in the beginning
        // It will be set to 0x80 as a part of block 0
        storage: HashMap::from([(alias_contract_address, HashMap::from([(alias_storage_key, Felt::ZERO)]))]),
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
    migrated_class_hashes: &HashSet<ClassHash>,
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
    let storage_results: Vec<Result<(ContractAddress, StorageKey, Felt), ProviderError>> =
        stream::iter(storage_requests)
            .map(|(contract_address, storage_key)| async move {
                let storage_value = match rpc_client
                    .get_storage_at_with_retry(*contract_address.key(), *storage_key.0.key(), block_id)
                    .await
                {
                    Ok(storage_value) => Ok(storage_value),
                    Err(err) if is_expected_missing_state_error(&err) => {
                        log_cached_state_zero_fallback(
                            "storage",
                            block_id,
                            contract_address,
                            Some(*storage_key.0.key()),
                            &err,
                        );
                        Ok(Felt::ZERO)
                    }
                    Err(err) => Err(err),
                }?;

                Ok((contract_address, storage_key, storage_value))
            })
            .buffer_unordered(MAX_CONCURRENT_GET_STORAGE_AT_REQUESTS)
            .collect()
            .await;

    // Reconstruct the nested HashMap structure from results
    for result in storage_results {
        let (contract_address, storage_key, storage_value) =
            result.map_err(|err| Box::new(err) as Box<dyn std::error::Error + Send + Sync>)?;
        storage.entry(contract_address).or_insert_with(HashMap::new).insert(storage_key, storage_value);
    }

    info!("Filled storage for {} contracts", storage.len());

    // 2. Get nonces for all addresses
    for contract_address in &all_addresses {
        let nonce = match rpc_client.get_nonce_with_retry(block_id, *contract_address.key()).await {
            Ok(nonce) => Ok(nonce),
            Err(err) if is_expected_missing_state_error(&err) => {
                log_cached_state_zero_fallback("nonce", block_id, *contract_address, None, &err);
                Ok(Felt::ZERO)
            }
            Err(err) => Err(err),
        }
        .map_err(|err| Box::new(err) as Box<dyn std::error::Error + Send + Sync>)?;

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
            let class_hash_felt =
                match rpc_client.get_class_hash_at_with_retry(block_id, *contract_address.key()).await {
                    Ok(class_hash_felt) => Ok(class_hash_felt),
                    Err(err) if is_expected_missing_state_error(&err) => {
                        log_cached_state_zero_fallback("class_hash", block_id, *contract_address, None, &err);
                        Ok(Felt::ZERO)
                    }
                    Err(err) => Err(err),
                }
                .map_err(|err| Box::new(err) as Box<dyn std::error::Error + Send + Sync>)?;
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
    let class_fetch_results: Vec<(ClassHash, Result<starknet::core::types::ContractClass, ProviderError>)> =
        stream::iter(non_zero_class_hashes.clone())
            .map(|class_hash| async move {
                let contract_class = rpc_client.get_class_with_retry(block_id, class_hash.0).await;
                (class_hash, contract_class)
            })
            .buffer_unordered(MAX_CONCURRENT_GET_CLASS_REQUESTS)
            .collect()
            .await;

    let mut successful_class_fetches = Vec::with_capacity(class_fetch_results.len());
    for (class_hash, contract_class_result) in class_fetch_results {
        match contract_class_result {
            Ok(contract_class) => successful_class_fetches.push((class_hash, contract_class)),
            Err(ProviderError::StarknetError(StarknetError::ClassHashNotFound)) => {
                info!(
                    "Cached state class fetch missed previous-state class at block {:?} for class_hash {:#x}. Falling back to compiled_class_hash=0.",
                    block_id,
                    class_hash.0
                );
            }
            Err(err) => {
                return Err(Box::new(err));
            }
        }
    }

    info!(
        "Fetched {} contract classes successfully, now computing hashes in parallel...",
        successful_class_fetches.len()
    );

    // Phase 2: Process contract classes in parallel using rayon (CPU parallelization)
    // For migrated classes, use v1 (Poseidon) hash since cached state represents previous block
    // For other classes, use v2 (BLAKE) hash
    let compiled_class_hash_results: Vec<(ClassHash, CompiledClassHash)> = successful_class_fetches
        .par_iter()
        .filter_map(|(class_hash, contract_class)| {
            let compiled_hash = if migrated_class_hashes.contains(class_hash) {
                // Use old Poseidon hash (v1) for migrated classes in cached state
                match compute_compiled_class_hash(contract_class) {
                    Ok(compiled_hash) => compiled_hash,
                    Err(err) => {
                        warn!(
                            "Cached state compiled class hash v1 computation failed at block {:?} for class_hash {:#x}: {}. Falling back to zero.",
                            block_id,
                            class_hash.0,
                            err
                        );
                        return None;
                    }
                }
            } else {
                // Use BLAKE hash (v2) for non-migrated classes
                match compute_compiled_class_hash_v2(contract_class) {
                    Ok(compiled_hash) => compiled_hash,
                    Err(err) => {
                        warn!(
                            "Cached state compiled class hash v2 computation failed at block {:?} for class_hash {:#x}: {}. Falling back to zero.",
                            block_id,
                            class_hash.0,
                            err
                        );
                        return None;
                    }
                }
            };
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

    let storage_key_count = cached_state_input.storage.values().map(HashMap::len).sum::<usize>();
    info!(
        "Generated cached state input successfully: storage_contracts={} storage_keys={} nonces={} class_hashes={} compiled_class_hashes={}",
        cached_state_input.storage.len(),
        storage_key_count,
        cached_state_input.address_to_nonce.len(),
        cached_state_input.address_to_class_hash.len(),
        cached_state_input.class_hash_to_compiled_class_hash.len()
    );
    Ok(cached_state_input)
}

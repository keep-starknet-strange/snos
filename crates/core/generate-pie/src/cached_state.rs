use log::info;
use starknet::core::types::BlockId;
use starknet::providers::Provider;
use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::state::StorageKey;
use starknet_os::io::os_input::CachedStateInput;
use starknet_types_core::felt::Felt;
use std::collections::{HashMap, HashSet};

use rpc_client::state_reader::AsyncRpcStateReader;
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
    for (contract_address, storage_keys) in accessed_keys_by_address {
        let mut contract_storage = HashMap::new();

        // TODO: Optimize this
        for storage_key in storage_keys {
            let storage_value = rpc_client
                .starknet_rpc()
                .get_storage_at(*contract_address.key(), *storage_key.0.key(), block_id)
                .await
                .unwrap_or(Felt::ZERO); // Default to zero if not found

            contract_storage.insert(*storage_key, storage_value);
        }

        if !contract_storage.is_empty() {
            storage.insert(*contract_address, contract_storage);
        }
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

    // 4. Get compiled class hashes for all class hashes
    for class_hash in &all_class_hashes {
        if class_hash.0 == Felt::ZERO {
            // Skip zero class hash
            continue;
        }

        let state_reader = AsyncRpcStateReader::new(rpc_client.clone(), Some(block_id));
        let compiled_class_hash = match state_reader.get_compiled_class_hash_async(*class_hash).await {
            Ok(compiled_hash) => compiled_hash,
            Err(_) => {
                // Put zero class hash in the map if we can't get the compiled class hash
                // TODO: Check the error type and only put zero if it's not a not found error
                class_hash_to_compiled_class_hash.insert(*class_hash, CompiledClassHash(Felt::ZERO));
                continue;
            }
        };

        class_hash_to_compiled_class_hash.insert(*class_hash, compiled_class_hash);
    }

    info!("Retrieved compiled class hashes for {} classes", class_hash_to_compiled_class_hash.len());

    let cached_state_input =
        CachedStateInput { storage, address_to_class_hash, address_to_nonce, class_hash_to_compiled_class_hash };

    info!("Generated cached state input successfully!");
    Ok(cached_state_input)
}

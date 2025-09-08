use rpc_client::state_reader::AsyncRpcStateReader;
use rpc_client::RpcClient;
use starknet::core::types::BlockId;
use starknet::providers::Provider;
use starknet_api::core::{ClassHash, ContractAddress, Nonce};
use starknet_api::state::StorageKey;
use starknet_os::io::os_input::CachedStateInput;
use starknet_types_core::felt::Felt;
use std::collections::{HashMap, HashSet};

pub async fn generate_cached_state_input(
    rpc_client: &RpcClient,
    block_id: BlockId,
    accessed_addresses: &HashSet<ContractAddress>,
    accessed_classes: &HashSet<ClassHash>,
    accessed_keys_by_address: &HashMap<ContractAddress, HashSet<StorageKey>>,
) -> Result<CachedStateInput, Box<dyn std::error::Error + Send + Sync>> {
    println!(" Generating cached state input...");

    let mut storage = HashMap::new();
    let mut address_to_class_hash = HashMap::new();
    let mut address_to_nonce = HashMap::new();
    let mut class_hash_to_compiled_class_hash = HashMap::new();

    // Combine all addresses from accessed_addresses and accessed_keys_by_address
    let mut all_addresses: HashSet<ContractAddress> = accessed_addresses.clone();
    all_addresses.extend(accessed_keys_by_address.keys());

    println!(" Processing {} total addresses...", all_addresses.len());

    // 1. Fill storage using accessed keys
    for (contract_address, storage_keys) in accessed_keys_by_address {
        let mut contract_storage = HashMap::new();

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

    println!(" Filled storage for {} contracts", storage.len());

    // 2. Get nonces for all addresses
    for contract_address in &all_addresses {
        let nonce = rpc_client
            .starknet_rpc()
            .get_nonce(block_id, *contract_address.key())
            .await
            .unwrap_or(Felt::ZERO); // Default to zero if not found

        address_to_nonce.insert(*contract_address, Nonce(nonce));
    }

    println!(" Retrieved nonces for {} addresses", address_to_nonce.len());

    // 3. Get class hashes for all addresses
    let mut all_class_hashes: HashSet<ClassHash> = accessed_classes.clone();

    for contract_address in &all_addresses {
        let class_hash = if *contract_address.key() == Felt::ONE {
            // Special case for block hash contract
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

    println!(
        " Retrieved class hashes for {} addresses",
        address_to_class_hash.len()
    );

    // 4. Get compiled class hashes for all class hashes
    for class_hash in &all_class_hashes {
        if class_hash.0 == Felt::ZERO {
            // Skip zero class hash
            continue;
        }

        let state_reader = AsyncRpcStateReader::new(rpc_client.clone(), block_id);
        let compiled_class_hash = match state_reader
            .get_compiled_class_hash_async(*class_hash)
            .await
        {
            Ok(compiled_hash) => compiled_hash,
            Err(_) => {
                // If we can't get the compiled class hash, skip it
                continue;
            }
        };

        class_hash_to_compiled_class_hash.insert(*class_hash, compiled_class_hash);
    }

    println!(
        " Retrieved compiled class hashes for {} classes",
        class_hash_to_compiled_class_hash.len()
    );

    let cached_state_input = CachedStateInput {
        storage,
        address_to_class_hash,
        address_to_nonce,
        class_hash_to_compiled_class_hash,
    };

    println!(" Generated cached state input successfully!");
    Ok(cached_state_input)
}

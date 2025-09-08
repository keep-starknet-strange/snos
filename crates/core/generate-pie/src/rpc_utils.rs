use blockifier::execution::call_info::CallInfo;
use blockifier::transaction::objects::TransactionExecutionInfo;
use cairo_vm::Felt252;
use rpc_client::pathfinder::client::ClientError;
use rpc_client::pathfinder::proofs::{
    verify_storage_proof, ContractData, PathfinderClassProof, PathfinderProof,
};
use rpc_client::RpcClient;
use serde_json;
use starknet_api::contract_address;
use starknet_api::core::ContractAddress;
use starknet_api::state::StorageKey;
use starknet_types_core::felt::Felt;
use std::collections::{HashMap, HashSet};
use std::fs;

/// Comprehensive structure that captures all access information from transaction execution
#[derive(Debug, Clone)]
pub struct BlockAccessInfo {
    /// Storage keys accessed per contract address
    pub accessed_keys_by_address: HashMap<ContractAddress, HashSet<StorageKey>>,
    /// All contract addresses accessed globally across all transactions
    pub accessed_contract_addresses: HashSet<ContractAddress>,
    /// All class hashes accessed globally across all transactions (as Felt for consistency)
    pub accessed_class_hashes: HashSet<Felt>,
    /// All unique storage read values across all transactions
    pub storage_read_values: HashSet<Felt>,
    /// All unique class hash values read across all transactions  
    pub read_class_hash_values: HashSet<Felt>,
    /// All unique block hash values read across all transactions
    pub read_block_hash_values: HashSet<Felt>,
    /// All block numbers accessed across all transactions (as Felt for consistency)
    pub accessed_blocks: HashSet<Felt>,
}

/// Collects comprehensive access information from transaction execution infos along with block hash contract key
/// and any extra keys needed for contracts that trigger get_block_hash_syscall.
pub(crate) fn get_comprehensive_access_info(
    tx_execution_infos: &[TransactionExecutionInfo],
    old_block_number: Felt,
) -> BlockAccessInfo {
    let mut accessed_keys_by_address = get_all_accessed_keys(tx_execution_infos);
    // We need to fetch the storage proof for the block hash contract
    accessed_keys_by_address
        .entry(contract_address!("0x1"))
        .or_default()
        .insert(old_block_number.try_into().unwrap());
    accessed_keys_by_address
        .entry(contract_address!("0x2"))
        .or_default()
        .insert(Felt::ZERO.try_into().unwrap());
    // Include extra keys for contracts that trigger get_block_hash_syscall
    insert_extra_storage_reads_keys(old_block_number, &mut accessed_keys_by_address);

    let mut accessed_contract_addresses = HashSet::new();
    let mut accessed_class_hashes = HashSet::new();
    let mut storage_read_values = HashSet::new();
    let mut read_class_hash_values = HashSet::new();
    let mut read_block_hash_values = HashSet::new();
    let mut accessed_blocks = HashSet::new();

    // Collect all access information from transaction execution infos
    for tx_execution_info in tx_execution_infos {
        for call_info in [
            &tx_execution_info.validate_call_info,
            &tx_execution_info.execute_call_info,
            &tx_execution_info.fee_transfer_call_info,
        ]
        .into_iter()
        .flatten()
        {
            collect_access_info_from_call(
                call_info,
                &mut accessed_contract_addresses,
                &mut accessed_class_hashes,
                &mut storage_read_values,
                &mut read_class_hash_values,
                &mut read_block_hash_values,
                &mut accessed_blocks,
            );
        }
    }

    // Extend contract address 0x1 with values from accessed_blocks
    let contract_0x1_keys = accessed_keys_by_address
        .entry(contract_address!("0x1"))
        .or_default();
    for block_number in &accessed_blocks {
        contract_0x1_keys.insert((*block_number).try_into().unwrap());
    }

    BlockAccessInfo {
        accessed_keys_by_address,
        accessed_contract_addresses,
        accessed_class_hashes,
        storage_read_values,
        read_class_hash_values,
        read_block_hash_values,
        accessed_blocks,
    }
}

/// Merges multiple BlockAccessInfo structures into one comprehensive structure
/// This is useful when you have access info from current and previous blocks
pub(crate) fn merge_access_info(access_infos: Vec<BlockAccessInfo>) -> BlockAccessInfo {
    let mut merged = BlockAccessInfo {
        accessed_keys_by_address: HashMap::new(),
        accessed_contract_addresses: HashSet::new(),
        accessed_class_hashes: HashSet::new(),
        storage_read_values: HashSet::new(),
        read_class_hash_values: HashSet::new(),
        read_block_hash_values: HashSet::new(),
        accessed_blocks: HashSet::new(),
    };

    for access_info in access_infos {
        // Merge accessed_keys_by_address - combine keys for each contract address
        for (contract_address, storage_keys) in access_info.accessed_keys_by_address {
            merged
                .accessed_keys_by_address
                .entry(contract_address)
                .or_default()
                .extend(storage_keys);
        }

        // Merge all global HashSets - union operations
        merged
            .accessed_contract_addresses
            .extend(access_info.accessed_contract_addresses);
        merged
            .accessed_class_hashes
            .extend(access_info.accessed_class_hashes);
        merged
            .storage_read_values
            .extend(access_info.storage_read_values);
        merged
            .read_class_hash_values
            .extend(access_info.read_class_hash_values);
        merged
            .read_block_hash_values
            .extend(access_info.read_block_hash_values);
        merged.accessed_blocks.extend(access_info.accessed_blocks);
    }

    merged
}

/// Recursively collects access information from a call and its inner calls
fn collect_access_info_from_call(
    call_info: &CallInfo,
    accessed_contract_addresses: &mut HashSet<ContractAddress>,
    accessed_class_hashes: &mut HashSet<Felt>,
    storage_read_values: &mut HashSet<Felt>,
    read_class_hash_values: &mut HashSet<Felt>,
    read_block_hash_values: &mut HashSet<Felt>,
    accessed_blocks: &mut HashSet<Felt>,
) {
    let tracker = &call_info.storage_access_tracker;

    // Collect contract addresses
    accessed_contract_addresses.extend(&tracker.accessed_contract_addresses);

    // Collect storage read values (insert unique values)
    for value in &tracker.storage_read_values {
        storage_read_values.insert(Felt::from(*value));
    }

    // Collect class hash values (insert unique values) - convert ClassHash to Felt
    for class_hash in &tracker.read_class_hash_values {
        read_class_hash_values.insert(Felt::from(class_hash.0));
    }

    // Collect block hash values (insert unique values) - convert BlockHash to Felt
    for block_hash in &tracker.read_block_hash_values {
        read_block_hash_values.insert(Felt::from(block_hash.0));
    }

    // Collect accessed blocks - convert BlockNumber to Felt
    for block_number in &tracker.accessed_blocks {
        accessed_blocks.insert(Felt::from(block_number.0));
    }

    // Recursively process inner calls
    for inner_call in &call_info.inner_calls {
        collect_access_info_from_call(
            inner_call,
            accessed_contract_addresses,
            accessed_class_hashes,
            storage_read_values,
            read_class_hash_values,
            read_block_hash_values,
            accessed_blocks,
        );
    }
}

pub(crate) async fn get_storage_proofs(
    client: &RpcClient,
    block_number: u64,
    accessed_keys_by_address: &HashMap<ContractAddress, HashSet<StorageKey>>,
) -> Result<HashMap<Felt, PathfinderProof>, ClientError> {
    let mut storage_proofs = HashMap::new();

    println!("Contracts we're fetching proofs for:");
    for (contract_address, storage_keys) in accessed_keys_by_address {
        println!("    Fetching proof for {}", contract_address.to_string());
        let contract_address_felt = *contract_address.key();
        let storage_proof = get_storage_proof_for_contract(
            client,
            *contract_address,
            storage_keys.clone().into_iter(),
            block_number,
        )
        .await?;
        // println!("storage proof for the address: {:?} is: {:?}", contract_address, storage_proof);
        storage_proofs.insert(contract_address_felt, storage_proof);
    }

    Ok(storage_proofs)
}

pub(crate) async fn get_class_proofs(
    rpc_client: &RpcClient,
    block_number: u64,
    class_hashes: &[&Felt],
) -> Result<HashMap<Felt252, PathfinderClassProof>, ClientError> {
    let mut proofs: HashMap<Felt252, PathfinderClassProof> =
        HashMap::with_capacity(class_hashes.len());
    for class_hash in class_hashes {
        let proof = rpc_client
            .pathfinder_rpc()
            .get_class_proof(block_number, class_hash)
            .await?;
        // TODO: need to combine these, similar to merge_chunked_storage_proofs above?
        proofs.insert(**class_hash, proof);
    }

    Ok(proofs)
}

/// Helper function to write storage proof to a JSON file
fn write_storage_proof_to_file(
    storage_proof: &PathfinderProof,
    filename: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let json_content = serde_json::to_string_pretty(storage_proof)?;
    fs::write(filename, json_content)?;
    Ok(())
}

/// Fetches the storage proof for the specified contract and storage keys.
/// This function can fetch additional keys if required to fill gaps in the storage trie
/// that must be filled to get the OS to function. See `get_key_following_edge` for more details.
async fn get_storage_proof_for_contract<KeyIter: Iterator<Item = StorageKey>>(
    rpc_client: &RpcClient,
    contract_address: ContractAddress,
    storage_keys: KeyIter,
    block_number: u64,
) -> Result<PathfinderProof, ClientError> {
    let contract_address_felt = *contract_address.key();
    let keys: Vec<_> = storage_keys.map(|storage_key| *storage_key.key()).collect();

    let mut storage_proof =
        fetch_storage_proof_for_contract(rpc_client, contract_address_felt, &keys, block_number)
            .await?;

    // Write the storage proof to a file

    let contract_data = match &storage_proof.contract_data {
        None => {
            return Ok(storage_proof);
        }
        Some(contract_data) => contract_data,
    };

    let additional_keys = if contract_data.root != Felt::ZERO {
        verify_storage_proof(contract_data, &keys)
    } else {
        vec![]
    };

    // Fetch additional proofs required to fill gaps in the storage trie that could make
    // the OS crash otherwise.
    if !additional_keys.is_empty() {
        println!("non empty additional_keys now: {:?}", additional_keys);
        let additional_proof = fetch_storage_proof_for_contract(
            rpc_client,
            contract_address_felt,
            &additional_keys,
            block_number,
        )
        .await?;

        storage_proof = merge_storage_proofs(vec![storage_proof, additional_proof]);
    }

    Ok(storage_proof)
}

/// Fetches the state + storage proof for a single contract for all the specified keys.
/// This function handles the chunking of requests imposed by the RPC API and merges
/// the proofs returned from multiple calls into one.
async fn fetch_storage_proof_for_contract(
    rpc_client: &RpcClient,
    contract_address: Felt,
    keys: &[Felt],
    block_number: u64,
) -> Result<PathfinderProof, ClientError> {
    let storage_proof = if keys.is_empty() {
        rpc_client
            .pathfinder_rpc()
            .get_proof(block_number, contract_address, &[])
            .await?
    } else {
        // The endpoint is limited to 100 keys at most per call
        const MAX_KEYS: usize = 100;
        let mut chunked_storage_proofs = Vec::new();
        for keys_chunk in keys.chunks(MAX_KEYS) {
            chunked_storage_proofs.push(
                rpc_client
                    .pathfinder_rpc()
                    .get_proof(block_number, contract_address, keys_chunk)
                    .await?,
            );
        }
        merge_storage_proofs(chunked_storage_proofs)
    };

    Ok(storage_proof)
}

fn merge_storage_proofs(proofs: Vec<PathfinderProof>) -> PathfinderProof {
    let class_commitment = proofs[0].class_commitment;
    let contract_commitment = proofs[0].contract_commitment;
    let state_commitment = proofs[0].state_commitment;
    let contract_proof = proofs[0].contract_proof.clone();

    let contract_data = {
        let mut contract_data: Option<ContractData> = None;

        for proof in proofs {
            if let Some(data) = proof.contract_data {
                if let Some(contract_data) = contract_data.as_mut() {
                    contract_data.storage_proofs.extend(data.storage_proofs);
                } else {
                    contract_data = Some(data);
                }
            }
        }

        contract_data
    };

    PathfinderProof {
        contract_commitment,
        class_commitment,
        state_commitment,
        contract_proof,
        contract_data,
    }
}

/// Inserts additional keys for retrieving storage proof from the block hash contract (address 0x1).
/// Certain contracts necessitate extra nodes from the contract 0x1. However, since Blockifier does not provide this information,
/// it is necessary to add some extra keys to ensure the inclusion of the required nodes.
/// This approach serves as a workaround. The ideal solutions would be to either retrieve the full tree or obtain information about the necessary nodes.
/// The first approach would introduce significant overhead for most blocks, and the second solution is currently not feasible at the moment.
fn insert_extra_storage_reads_keys(
    old_block_number: Felt,
    keys: &mut HashMap<ContractAddress, HashSet<StorageKey>>,
) {
    // A list of the contracts that accessed to the storage from 0x1 using `get_block_hash_syscall`
    let special_addresses: Vec<ContractAddress> = vec![
        contract_address!("0x01246c3031c5d0d1cf60a9370aac03a4717538f659e4a2bfb0f692e970e0c4b5"),
        contract_address!("0x00656ca4889a405ec5222e4b0997e5a043902a98cb1f85a039f76f50c000479d"),
        contract_address!("0x022207b425a6c0239bbf5d58fbf0272fbb059ee4bb89f48255321d6e7c1606ef"),
        // Ekubo:core contract address. Source code is not available but `key_not_in_preimage` error is triggered every time it's called
        contract_address!("0x5dd3d2f4429af886cd1a3b08289dbcea99a294197e9eb43b0e0325b4b"),
    ];
    if special_addresses
        .iter()
        .any(|address| keys.contains_key(address))
    {
        let extra_storage_reads = 200 * 10; // TODO: 10 here is the STORED_BLOCK_HASH_BUFFER
        if old_block_number >= Felt252::from(extra_storage_reads) {
            for i in 1..=extra_storage_reads {
                keys.entry(contract_address!("0x1")).or_default().insert(
                    (old_block_number - i)
                        .try_into()
                        .expect("Felt to StorageKey conversion failed"),
                );
            }
        }
    }
}

/// Utility to get all the accesed keys from TxexecutionInfo resulted from
/// Reexecuting all block tx using blockifier
/// We need this as the OS require proofs for all the accessed values
pub(crate) fn get_all_accessed_keys(
    tx_execution_infos: &[TransactionExecutionInfo],
) -> HashMap<ContractAddress, HashSet<StorageKey>> {
    let mut accessed_keys_by_address: HashMap<ContractAddress, HashSet<StorageKey>> =
        HashMap::new();

    for tx_execution_info in tx_execution_infos {
        let accessed_keys_in_tx = get_accessed_keys_in_tx(tx_execution_info);
        for (contract_address, storage_keys) in accessed_keys_in_tx {
            accessed_keys_by_address
                .entry(contract_address)
                .or_default()
                .extend(storage_keys);
        }
    }

    let code_addresses = extract_code_addresses(tx_execution_infos);

    for address in code_addresses {
        accessed_keys_by_address.entry(address).or_default();
    }

    accessed_keys_by_address
}

fn get_accessed_keys_in_tx(
    tx_execution_info: &TransactionExecutionInfo,
) -> HashMap<ContractAddress, HashSet<StorageKey>> {
    let mut accessed_keys_by_address: HashMap<ContractAddress, HashSet<StorageKey>> =
        HashMap::new();

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
            accessed_keys_by_address
                .entry(contract_address)
                .or_default()
                .extend(storage_keys);
        }
    }

    accessed_keys_by_address
}

fn get_accessed_storage_keys(
    call_info: &CallInfo,
) -> HashMap<ContractAddress, HashSet<StorageKey>> {
    let mut accessed_keys_by_address: HashMap<ContractAddress, HashSet<StorageKey>> =
        HashMap::new();

    let contract_address = &call_info.call.storage_address;
    accessed_keys_by_address
        .entry(*contract_address)
        .or_default()
        .extend(
            call_info
                .storage_access_tracker
                .accessed_storage_keys
                .iter()
                .copied(),
        );

    for inner_call in &call_info.inner_calls {
        let inner_call_storage_keys = get_accessed_storage_keys(inner_call);
        for (contract_address, storage_keys) in inner_call_storage_keys {
            accessed_keys_by_address
                .entry(contract_address)
                .or_default()
                .extend(storage_keys);
        }
    }

    accessed_keys_by_address
}

fn extract_code_addresses(
    transaction_info: &[TransactionExecutionInfo],
) -> HashSet<ContractAddress> {
    let mut addresses = HashSet::new();

    for info in transaction_info {
        if let Some(call_info) = &info.validate_call_info {
            extract_inner_addresses(call_info, &mut addresses);
        }
        if let Some(call_info) = &info.execute_call_info {
            extract_inner_addresses(call_info, &mut addresses);
        }
        if let Some(call_info) = &info.fee_transfer_call_info {
            extract_inner_addresses(call_info, &mut addresses);
        }
    }

    addresses
}

/// Extracts inner code addresses recursively
///
/// *Note* This is an unbounded recursive call
fn extract_inner_addresses(call_info: &CallInfo, addresses: &mut HashSet<ContractAddress>) {
    addresses.extend(&call_info.storage_access_tracker.accessed_contract_addresses);
    if let Some(code_address) = &call_info.call.code_address {
        addresses.insert(*code_address);
    }

    for inner_call in &call_info.inner_calls {
        extract_inner_addresses(inner_call, addresses);
    }
}

/// Legacy function for backward compatibility - extracts just the storage keys
pub(crate) fn get_accessed_keys_with_block_hash(
    tx_execution_infos: &[TransactionExecutionInfo],
    old_block_number: Felt,
) -> HashMap<ContractAddress, HashSet<StorageKey>> {
    get_comprehensive_access_info(tx_execution_infos, old_block_number).accessed_keys_by_address
}

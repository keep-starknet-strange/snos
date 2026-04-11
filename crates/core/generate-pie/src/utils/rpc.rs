use crate::constants::{ALIAS_CONTRACT_ADDRESS, BLOCK_HASH_CONTRACT_ADDRESS};
use crate::types::initial_reads::accessed_keys_from_initial_reads;
use blockifier::execution::call_info::CallInfo;
use blockifier::state::cached_state::StateMaps;
use blockifier::transaction::objects::TransactionExecutionInfo;
use cairo_vm::Felt252;
use log::info;
use rpc_client::client::ProofClient;
use rpc_client::error::ClientError;
use rpc_client::types::{ClassProof, ContractData, ContractProof};
use rpc_client::RpcClient;
use starknet_api::contract_address;
use starknet_api::core::{ClassHash, ContractAddress};
use starknet_api::state::StorageKey;
use starknet_types_core::felt::Felt;
use std::collections::{HashMap, HashSet};

/// Comprehensive structure that captures all access information from transaction execution
#[allow(dead_code)]
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

#[derive(Default)]
struct CallTreeAccesses {
    accessed_contract_addresses: HashSet<ContractAddress>,
    accessed_class_hashes: HashSet<ClassHash>,
    accessed_blocks: HashSet<Felt>,
}

/// Collects comprehensive access information from local blockifier execution, using
/// `initial_reads` as the authoritative storage witness and the execution call tree for
/// executed contract/class metadata.
pub(crate) fn get_comprehensive_access_info(
    tx_execution_infos: &[TransactionExecutionInfo],
    initial_reads: &StateMaps,
    old_block_number: Felt,
) -> BlockAccessInfo {
    let mut accessed_keys_by_address = accessed_keys_from_initial_reads(initial_reads);
    let mut call_tree_accesses = collect_call_tree_accesses(tx_execution_infos);
    merge_initial_read_contract_addresses(&mut call_tree_accesses.accessed_contract_addresses, initial_reads);
    let accessed_class_hashes: HashSet<Felt> =
        call_tree_accesses.accessed_class_hashes.iter().map(|class_hash| class_hash.0).collect();

    for address in &call_tree_accesses.accessed_contract_addresses {
        accessed_keys_by_address.entry(*address).or_default();
    }

    // We need to fetch the storage proof for the block-hash contract and alias contract.
    accessed_keys_by_address
        .entry(BLOCK_HASH_CONTRACT_ADDRESS)
        .or_default()
        .insert(old_block_number.try_into().unwrap());
    accessed_keys_by_address.entry(ALIAS_CONTRACT_ADDRESS).or_default().insert(Felt::ZERO.try_into().unwrap());
    // Include extra keys for contracts that trigger get_block_hash_syscall
    insert_extra_storage_reads_keys(old_block_number, &mut accessed_keys_by_address);

    let storage_read_values = HashSet::new();
    let read_class_hash_values = HashSet::new();
    let read_block_hash_values = HashSet::new();
    let accessed_blocks = std::mem::take(&mut call_tree_accesses.accessed_blocks);

    // Extend the block-hash contract with values from accessed_blocks.
    let block_hash_contract_keys = accessed_keys_by_address.entry(BLOCK_HASH_CONTRACT_ADDRESS).or_default();
    for block_number in &accessed_blocks {
        block_hash_contract_keys.insert((*block_number).try_into().unwrap());
    }

    BlockAccessInfo {
        accessed_keys_by_address,
        accessed_contract_addresses: call_tree_accesses.accessed_contract_addresses,
        accessed_class_hashes,
        storage_read_values,
        read_class_hash_values,
        read_block_hash_values,
        accessed_blocks,
    }
}

fn merge_initial_read_contract_addresses(addresses: &mut HashSet<ContractAddress>, initial_reads: &StateMaps) {
    addresses.extend(initial_reads.storage.keys().map(|(contract_address, _)| *contract_address));
    addresses.extend(initial_reads.class_hashes.keys().copied());
    addresses.extend(initial_reads.nonces.keys().copied());
}

fn collect_call_tree_accesses(transaction_info: &[TransactionExecutionInfo]) -> CallTreeAccesses {
    let mut accesses = CallTreeAccesses::default();

    for info in transaction_info {
        for call_info in
            [&info.validate_call_info, &info.execute_call_info, &info.fee_transfer_call_info].into_iter().flatten()
        {
            collect_call_tree_accesses_from_call(call_info, &mut accesses);
        }
    }

    accesses
}

/// Get the storage proofs for all the specified storage keys for all the given contracts.
/// We return a hash map of the contract addresses and it's proof ([ContractProof])
/// TODO: We can optimize this by sending multiple contracts in a single RPC call
pub(crate) async fn get_storage_proofs(
    client: &RpcClient,
    block_number: u64,
    accessed_keys_by_address: &HashMap<ContractAddress, HashSet<StorageKey>>,
) -> Result<HashMap<Felt, ContractProof>, ClientError> {
    let mut storage_proofs = HashMap::new();

    info!("Fetching storage proofs for {} contracts", accessed_keys_by_address.len());

    for (contract_address, storage_keys) in accessed_keys_by_address {
        let contract_address_felt = *contract_address.key();
        let storage_proof =
            get_storage_proof_for_contract(client, *contract_address, storage_keys.clone().into_iter(), block_number)
                .await?;
        storage_proofs.insert(contract_address_felt, storage_proof);
    }

    Ok(storage_proofs)
}

pub(crate) async fn get_class_proofs(
    rpc_client: &RpcClient,
    block_number: u64,
    class_hashes: &[&Felt],
) -> Result<HashMap<Felt252, ClassProof>, ClientError> {
    let mut proofs: HashMap<Felt252, ClassProof> = HashMap::with_capacity(class_hashes.len());

    info!("Fetching class proofs for {} classes", class_hashes.len());

    for class_hash in class_hashes {
        let proof = rpc_client
            .starknet_rpc()
            .get_class_proof(block_number, class_hash)
            .await
            .map_err(|e| ClientError::CustomError(format!("{}", e)))?;
        // TODO: need to combine these, similar to merge_chunked_storage_proofs above?
        proofs.insert(**class_hash, proof);
    }

    Ok(proofs)
}

/// Fetches the storage proof for the specified contract and storage keys.
/// This function can fetch additional keys if required to fill gaps in the storage trie
/// that must be filled to get the OS to function. See `get_key_following_edge` for more details.
async fn get_storage_proof_for_contract<KeyIter: Iterator<Item = StorageKey>>(
    rpc_client: &RpcClient,
    contract_address: ContractAddress,
    storage_keys: KeyIter,
    block_number: u64,
) -> Result<ContractProof, ClientError> {
    info!("Getting storage proof for contract {}", contract_address);
    let contract_address_felt = *contract_address.key();
    let keys: Vec<_> = storage_keys.map(|storage_key| *storage_key.key()).collect();

    let mut contract_proof =
        fetch_storage_proof_for_contract(rpc_client, contract_address_felt, &keys, block_number).await?;

    // Combine all storage proofs into a single vector
    match &contract_proof.contract_data {
        None => {
            return Ok(contract_proof);
        }
        Some(contract_data) => {
            contract_proof.contract_data = Some(ContractData {
                storage_proofs: vec![contract_data.clone().storage_proofs.into_iter().flatten().collect()],
                // This unwrap is safe since we are checking that it's Some above
                root: contract_proof.contract_data.unwrap().root,
            });
        }
    }

    let contract_data = match &contract_proof.contract_data {
        None => {
            return Ok(contract_proof);
        }
        Some(contract_data) => contract_data,
    };

    let additional_keys = if contract_data.root != Felt::ZERO {
        contract_data.get_additional_keys(&keys).map_err(|e| ClientError::CustomError(format!("{}", e)))?
    } else {
        vec![]
    };

    info!("Got {} additional keys for contract {}", additional_keys.len(), contract_address);

    // Fetch additional proofs required to fill gaps in the storage trie that could make
    // the OS crash otherwise.
    if !additional_keys.is_empty() {
        let mut additional_proof =
            fetch_storage_proof_for_contract(rpc_client, contract_address_felt, &additional_keys, block_number).await?;

        // Combine all storage proofs into a single vector
        match &additional_proof.contract_data {
            None => {
                panic!("Failed to fetch additional proof for contract {}", contract_address)
            }
            Some(contract_data) => {
                additional_proof.contract_data = Some(ContractData {
                    storage_proofs: vec![contract_data.clone().storage_proofs.into_iter().flatten().collect()],
                    // This unwrap is safe since we are checking that it's Some above
                    root: additional_proof.contract_data.unwrap().root,
                });
            }
        }
        contract_proof = merge_storage_proofs(vec![contract_proof.clone(), additional_proof]);
    }

    Ok(contract_proof)
}

/// Fetches the state + storage proof for a single contract for all the specified keys.
/// This function handles the chunking of requests imposed by the RPC API and merges
/// the proofs returned from multiple calls into one.
async fn fetch_storage_proof_for_contract(
    rpc_client: &RpcClient,
    contract_address: Felt,
    keys: &[Felt],
    block_number: u64,
) -> Result<ContractProof, ClientError> {
    info!("Fetching storage proof for contract {} with {} keys", contract_address, keys.len());

    rpc_client
        .starknet_rpc()
        .get_proof(block_number, contract_address, keys)
        .await
        .map_err(|e| ClientError::CustomError(format!("{}", e)))
}

/// Merges the storage proofs of the SAME contract.
/// It takes a vector of [ContractProof] and returns a single [ContractProof]
fn merge_storage_proofs(proofs: Vec<ContractProof>) -> ContractProof {
    info!("Merging {} storage proofs", proofs.len());
    let class_commitment = proofs[0].class_commitment;
    let contract_commitment = proofs[0].contract_commitment;
    let state_commitment = proofs[0].state_commitment;
    let contract_proof = proofs[0].contract_proof.clone();

    let contract_data = {
        let mut contract_data: Option<ContractData> = None;

        for proof in proofs {
            if let Some(data) = proof.contract_data {
                if let Some(contract_data) = contract_data.as_mut() {
                    contract_data.storage_proofs[0].extend(data.storage_proofs[0].clone());
                } else {
                    contract_data = Some(data);
                }
            }
        }

        contract_data
    };

    ContractProof { contract_commitment, class_commitment, state_commitment, contract_proof, contract_data }
}

/// Inserts additional keys for retrieving storage proof from the block hash contract (address 0x1).
/// Certain contracts require extra nodes from the contract 0x1. However, since Blockifier does not provide this information,
/// it is necessary to add some extra keys to ensure the inclusion of the required nodes.
/// This approach serves as a workaround. The ideal solutions would be to either retrieve the full tree or collect information about the necessary nodes.
/// The first approach would introduce significant overhead for most blocks, and the second solution is currently not possible at the moment.
fn insert_extra_storage_reads_keys(old_block_number: Felt, keys: &mut HashMap<ContractAddress, HashSet<StorageKey>>) {
    // A list of the contracts that accessed to the storage from 0x1 using `get_block_hash_syscall`
    let special_addresses: Vec<ContractAddress> = vec![
        contract_address!("0x01246c3031c5d0d1cf60a9370aac03a4717538f659e4a2bfb0f692e970e0c4b5"),
        contract_address!("0x00656ca4889a405ec5222e4b0997e5a043902a98cb1f85a039f76f50c000479d"),
        contract_address!("0x022207b425a6c0239bbf5d58fbf0272fbb059ee4bb89f48255321d6e7c1606ef"),
        // Ekubo:core contract address.
        // Source code is not available, but the ` key_not_in_preimage ` error is triggered every time it's called
        contract_address!("0x5dd3d2f4429af886cd1a3b08289dbcea99a294197e9eb43b0e0325b4b"),
    ];
    if special_addresses.iter().any(|address| keys.contains_key(address)) {
        let extra_storage_reads = 200 * 10; // TODO: 10 here is the STORED_BLOCK_HASH_BUFFER
        if old_block_number >= Felt252::from(extra_storage_reads) {
            for i in 1..=extra_storage_reads {
                keys.entry(BLOCK_HASH_CONTRACT_ADDRESS)
                    .or_default()
                    .insert((old_block_number - i).try_into().expect("Felt to StorageKey conversion failed"));
            }
        }
    }
}

fn collect_call_tree_accesses_from_call(call_info: &CallInfo, accesses: &mut CallTreeAccesses) {
    accesses.accessed_contract_addresses.insert(call_info.call.storage_address);
    accesses
        .accessed_contract_addresses
        .extend(call_info.storage_access_tracker.accessed_contract_addresses.iter().copied());
    if let Some(code_address) = &call_info.call.code_address {
        accesses.accessed_contract_addresses.insert(*code_address);
    }
    if let Some(class_hash) = call_info.call.class_hash {
        accesses.accessed_class_hashes.insert(class_hash);
    }
    for block_number in &call_info.storage_access_tracker.accessed_blocks {
        accesses.accessed_blocks.insert(Felt::from(block_number.0));
    }

    for inner_call in &call_info.inner_calls {
        collect_call_tree_accesses_from_call(inner_call, accesses);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blockifier::state::cached_state::StateMaps;
    use blockifier::transaction::objects::TransactionExecutionInfo;
    use starknet_api::block::BlockNumber;
    use starknet_api::state::StorageKey;

    fn contract_address(value: u64) -> ContractAddress {
        ContractAddress::try_from(Felt::from(value)).unwrap()
    }

    fn class_hash(value: u64) -> ClassHash {
        ClassHash(Felt::from(value))
    }

    fn call_info(
        class_hash: Option<ClassHash>,
        storage_address: u64,
        code_address: Option<u64>,
        tracked_addresses: &[u64],
        accessed_blocks: &[u64],
        inner_calls: Vec<CallInfo>,
    ) -> CallInfo {
        let mut call_info = CallInfo::default();
        call_info.call.class_hash = class_hash;
        call_info.call.storage_address = contract_address(storage_address);
        call_info.call.code_address = code_address.map(contract_address);
        call_info.storage_access_tracker.accessed_contract_addresses =
            tracked_addresses.iter().copied().map(contract_address).collect();
        call_info.storage_access_tracker.accessed_blocks = accessed_blocks.iter().copied().map(BlockNumber).collect();
        call_info.inner_calls = inner_calls;
        call_info
    }

    #[test]
    fn collect_call_tree_accesses_collects_nested_contracts_classes_and_blocks() {
        let validate_call = call_info(Some(class_hash(10)), 10, Some(11), &[12], &[100], vec![]);
        let execute_call = call_info(
            Some(class_hash(20)),
            20,
            None,
            &[22],
            &[200],
            vec![call_info(Some(class_hash(21)), 21, Some(23), &[24], &[201], vec![])],
        );
        let fee_transfer_call = call_info(Some(class_hash(30)), 30, None, &[31], &[300], vec![]);

        let tx_execution_infos = vec![
            TransactionExecutionInfo {
                validate_call_info: Some(validate_call),
                execute_call_info: Some(execute_call),
                fee_transfer_call_info: None,
                ..Default::default()
            },
            TransactionExecutionInfo {
                validate_call_info: None,
                execute_call_info: None,
                fee_transfer_call_info: Some(fee_transfer_call),
                ..Default::default()
            },
        ];

        let accesses = collect_call_tree_accesses(&tx_execution_infos);

        assert_eq!(
            accesses.accessed_contract_addresses,
            HashSet::from([
                contract_address(10),
                contract_address(11),
                contract_address(12),
                contract_address(20),
                contract_address(21),
                contract_address(22),
                contract_address(23),
                contract_address(24),
                contract_address(30),
                contract_address(31),
            ])
        );
        assert_eq!(
            accesses.accessed_class_hashes,
            HashSet::from([class_hash(10), class_hash(20), class_hash(21), class_hash(30)])
        );
        assert_eq!(
            accesses.accessed_blocks,
            HashSet::from([Felt::from(100_u64), Felt::from(200_u64), Felt::from(201_u64), Felt::from(300_u64)])
        );
    }

    #[test]
    fn get_comprehensive_access_info_merges_initial_read_contract_addresses() {
        let storage_contract = contract_address(40);
        let class_hash_contract = contract_address(41);
        let nonce_contract = contract_address(42);
        let mut initial_reads = StateMaps::default();
        initial_reads.storage.insert((storage_contract, StorageKey::try_from(Felt::ONE).unwrap()), Felt::from(7_u64));
        initial_reads.class_hashes.insert(class_hash_contract, class_hash(410));
        initial_reads.nonces.insert(nonce_contract, starknet_api::core::Nonce(Felt::from(9_u64)));

        let access_info = get_comprehensive_access_info(&[], &initial_reads, Felt::from(500_u64));

        assert!(access_info.accessed_contract_addresses.contains(&storage_contract));
        assert!(access_info.accessed_contract_addresses.contains(&class_hash_contract));
        assert!(access_info.accessed_contract_addresses.contains(&nonce_contract));
    }
}

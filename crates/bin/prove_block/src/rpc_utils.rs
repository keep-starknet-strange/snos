use std::collections::{HashMap, HashSet};

use blockifier::transaction::objects::TransactionExecutionInfo;
use cairo_vm::Felt252;
use num_bigint::BigInt;
use rpc_client::pathfinder::client::ClientError;
use rpc_client::pathfinder::proofs::{
    ContractData, EdgePath, PathfinderClassProof, PathfinderProof, ProofVerificationError, TrieNode,
};
use rpc_client::RpcClient;
use starknet::core::types::BlockWithTxs;
use starknet_api::core::{ContractAddress, PatriciaKey};
use starknet_api::state::StorageKey;
use starknet_api::{contract_address, felt, patricia_key};
use starknet_os::config::{DEFAULT_STORAGE_TREE_HEIGHT, STORED_BLOCK_HASH_BUFFER};
use starknet_os::crypto::pedersen::PedersenHash;
use starknet_os::starkware_utils::commitment_tree::base_types::Height;
use starknet_types_core::felt::Felt;

use crate::reexecute::format_commitment_facts;
use crate::utils::get_all_accessed_keys;

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
        rpc_client.pathfinder_rpc().get_proof(block_number, contract_address, &[]).await?
    } else {
        // The endpoint is limited to 100 keys at most per call
        const MAX_KEYS: usize = 100;
        let mut chunked_storage_proofs = Vec::new();
        for keys_chunk in keys.chunks(MAX_KEYS) {
            chunked_storage_proofs
                .push(rpc_client.pathfinder_rpc().get_proof(block_number, contract_address, keys_chunk).await?);
        }
        merge_storage_proofs(chunked_storage_proofs)
    };

    Ok(storage_proof)
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
        fetch_storage_proof_for_contract(rpc_client, contract_address_felt, &keys, block_number).await?;

    let contract_data = match &storage_proof.contract_data {
        None => {
            return Ok(storage_proof);
        }
        Some(contract_data) => contract_data,
    };
    let additional_keys = verify_storage_proof(contract_data, &keys);

    // Fetch additional proofs required to fill gaps in the storage trie that could make
    // the OS crash otherwise.
    if !additional_keys.is_empty() {
        let additional_proof =
            fetch_storage_proof_for_contract(rpc_client, contract_address_felt, &additional_keys, block_number).await?;

        storage_proof = merge_storage_proofs(vec![storage_proof, additional_proof]);
    }

    Ok(storage_proof)
}

/// Verify the storage proofs and handle errors.
/// Returns a list of additional keys to fetch to fill gaps in the tree that will make the OS
/// crash otherwise.
/// This function will panic if the proof contains an invalid node hash (i.e. the hash of a child
/// node does not match the one specified in the parent).
fn verify_storage_proof(contract_data: &ContractData, keys: &[Felt]) -> Vec<Felt> {
    let mut additional_keys = vec![];
    if let Err(errors) = contract_data.verify(keys) {
        for error in errors {
            match error {
                ProofVerificationError::NonExistenceProof { key, height, proof } => {
                    if let Some(TrieNode::Edge { child: _, path }) = proof.last() {
                        if height.0 < DEFAULT_STORAGE_TREE_HEIGHT {
                            let modified_key = get_key_following_edge(key, height, path);
                            log::trace!(
                                "Fetching modified key {} for key {}",
                                modified_key.to_hex_string(),
                                key.to_hex_string()
                            );
                            additional_keys.push(modified_key);
                        }
                    }
                }
                _ => {
                    panic!("Proof verification failed: {}", error);
                }
            }
        }
    }

    additional_keys
}

/// Inserts additional keys for retrieving storage proof from the block hash contract (address 0x1).
/// Certain contracts necessitate extra nodes from the contract 0x1. However, since Blockifier does not provide this information,
/// it is necessary to add some extra keys to ensure the inclusion of the required nodes.
/// This approach serves as a workaround. The ideal solutions would be to either retrieve the full tree or obtain information about the necessary nodes.
/// The first approach would introduce significant overhead for most blocks, and the second solution is currently not feasible at the moment.
fn insert_extra_storage_reads_keys(
    storage_reads: &HashMap<ContractAddress, Vec<Felt252>>,
    old_block_number: Felt252,
    keys: &mut HashMap<ContractAddress, HashSet<StorageKey>>,
) {
    // A list of the contracts that accessed to the storage from 0x1 using `get_block_hash_syscall`
    let special_addresses: Vec<ContractAddress> = vec![
        contract_address!("0x01246c3031c5d0d1cf60a9370aac03a4717538f659e4a2bfb0f692e970e0c4b5"),
        contract_address!("0x00656ca4889a405ec5222e4b0997e5a043902a98cb1f85a039f76f50c000479d"),
    ];

    let extra_storage_reads = if special_addresses.iter().any(|address| storage_reads.contains_key(address)) {
        100 * STORED_BLOCK_HASH_BUFFER
    } else {
        STORED_BLOCK_HASH_BUFFER
    };

    if old_block_number >= Felt252::from(extra_storage_reads) {
        for i in 1..=extra_storage_reads {
            keys.entry(contract_address!("0x1"))
                .or_default()
                .insert((old_block_number - i).try_into().expect("Felt to StorageKey conversion failed"));
        }
    }
}

pub async fn get_storage_proofs(
    client: &RpcClient,
    block_number: u64,
    tx_execution_infos: &[TransactionExecutionInfo],
    old_block_number: Felt,
) -> Result<HashMap<Felt, PathfinderProof>, ClientError> {
    let accessed_keys_by_address = {
        let (mut keys, storage_reads) = get_all_accessed_keys(tx_execution_infos);

        // We need to fetch the storage proof for the block hash contract
        // Include not only old_block_hash but also retrieve the previous 10 values
        let block_hash_contract_address = contract_address!("0x1");
        keys.entry(block_hash_contract_address)
            .or_default()
            .insert((old_block_number).try_into().expect("Felt to StorageKey conversion failed"));

        println!("KEYS: {:?}", keys);

        println!("BLOCK HASH KEYS: {:?}", keys.get(&contract_address!("0x1")).expect("Expected keys for address 0x1"));

        // Include extra keys for contracts that trigger get_block_hash_syscall
        // insert_extra_storage_reads_keys(&storage_reads, old_block_number, &mut keys);

        // Within the Starknet architecture, the address 0x1 is a special address that maps block numbers to their corresponding block hashes. As some contracts might access storage reads using `get_block_hash_syscall`, it is necessary to add some extra keys here.
        // By leveraging the structure of this special contract, we filter out storage_read_values that are greater than old_block_number and add these extra values to the necessary keys from the 0x1 contract address.
        // It is worth noting that this approach incurs some overhead due to the retrieval of additional data.
        // let additional_storage_reads: Vec<Felt> = storage_reads.values().flat_map(|vec| vec.iter()).cloned().collect();
        let additional_storage_reads: Vec<Felt> = storage_reads
            .values()
            .flat_map(|vec| vec.iter().cloned().filter(|x| x <= &Felt252::from(block_number)))
            .collect::<HashSet<Felt>>()
            .into_iter()
            .collect();

        println!("ADDITIONAL KEYS: {:?}", additional_storage_reads);

        // keys.entry(block_hash_contract_address).or_default().extend(
        //     additional_storage_reads
        //         .into_iter()
        //         .map(|key| StorageKey::try_from(key).expect("Felt to StorageKey conversion failed")),
        // );

        keys
    };

    let mut storage_proofs = HashMap::new();

    log::info!("Contracts we're fetching proofs for:");
    for (contract_address, storage_keys) in accessed_keys_by_address {
        log::info!("    Fetching proof for {}", contract_address.to_string());
        let contract_address_felt = *contract_address.key();
        let storage_proof =
            get_storage_proof_for_contract(client, contract_address, storage_keys.into_iter(), block_number).await?;

        if contract_address_felt == Felt252::ONE {
            let formatted_proof = format_commitment_facts::<PedersenHash>(&[storage_proof.contract_proof.clone()]);

            println!("FORMATTED PROOF: {:?}", formatted_proof);
        }

        storage_proofs.insert(contract_address_felt, storage_proof);
    }

    Ok(storage_proofs)
}

/// Returns a modified key that follows the specified edge path.
/// This function is used to work around an issue where the OS fails if it encounters a
/// write to 0 and the last node in the storage proof is an edge node of length 1.
/// In this situation the OS will still look up the node in the preimage and will fail
/// on a "Edge bottom not found in preimage" error.
/// To resolve this, we fetch the storage proof for a node that follows this edge in order
/// to get the bottom node in the preimage and resolve the issue.
///
/// For example, if following a key 0x00A0 we encounter an edge 0xB0 starting from height 8
/// to height 4 (i.e. the length of the edge is 4), then the bottom node of the edge will
/// not be included in the proof as the key does not follow the edge. We need to compute a key
/// that will follow the edge in order to get that bottom node. For example, the key 0x00B0 will
/// follow that edge.
///
/// An important note is that heigh = 0 at the level of leaf nodes (as opposed to the rest of the OS)
///
/// To achieve this, we zero the part of the key at the height of the edge and then replace it
/// with the path of the edge. This is achieved with bitwise operations. For our example,
/// this function will compute the new key as `(key & 0xFF0F) | 0x00B0`.
fn get_key_following_edge(key: Felt, height: Height, edge_path: &EdgePath) -> Felt {
    assert!(height.0 < DEFAULT_STORAGE_TREE_HEIGHT);

    let shift = height.0;
    let clear_mask = ((BigInt::from(1) << edge_path.len) - BigInt::from(1)) << shift;
    let mask = edge_path.value.to_bigint() << shift;
    let new_key = (key.to_bigint() & !clear_mask) | mask;

    Felt::from(new_key)
}

fn merge_storage_proofs(proofs: Vec<PathfinderProof>) -> PathfinderProof {
    let class_commitment = proofs[0].class_commitment;
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

    PathfinderProof { class_commitment, state_commitment, contract_proof, contract_data }
}

pub(crate) async fn get_class_proofs(
    rpc_client: &RpcClient,
    block_number: u64,
    class_hashes: &[&Felt],
) -> Result<HashMap<Felt252, PathfinderClassProof>, ClientError> {
    let mut proofs: HashMap<Felt252, PathfinderClassProof> = HashMap::with_capacity(class_hashes.len());
    for class_hash in class_hashes {
        let proof = rpc_client.pathfinder_rpc().get_class_proof(block_number, class_hash).await?;
        // TODO: need to combine these, similar to merge_chunked_storage_proofs above?
        proofs.insert(**class_hash, proof);
    }

    Ok(proofs)
}

pub fn get_starknet_version(block_with_txs: &BlockWithTxs) -> blockifier::versioned_constants::StarknetVersion {
    let starknet_version_str = &block_with_txs.starknet_version;
    match starknet_version_str.as_ref() {
        "0.13.0" => blockifier::versioned_constants::StarknetVersion::V0_13_0,
        "0.13.1" => blockifier::versioned_constants::StarknetVersion::V0_13_1,
        "0.13.1.1" => blockifier::versioned_constants::StarknetVersion::V0_13_1_1,
        "0.13.2" => blockifier::versioned_constants::StarknetVersion::V0_13_2,
        "0.13.2.1" => blockifier::versioned_constants::StarknetVersion::Latest,
        other => {
            unimplemented!("Unsupported Starknet version: {}", other)
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use starknet_os::crypto::pedersen::PedersenHash;

    use super::*;
    use crate::reexecute::format_commitment_facts;

    #[rstest]
    #[case(
        Felt::from_hex_unchecked("0x00A0"),
        Felt::from_hex_unchecked("0x00B0"),
        EdgePath { len: 4, value: Felt::from(0xB) },
        Height(4),
    )]
    #[case(
        Felt::from_hex_unchecked("0x1357"),
        Felt::from_hex_unchecked("0x13A7"),
        EdgePath { len: 4, value: Felt::from(0xA) },
        Height(4),
    )]
    #[case(
        Felt::from_hex_unchecked("0x281a73a6708b6c7df8ab477abbf99929586bd745d4ed2e45190d6d5edff1a6c"),
        Felt::from_hex_unchecked("0x2c1a73a6708b6c7df8ab477abbf99929586bd745d4ed2e45190d6d5edff1a6c"),
        EdgePath { len: 1, value: Felt::from(0x1) },
        Height(246),
    )]
    fn test_modified_key(
        #[case] key: Felt,
        #[case] expected_key: Felt,
        #[case] edge_path: EdgePath,
        #[case] height: Height,
    ) {
        let modified_key = get_key_following_edge(key, height, &edge_path);
        assert_eq!(modified_key, expected_key);
    }

    #[ignore = "Requires a running Pathfinder node"]
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_key_not_found_in_preimage() {
        println!("RUNNING KEY NOT IN PREIMAGE TEST");
        let endpoint = std::env::var("PATHFINDER_RPC_URL").expect("Missing PATHFINDER_RPC_URL in env");
        let rpc_client = RpcClient::new(&endpoint);

        let block_number = 237037;
        let old_block_number = 237027u64;
        let block_hash_contract_address = contract_address!("0x1");
        let mut storage_keys: HashSet<StorageKey> = HashSet::from([old_block_number.into()]);

        let storage_proof = get_storage_proof_for_contract(
            &rpc_client,
            block_hash_contract_address,
            storage_keys.clone().into_iter(),
            block_number,
        )
        .await
        .unwrap();

        let formatted_proof = format_commitment_facts::<PedersenHash>(&[storage_proof.contract_proof]);

        // On the first try, we won't find this node from the retrieved storage proof
        let missing_node =
            Felt252::from_hex_unchecked("0x34f1a3021b450d34bf9ce833b19de68b9f9d565d1951529f1eb4f30dbfc5e1c");
        assert_eq!(formatted_proof.contains_key(&missing_node), false);

        // Let's repeat the process once again but adding some extra keys/block numbers
        // storage_keys.insert(StorageKey::try_from(Felt::from(237027)).expect("Felt to StorageKey conversion failed"));
        // storage_keys.insert(StorageKey::try_from(Felt::from(237026)).expect("Felt to StorageKey conversion failed"));
        // storage_keys.insert(StorageKey::try_from(Felt::from(237025)).expect("Felt to StorageKey conversion failed"));
        // storage_keys.insert(StorageKey::try_from(Felt::from(237024)).expect("Felt to StorageKey conversion failed"));
        // storage_keys.insert(StorageKey::try_from(Felt::from(237023)).expect("Felt to StorageKey conversion failed"));
        // storage_keys.insert(StorageKey::try_from(Felt::from(237022)).expect("Felt to StorageKey conversion failed"));
        // storage_keys.insert(StorageKey::try_from(Felt::from(237021)).expect("Felt to StorageKey conversion failed"));
        // storage_keys.insert(StorageKey::try_from(Felt::from(237020)).expect("Felt to StorageKey conversion failed"));
        // storage_keys.insert(StorageKey::try_from(Felt::from(237019)).expect("Felt to StorageKey conversion failed"));
        // storage_keys.insert(StorageKey::try_from(Felt::from(237018)).expect("Felt to StorageKey conversion failed"));
        // storage_keys.insert(StorageKey::try_from(Felt::from(237017)).expect("Felt to StorageKey conversion failed"));
        // storage_keys.insert(StorageKey::try_from(Felt::from(237016)).expect("Felt to StorageKey conversion failed"));
        storage_keys.insert(StorageKey::try_from(Felt::from(236946)).expect("Felt to StorageKey conversion failed"));
        storage_keys.insert(StorageKey::try_from(Felt::from(236945)).expect("Felt to StorageKey conversion failed"));
        storage_keys.insert(StorageKey::try_from(Felt::from(237004)).expect("Felt to StorageKey conversion failed"));
        storage_keys.insert(StorageKey::try_from(Felt::from(0)).expect("Felt to StorageKey conversion failed"));
        storage_keys.insert(StorageKey::try_from(Felt::from(1)).expect("Felt to StorageKey conversion failed"));
        storage_keys.insert(StorageKey::try_from(Felt::from(15)).expect("Felt to StorageKey conversion failed"));
        storage_keys.insert(StorageKey::try_from(Felt::from(3)).expect("Felt to StorageKey conversion failed"));
        storage_keys.insert(StorageKey::try_from(Felt::from(8)).expect("Felt to StorageKey conversion failed"));

        // for i in 0..100 {
        //     storage_keys.insert(
        //         StorageKey::try_from(Felt::from(old_block_number - i)).expect("Felt to StorageKey conversion failed"),
        //     );
        // }

        // StorageKey::try_from(Felt::from(block_number)).expect("Felt to StorageKey conversion failed");
        // StorageKey::try_from(Felt::from(block_number - 1)).expect("Felt to StorageKey conversion failed");

        println!("Storage keys: {:?}", storage_keys);
        let storage_proof = get_storage_proof_for_contract(
            &rpc_client,
            block_hash_contract_address,
            storage_keys.into_iter(),
            block_number,
        )
        .await
        .unwrap();

        println!("StorageProof: {:?}", storage_proof);

        let formatted_proof = format_commitment_facts::<PedersenHash>(&[storage_proof.contract_proof]);

        println!("Formatted proof: {:?}", formatted_proof);

        assert_eq!(formatted_proof.contains_key(&missing_node), true);
    }
}

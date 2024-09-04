use std::collections::HashMap;

use blockifier::transaction::objects::TransactionExecutionInfo;
use cairo_vm::Felt252;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::json;
use starknet::core::types::BlockWithTxs;
use starknet_api::core::{ContractAddress, PatriciaKey};
use starknet_api::state::StorageKey;
use starknet_api::{contract_address, felt, patricia_key};
use starknet_os::config::DEFAULT_STORAGE_TREE_HEIGHT;
use starknet_os::crypto::pedersen::PedersenHash;
use starknet_os::crypto::poseidon::PoseidonHash;
use starknet_os::starkware_utils::commitment_tree::base_types::{Height, Length, NodePath};
use starknet_os::starkware_utils::commitment_tree::patricia_tree::nodes::{BinaryNodeFact, EdgeNodeFact};
use starknet_os::storage::dict_storage::DictStorage;
use starknet_os::storage::storage::{Fact, HashFunctionType};
use starknet_types_core::felt::Felt;

use crate::utils::get_all_accessed_keys;

pub(crate) fn jsonrpc_request(method: &str, params: serde_json::Value) -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "id": "0",
        "method": method,
        "params": params,
    })
}

async fn post_jsonrpc_request<T: DeserializeOwned>(
    client: &reqwest::Client,
    rpc_provider: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<T, reqwest::Error> {
    let request = jsonrpc_request(method, params);
    let response = client.post(format!("{}/rpc/pathfinder/v0.1", rpc_provider)).json(&request).send().await?;

    #[derive(Deserialize)]
    struct TransactionReceiptResponse<T> {
        result: T,
    }

    let response_text = response.text().await?;
    let response: TransactionReceiptResponse<T> =
        serde_json::from_str(&response_text).unwrap_or_else(|_| panic!("Error: {}", response_text));
    Ok(response.result)
}

// Types defined for Deserialize functionality
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct EdgePath {
    pub len: u64,
    pub value: Felt252,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) enum TrieNode {
    #[serde(rename = "binary")]
    Binary { left: Felt252, right: Felt252 },
    #[serde(rename = "edge")]
    Edge { child: Felt252, path: EdgePath },
}

impl TrieNode {
    pub(crate) fn hash<H: HashFunctionType>(&self) -> Felt {
        match self {
            TrieNode::Binary { left, right } => {
                let fact = BinaryNodeFact::new((*left).into(), (*right).into())
                    .expect("storage proof endpoint gave us an invalid binary node");

                // TODO: the hash function should probably be split from the Fact trait.
                //       we use a placeholder for the Storage trait in the meantime.
                Felt::from(<BinaryNodeFact as Fact<DictStorage, H>>::hash(&fact))
            }
            TrieNode::Edge { child, path } => {
                let fact = EdgeNodeFact::new((*child).into(), NodePath(path.value.to_biguint()), Length(path.len))
                    .expect("storage proof endpoint gave us an invalid edge node");
                // TODO: the hash function should probably be split from the Fact trait.
                //       we use a placeholder for the Storage trait in the meantime.
                Felt::from(<EdgeNodeFact as Fact<DictStorage, H>>::hash(&fact))
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ContractData {
    /// Root of the Contract state tree
    pub root: Felt252,
    /// The proofs associated with the queried storage values
    pub storage_proofs: Vec<Vec<TrieNode>>,
}

impl ContractData {
    /// Verifies that each contract state proof is valid.
    pub(crate) fn verify(&self, storage_keys: &[Felt252]) -> Result<(), Vec<ProofVerificationError>> {
        let mut errors = vec![];

        for (index, storage_key) in storage_keys.iter().enumerate() {
            if let Err(e) = verify_proof::<PedersenHash>(*storage_key, self.root, &self.storage_proofs[index]) {
                errors.push(e);
            }
        }

        if errors.is_empty() { Ok(()) } else { Err(errors) }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct PathfinderProof {
    pub state_commitment: Felt252,
    pub class_commitment: Felt252,
    pub contract_proof: Vec<TrieNode>,
    pub contract_data: Option<ContractData>,
}

pub(crate) async fn pathfinder_get_proof(
    client: &reqwest::Client,
    rpc_provider: &str,
    block_number: u64,
    contract_address: Felt,
    keys: &[Felt],
) -> Result<PathfinderProof, reqwest::Error> {
    post_jsonrpc_request(
        client,
        rpc_provider,
        "pathfinder_getProof",
        json!({ "block_id": { "block_number": block_number }, "contract_address": contract_address, "keys": keys }),
    )
    .await
}

/// Fetches the state + storage proof for a single contract for all the specified keys.
/// This function handles the chunking of requests imposed by the RPC API and merges
/// the proofs returned from multiple calls into one.
async fn fetch_storage_proof_for_contract(
    client: &reqwest::Client,
    rpc_provider: &str,
    contract_address: Felt,
    keys: &[Felt],
    block_number: u64,
) -> Result<PathfinderProof, reqwest::Error> {
    let storage_proof = if keys.is_empty() {
        pathfinder_get_proof(client, rpc_provider, block_number, contract_address, &[]).await?
    } else {
        // The endpoint is limited to 100 keys at most per call
        const MAX_KEYS: usize = 100;
        let mut chunked_storage_proofs = Vec::new();
        for keys_chunk in keys.chunks(MAX_KEYS) {
            chunked_storage_proofs
                .push(pathfinder_get_proof(client, rpc_provider, block_number, contract_address, keys_chunk).await?);
        }
        merge_storage_proofs(chunked_storage_proofs)
    };

    Ok(storage_proof)
}

/// Fetches the storage proof for the specified contract and storage keys.
/// This function can fetch additional keys if required to fill gaps in the storage trie
/// that must be filled to get the OS to function. See `get_key_following_edge` for more details.
async fn get_storage_proof_for_contract<KeyIter: Iterator<Item = StorageKey>>(
    client: &reqwest::Client,
    rpc_provider: &str,
    contract_address: ContractAddress,
    storage_keys: KeyIter,
    block_number: u64,
) -> Result<PathfinderProof, reqwest::Error> {
    let contract_address_felt = *contract_address.key();
    let keys: Vec<_> = storage_keys.map(|storage_key| *storage_key.key()).collect();

    let mut storage_proof =
        fetch_storage_proof_for_contract(client, rpc_provider, contract_address_felt, &keys, block_number).await?;

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
        let additional_proof = fetch_storage_proof_for_contract(
            client,
            rpc_provider,
            contract_address_felt,
            &additional_keys,
            block_number,
        )
        .await?;

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
                ProofVerificationError::KeyNotInProof { key, height, proof } => {
                    if let Some(TrieNode::Edge { child: _, path }) = proof.last() {
                        let modified_key = get_key_following_edge(key, height, path);
                        log::debug!(
                            "Fetching modified key {} for key {}",
                            modified_key.to_hex_string(),
                            key.to_hex_string()
                        );
                        additional_keys.push(modified_key);
                    }
                }
                ProofVerificationError::InvalidChildNodeHash { .. } => {
                    panic!("Proof verification failed: {}", error);
                }
            }
        }
    }

    additional_keys
}

pub(crate) async fn get_storage_proofs(
    client: &reqwest::Client,
    rpc_provider: &str,
    block_number: u64,
    tx_execution_infos: &[TransactionExecutionInfo],
    old_block_number: Felt,
) -> Result<HashMap<Felt, PathfinderProof>, reqwest::Error> {
    let accessed_keys_by_address = {
        let mut keys = get_all_accessed_keys(tx_execution_infos);
        // We need to fetch the storage proof for the block hash contract
        keys.entry(contract_address!("0x1")).or_default().insert(old_block_number.try_into().unwrap());
        keys
    };

    let mut storage_proofs = HashMap::new();

    log::info!("Contracts we're fetching proofs for:");
    for contract_address in accessed_keys_by_address.keys() {
        log::info!("    {}", contract_address.to_string());
    }

    for (contract_address, storage_keys) in accessed_keys_by_address {
        let contract_address_felt = *contract_address.key();
        let storage_proof = get_storage_proof_for_contract(
            client,
            rpc_provider,
            contract_address,
            storage_keys.into_iter(),
            block_number,
        )
        .await?;
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
fn get_key_following_edge(key: Felt, height: Height, edge_path: &EdgePath) -> Felt {
    assert!(height.0 < DEFAULT_STORAGE_TREE_HEIGHT);
    let mask = edge_path.value.to_bigint() << (DEFAULT_STORAGE_TREE_HEIGHT - height.0);
    let new_key = (key.to_bigint() & !mask.clone()) | mask;

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

#[allow(dead_code)]
#[derive(Clone, Deserialize)]
pub(crate) struct PathfinderClassProof {
    pub class_commitment: Felt252,
    pub class_proof: Vec<TrieNode>,
}

impl PathfinderClassProof {
    /// Verifies that the class proof is valid.
    pub(crate) fn verify(&self, class_hash: Felt) -> Result<(), ProofVerificationError> {
        verify_proof::<PoseidonHash>(class_hash, self.class_commitment, &self.class_proof)
    }
}

pub(crate) async fn pathfinder_get_class_proof(
    client: &reqwest::Client,
    rpc_provider: &str,
    block_number: u64,
    class_hash: &Felt,
) -> Result<PathfinderClassProof, reqwest::Error> {
    log::debug!("querying pathfinder_getClassProof for {:x}", class_hash);
    log::debug!("provider: {}", rpc_provider);
    post_jsonrpc_request(
        client,
        rpc_provider,
        "pathfinder_getClassProof",
        json!({ "block_id": { "block_number": block_number }, "class_hash": class_hash }),
    )
    .await
}

pub(crate) async fn get_class_proofs(
    client: &reqwest::Client,
    rpc_provider: &str,
    block_number: u64,
    class_hashes: &[&Felt],
) -> Result<HashMap<Felt252, PathfinderClassProof>, reqwest::Error> {
    let mut proofs: HashMap<Felt252, PathfinderClassProof> = HashMap::with_capacity(class_hashes.len());
    for class_hash in class_hashes {
        let proof = pathfinder_get_class_proof(client, rpc_provider, block_number, class_hash).await?;
        // TODO: need to combine these, similar to merge_chunked_storage_proofs above?
        proofs.insert(**class_hash, proof);
    }

    Ok(proofs)
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum ProofVerificationError<'a> {
    #[error("Proof verification failed for key {}. Proof stopped at height {}.", key.to_hex_string(), height.0)]
    KeyNotInProof { key: Felt, height: Height, proof: &'a [TrieNode] },

    #[error("Proof verification failed, node_hash {node_hash:x} != parent_hash {parent_hash:x}")]
    InvalidChildNodeHash { node_hash: Felt, parent_hash: Felt },
}

/// This function goes through the tree from top to bottom and verifies that
/// the hash of each node is equal to the corresponding hash in the parent node.
pub(crate) fn verify_proof<H: HashFunctionType>(
    key: Felt,
    commitment: Felt,
    proof: &[TrieNode],
) -> Result<(), ProofVerificationError> {
    let bits = key.to_bits_be();

    let mut parent_hash = commitment;
    let mut trie_node_iter = proof.iter();

    // The tree height is 251, so the first 5 bits are ignored.
    let start = 5;
    let mut index = start;

    loop {
        match trie_node_iter.next() {
            None => {
                if index - start != DEFAULT_STORAGE_TREE_HEIGHT {
                    return Err(ProofVerificationError::KeyNotInProof { key, height: Height(index - start), proof });
                }
                break;
            }
            Some(node) => {
                let node_hash = node.hash::<H>();
                if node_hash != parent_hash {
                    return Err(ProofVerificationError::InvalidChildNodeHash { node_hash, parent_hash });
                }

                match node {
                    TrieNode::Binary { left, right } => {
                        parent_hash = if bits[index as usize] { *right } else { *left };
                        index += 1;
                    }
                    TrieNode::Edge { child, path } => {
                        parent_hash = *child;
                        index += path.len;
                    }
                }
            }
        }
    }

    Ok(())
}

pub(crate) fn get_starknet_version(block_with_txs: &BlockWithTxs) -> blockifier::versioned_constants::StarknetVersion {
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
    use super::*;

    #[test]
    fn test_modified_key() {
        let key = Felt::from_hex_unchecked("0x281a73a6708b6c7df8ab477abbf99929586bd745d4ed2e45190d6d5edff1a6c");
        let expected_modified_key =
            Felt::from_hex_unchecked("0x2c1a73a6708b6c7df8ab477abbf99929586bd745d4ed2e45190d6d5edff1a6c");

        let height = Height(5);
        let edge_path = EdgePath { len: 1, value: Felt::from(0x1) };

        let modified_key = get_key_following_edge(key, height, &edge_path);
        assert_eq!(modified_key, expected_modified_key);
    }
}

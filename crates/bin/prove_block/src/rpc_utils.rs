use std::collections::HashMap;
use std::future::Future;

use blockifier::transaction::objects::TransactionExecutionInfo;
use cairo_vm::Felt252;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::json;
use starknet_api::core::{ContractAddress, PatriciaKey};
use starknet_api::hash::StarkHash;
use starknet_api::{contract_address, patricia_key};
use starknet_os::crypto::pedersen::PedersenHash;
use starknet_os::crypto::poseidon::PoseidonHash;
use starknet_os::starkware_utils::commitment_tree::base_types::{Length, NodePath};
use starknet_os::starkware_utils::commitment_tree::patricia_tree::nodes::{BinaryNodeFact, EdgeNodeFact};
use starknet_os::storage::cached_storage::CachedStorage;
use starknet_os::storage::dict_storage::DictStorage;
use starknet_os::storage::storage::{Fact, HashFunctionType, Storage, StorageError};
use starknet_os::utils::{felt_api2vm, felt_vm2api};
use starknet_types_core::felt::Felt;

use crate::utils::get_all_accessed_keys;

/// A `Storage` impl backed by RPC
#[derive(Clone)]
pub(crate) struct RpcStorage {
    cache: HashMap<Vec<u8>, Vec<u8>>,
}

pub(crate) type CachedRpcStorage = CachedStorage<RpcStorage>;

impl RpcStorage {
    pub fn new() -> Self {
        Self { cache: HashMap::with_capacity(1024) }
    }
}

impl Storage for RpcStorage {
    async fn set_value(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), StorageError> {
        log::trace!(
            "RpcStorage::set_value(), key-len: {}, key: {:x}, value len: {}",
            key.len(),
            num_bigint::BigUint::from_bytes_be(&key[..]),
            value.len()
        );
        self.cache.insert(key, value);
        Ok(())
    }

    fn get_value(&self, key: &[u8]) -> impl Future<Output = Result<Option<Vec<u8>>, StorageError>> + Send {
        log::trace!(
            "RpcStorage::get_value(), key-len: {}, key: {:x}",
            key.len(),
            num_bigint::BigUint::from_bytes_be(key)
        );
        async {
            if let Some(value) = self.cache.get(key) {
                Ok(Some(value.clone()))
            } else {
                log::warn!("    have no value for key {:x}", num_bigint::BigUint::from_bytes_be(key));
                Err(StorageError::ContentNotFound)
            }
        }
    }
}

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
    pub(crate) fn verify(&self, storage_keys: &[Felt252]) -> Result<(), String> {
        for (index, storage_key) in storage_keys.iter().enumerate() {
            verify_proof::<PedersenHash>(*storage_key, self.root, &self.storage_proofs[index])?;
        }

        Ok(())
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

pub(crate) async fn get_storage_proofs(
    client: &reqwest::Client,
    rpc_provider: &str,
    block_number: u64,
    tx_execution_infos: &[TransactionExecutionInfo],
    old_block_number: Felt,
) -> Result<HashMap<Felt, PathfinderProof>, reqwest::Error> {
    let accessed_keys_by_address = {
        let mut keys = get_all_accessed_keys(tx_execution_infos);
        keys.entry(contract_address!("0x1")).or_default().insert(felt_vm2api(old_block_number).try_into().unwrap());
        keys
    };

    let mut storage_proofs = HashMap::new();

    log::info!("Contracts we're fetching proofs for:");
    for contract_address in accessed_keys_by_address.keys() {
        log::info!("    {}", contract_address.to_string());
    }

    for (contract_address, storage_keys) in accessed_keys_by_address {
        let contract_address_felt = felt_api2vm(*contract_address.key());

        let keys: Vec<_> = storage_keys.iter().map(|storage_key| felt_api2vm(*storage_key.key())).collect();

        let storage_proof = if keys.is_empty() {
            pathfinder_get_proof(client, rpc_provider, block_number, contract_address_felt, &[]).await?
        } else {
            // The endpoint is limited to 100 keys at most per call
            const MAX_KEYS: usize = 100;
            let mut chunked_storage_proofs = Vec::new();
            for keys_chunk in keys.chunks(MAX_KEYS) {
                chunked_storage_proofs.push(
                    pathfinder_get_proof(client, rpc_provider, block_number, contract_address_felt, keys_chunk).await?,
                );
            }
            merge_chunked_storage_proofs(chunked_storage_proofs)
        };

        assert!(
            storage_proof
                .contract_data
                .as_ref()
                .expect("Storage proof should have contract_data")
                .verify(&keys)
                .is_ok()
        );

        storage_proofs.insert(contract_address_felt, storage_proof);
    }

    Ok(storage_proofs)
}

fn merge_chunked_storage_proofs(proofs: Vec<PathfinderProof>) -> PathfinderProof {
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
    pub(crate) fn verify(&self, class_hash: Felt) -> Result<(), String> {
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

/// This function goes through the tree from top to bottom and verifies that
/// the hash of each node is equal to the corresponding hash in the parent node.
pub(crate) fn verify_proof<H: HashFunctionType>(key: Felt, commitment: Felt, proof: &[TrieNode]) -> Result<(), String> {
    let bits = key.to_bits_be();

    let mut parent_hash = commitment;
    let mut trie_node_iter = proof.iter();

    // The tree height is 251, so the first 5 bits are ignored.
    let start = 5;
    let mut index = start;

    loop {
        match trie_node_iter.next() {
            None => {
                if index - start != 251 {
                    return Err(format!("Proof verification failed, proof height ({}) is not 251", (index - start)));
                }
                break;
            }
            Some(node) => {
                let node_hash = node.hash::<H>();
                if node_hash != parent_hash {
                    return Err(format!(
                        "Proof verification failed, node_hash {:x} != parent_hash {:x}",
                        node_hash, parent_hash
                    ));
                }

                match node {
                    TrieNode::Binary { left, right } => {
                        parent_hash = if bits[index] { *right } else { *left };
                        index += 1;
                    }
                    TrieNode::Edge { child, path } => {
                        parent_hash = *child;
                        index += path.len as usize;
                    }
                }
            }
        }
    }

    Ok(())
}

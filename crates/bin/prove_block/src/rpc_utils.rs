use std::collections::HashMap;
use std::future::Future;

use cairo_vm::Felt252;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::json;
use starknet::core::types::{StateUpdate, StorageEntry};
use starknet_os::storage::cached_storage::CachedStorage;
use starknet_os::storage::storage::{Storage, StorageError};
use starknet_types_core::felt::Felt;

/// A `Storage` impl backed by RPC
#[derive(Clone)]
pub(crate) struct RpcStorage {}

pub(crate) type CachedRpcStorage = CachedStorage<RpcStorage>;

impl RpcStorage {
    pub fn new() -> Self {
        Self {}
    }
}

impl Storage for RpcStorage {
    async fn set_value(&mut self, _key: Vec<u8>, _value: Vec<u8>) -> Result<(), StorageError> {
        Ok(())
    }

    fn get_value(&self, key: &[u8]) -> impl Future<Output = Result<Option<Vec<u8>>, StorageError>> + Send {
        log::warn!("unimplemented: RpcStorage::get_value(), key-len: {}, key: {:?}", key.len(), key);
        async { Ok(Some(Default::default())) }
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
    let response = client.post(format!("{}/rpc/v0_7", rpc_provider)).json(&request).send().await?;

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
#[derive(Clone, Deserialize)]
pub(crate) struct EdgePath {
    pub len: u64,
    pub value: Felt252,
}

#[derive(Clone, Deserialize)]
pub(crate) enum TrieNode {
    #[serde(rename = "binary")]
    Binary { left: Felt252, right: Felt252 },
    #[serde(rename = "edge")]
    Edge { child: Felt252, path: EdgePath },
}

#[derive(Deserialize)]
pub(crate) struct ContractData {
    /// The proofs associated with the queried storage values
    pub storage_proofs: Vec<Vec<TrieNode>>,
}

#[derive(Deserialize)]
pub(crate) struct PathfinderProof {
    pub class_commitment: Felt252,
    pub state_commitment: Felt252,
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
    state_update: &StateUpdate,
) -> Result<HashMap<Felt, PathfinderProof>, reqwest::Error> {
    let mut storage_changes_by_contract: HashMap<Felt, Vec<StorageEntry>> = HashMap::new();

    for diff_item in &state_update.state_diff.storage_diffs {
        storage_changes_by_contract.entry(diff_item.address).or_default().extend_from_slice(&diff_item.storage_entries);
    }

    let mut storage_proofs = HashMap::new();

    for (contract_address, storage_changes) in storage_changes_by_contract {
        let keys: Vec<_> = storage_changes.iter().map(|change| change.key).collect();

        // The endpoint is limited to 100 keys at most per call
        const MAX_KEYS: usize = 100;
        let mut chunked_storage_proofs = Vec::new();
        for keys_chunk in keys.chunks(MAX_KEYS) {
            chunked_storage_proofs
                .push(pathfinder_get_proof(client, rpc_provider, block_number, contract_address, keys_chunk).await?);
        }
        let storage_proof = merge_chunked_storage_proofs(chunked_storage_proofs);

        storage_proofs.insert(contract_address, storage_proof);
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

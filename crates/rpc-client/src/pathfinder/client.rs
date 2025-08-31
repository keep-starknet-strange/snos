use std::collections::VecDeque;
use std::fs::File;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use reqwest::{Response, StatusCode};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::json;
use starknet::macros::short_string;
use starknet_types_core::felt::Felt;

use crate::pathfinder::proofs::{ContractData, PathfinderClassProof, PathfinderProof, TrieNode};
use crate::types::{GetStorageProofResponse, MerkleNode, NodeWithHash};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("Encountered a request error: {0}")]
    ReqwestError(#[from] reqwest::Error),
    #[error("Encountered a custom error: {0}")]
    CustomError(String),
}

fn jsonrpc_request(method: &str, params: serde_json::Value) -> serde_json::Value {
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
) -> Result<T, ClientError> {
    let request = jsonrpc_request(method, params);
    let url = format!("{}/rpc/v0_8", rpc_provider);
    let response = client.post(url.to_string()).json(&request).send().await?;

    #[derive(Deserialize)]
    struct TransactionReceiptResponse<T> {
        result: T,
    }

    let response: TransactionReceiptResponse<T> = handle_error(response).await?;

    Ok(response.result)
}

async fn handle_error<T: DeserializeOwned>(response: Response) -> Result<T, ClientError> {
    match response.status() {
        StatusCode::OK => Ok(response.json().await?),
        s => {
            let error = response.text().await?;
            Err(ClientError::CustomError(format!("Received response: {s:?} Error: {error}")))
        }
    }
}

pub struct PathfinderRpcClient {
    /// A raw client to access endpoints not covered by starknet-rs.
    http_client: reqwest::Client,
    /// The base URL of the RPC client
    rpc_base_url: String,
}

impl PathfinderRpcClient {
    pub fn new(base_url: &str) -> Self {
        let starknet_rpc_url = base_url.to_string();
        log::trace!("Starknet RPC URL: {}", starknet_rpc_url);
        let http_client =
            reqwest::ClientBuilder::new().build().unwrap_or_else(|e| panic!("Could not build reqwest client: {e}"));

        Self { http_client, rpc_base_url: base_url.to_string() }
    }

    pub async fn get_proof(
        &self,
        block_number: u64,
        contract_address: Felt,
        keys: &[Felt],
    ) -> Result<PathfinderProof, ClientError> {
        let mut proofs = VecDeque::new();

        if keys.is_empty() {
            let proof = self.get_proof_one_key(block_number, contract_address, None).await?;
            proofs.push_back(proof);
        } else {
            for key in keys {
                let proof = self.get_proof_one_key(block_number, contract_address, Some(*key)).await?;
                proofs.push_back(proof);
            }
        }

        // Merge all the proofs into a single proof
        let mut proof = proofs.pop_front().expect("must have at least one");
        let contract_data = proof.contract_data.as_mut().expect("must have contract data");

        for proof in proofs {
            contract_data.storage_proofs.push(proof.contract_data.unwrap().storage_proofs[0].clone());
        }

        Ok(proof)
    }

    async fn get_proof_one_key(
        &self,
        block_number: u64,
        contract_address: Felt,
        key: Option<Felt>,
    ) -> Result<PathfinderProof, ClientError> {
        let key = if let Some(key) = key { vec![key] } else { Vec::new() };

        let json = json!({
            "block_id": { "block_number": block_number },
            "contract_addresses": [contract_address],
            "contracts_storage_keys": [{
                "contract_address": contract_address,
                "storage_keys": key
            }]
        });

        log::debug!(
            "querying starknet_getStorageProof for address {:x} key {:?} at block {:x}:\n {}",
            contract_address,
            key,
            block_number,
            json
        );
        let response = post_jsonrpc_request::<GetStorageProofResponse>(
            &self.http_client,
            &self.rpc_base_url,
            "starknet_getStorageProof",
            json,
        )
        .await?;

        Ok(official_proof_to_pathfinder_proof(response, block_number, contract_address, &key))
    }

    pub async fn get_class_proof(
        &self,
        block_number: u64,
        class_hash: &Felt,
    ) -> Result<PathfinderClassProof, ClientError> {
        log::debug!("querying starknet_getStorageProofs for class {:x} at block {:x}", class_hash, block_number);

        let response = post_jsonrpc_request::<GetStorageProofResponse>(
            &self.http_client,
            &self.rpc_base_url,
            "starknet_getStorageProof",
            json!({ "block_id": { "block_number": block_number }, "class_hashes": [class_hash] }),
        )
        .await?;

        Ok(official_proof_to_pathfinder_class_proof(response))
    }
}

#[allow(dead_code)]
fn write_proof_to_json(
    proof: &GetStorageProofResponse,
    block_number: u64,
    contract_address: Felt,
    keys: &[Felt],
) -> std::io::Result<()> {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    let json_string = serde_json::to_string_pretty(proof)?;
    let keys_string = keys.iter().map(|k| k.to_hex_string()).collect::<Vec<String>>().join("_");
    let filename = if keys_string.is_empty() {
        format!(
            "storage_proof_response_{}_{}_{}_{}.json",
            block_number,
            contract_address.to_hex_string(),
            "no_keys",
            timestamp
        )
    } else {
        format!(
            "storage_proof_response_{}_{}_{}__{}.json",
            block_number,
            contract_address.to_hex_string(),
            keys_string,
            timestamp
        )
    };

    let mut file = File::create(filename)?;
    file.write_all(json_string.as_bytes())?;
    println!("✅ Storage proof written to storage_proof_response.json");
    Ok(())
}

pub(crate) fn official_proof_to_pathfinder_proof(
    proof: GetStorageProofResponse,
    _block_number: u64,
    _contract_address: Felt,
    _keys: &[Felt],
) -> PathfinderProof {
    // write_proof_to_json(&proof, block_number, contract_address, keys).unwrap();
    // panic!("temp");
    let contract_proof = proof.contracts_proof;
    let contract_leaf = contract_proof.contract_leaves_data.first().expect("must have exactly one");
    let storage_proofs = proof.contracts_storage_proofs.nodes.first().expect("must have exactly one");
    // let contract_proof_root = proof.contracts_proof.contract_leaves_data

    let state_commitment = starknet_crypto::poseidon_hash_many(&[
        short_string!("STARKNET_STATE_V0"),
        proof.global_roots.contracts_tree_root,
        proof.global_roots.classes_tree_root,
    ]);

    // convert storage proofs to pathfinder types
    let mut pf_storage_proofs = Vec::with_capacity(1);
    let mut pf_storage_proof: Vec<TrieNode> = Vec::with_capacity(pf_storage_proofs.len());

    for n in &storage_proofs.0 {
        let NodeWithHash { node, node_hash } = n;
        let mut trie_node: TrieNode = node.clone().into();
        // Set the node_hash from the NodeWithHash
        match &mut trie_node {
            TrieNode::Binary { node_hash: nh, .. } => *nh = Some(*node_hash),
            TrieNode::Edge { node_hash: nh, .. } => *nh = Some(*node_hash),
        }
        pf_storage_proof.push(trie_node);
    }

    pf_storage_proofs.push(pf_storage_proof);

    // convert contract proofs to pathfinder types
    let mut pf_contract_proof: Vec<TrieNode> = Vec::with_capacity(contract_proof.nodes.len());
    for n in &contract_proof.nodes.0 {
        let NodeWithHash { node, node_hash } = n;
        let mut trie_node: TrieNode = node.clone().into();
        // Set the node_hash from the NodeWithHash
        match &mut trie_node {
            TrieNode::Binary { node_hash: nh, .. } => *nh = Some(*node_hash),
            TrieNode::Edge { node_hash: nh, .. } => *nh = Some(*node_hash),
        }
        pf_contract_proof.push(trie_node);
    }

    PathfinderProof {
        state_commitment: Some(state_commitment),
        contract_commitment: proof.global_roots.contracts_tree_root,
        class_commitment: Some(proof.global_roots.classes_tree_root),
        contract_proof: pf_contract_proof,
        contract_data: Some(ContractData { root: contract_leaf.storage_root, storage_proofs: pf_storage_proofs }),
    }
}

pub(crate) fn official_proof_to_pathfinder_class_proof(proof: GetStorageProofResponse) -> PathfinderClassProof {
    let class_proof = proof
        .classes_proof
        .nodes
        .iter()
        .map(|node_with_hash| {
            let NodeWithHash { node, node_hash } = node_with_hash;
            let mut trie_node: TrieNode = node.clone().into();
            // Set the node_hash from the NodeWithHash
            match &mut trie_node {
                TrieNode::Binary { node_hash: nh, .. } => *nh = Some(*node_hash),
                TrieNode::Edge { node_hash: nh, .. } => *nh = Some(*node_hash),
            }
            trie_node
        })
        .collect();
    let class_commitment = proof.global_roots.classes_tree_root;
    PathfinderClassProof { class_commitment, class_proof }
}

impl From<MerkleNode> for TrieNode {
    fn from(node: MerkleNode) -> Self {
        match node {
            MerkleNode::Edge { path, length, child, node_hash } => super::proofs::TrieNode::Edge {
                path: super::proofs::EdgePath { value: path, len: length as u64 },
                child,
                node_hash,
            },
            MerkleNode::Binary { left, right, node_hash } => super::proofs::TrieNode::Binary { left, right, node_hash },
        }
    }
}

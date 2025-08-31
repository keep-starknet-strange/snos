use std::collections::VecDeque;

use crate::pathfinder::error::ClientError;
use crate::pathfinder::types::request::{Request, TransactionReceiptResponse};
use crate::pathfinder::types::{GetStorageProofResponse, PathfinderClassProof, PathfinderProof};
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use serde_json::json;
use starknet_types_core::felt::Felt;

pub struct PathfinderRpcClient {
    /// A raw client to access endpoints not covered by starknet-rs
    http_client: reqwest::Client,
    /// The base URL of the RPC client
    rpc_base_url: String,
}

impl PathfinderRpcClient {
    /// Get a new Pathfinder RPC client
    pub fn new(base_url: &str) -> Self {
        let starknet_rpc_url = base_url.to_string();
        log::trace!("Starknet RPC URL: {}", starknet_rpc_url);
        let http_client =
            reqwest::ClientBuilder::new().build().unwrap_or_else(|e| panic!("Could not build reqwest client: {e}"));

        Self { http_client, rpc_base_url: base_url.to_string() }
    }

    /// Get proof for all the keys for the given contract at the given block number
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

    /// Get proof for a class at the given block number
    pub async fn get_class_proof(
        &self,
        block_number: u64,
        class_hash: &Felt,
    ) -> Result<PathfinderClassProof, ClientError> {
        log::debug!("querying starknet_getStorageProofs for class {:x} at block {:x}", class_hash, block_number);

        let response = self
            .send_request::<GetStorageProofResponse>(
                "starknet_getStorageProof",
                json!({ "block_id": { "block_number": block_number }, "class_hashes": [class_hash] }),
            )
            .await?;

        Ok(PathfinderClassProof::from(response))
    }

    /// Get proof for a single key for the given contract at the given block number
    /// TODO: Update this function to send multiple keys at once
    /// TODO: (Max keys is defined as 100 in Pathfinder. Make it a constant)
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
        let response = self.send_request::<GetStorageProofResponse>("starknet_getStorageProof", json).await?;

        Ok(PathfinderProof::try_from(response)?)
    }

    async fn send_request<T: DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T, ClientError> {
        let request = Request::new(method, params);
        let url = format!("{}/rpc/v0_8", self.rpc_base_url);
        let response = self.http_client.post(url.to_string()).json(&request).send().await?;
        let response: TransactionReceiptResponse<T> = match response.status() {
            StatusCode::OK => response.json().await?,
            status_code => {
                let error = response.text().await?;
                return Err(ClientError::CustomError(format!("Received response: {status_code:?} Error: {error}")));
            }
        };
        Ok(response.result())
    }
}

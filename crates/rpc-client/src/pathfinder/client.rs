use reqwest::{Response, StatusCode};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::json;
use starknet::core::types::TransactionTraceWithHash;
use starknet_types_core::felt::Felt;

use crate::client::{ClientError, ClientVersion};
use crate::pathfinder::proofs::{
    convert_storage_to_pathfinder_class_proof, convert_storage_to_pathfinder_proof, ContractStorageKeysItem,
    PathfinderClassProof, PathfinderProof, StorageProof,
};

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
    let response = client.post(rpc_provider).json(&request).send().await?;

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
    /// The URL version of the RPC client
    rpc_version: ClientVersion,
}

impl PathfinderRpcClient {
    pub fn new(base_url: &str, rpc_version: ClientVersion) -> Self {
        let http_client =
            reqwest::ClientBuilder::new().build().unwrap_or_else(|e| panic!("Could not build reqwest client: {e}"));

        Self { http_client, rpc_base_url: base_url.to_string(), rpc_version }
    }

    pub async fn get_contract_proof(
        &self,
        block_number: u64,
        contract_address: Felt,
        keys: &[Felt],
    ) -> Result<PathfinderProof, ClientError> {
        match &self.rpc_version {
            ClientVersion::Rpcv07 => {
                post_jsonrpc_request(
                    &self.http_client,
                    &format!("{}/rpc/pathfinder/v0_1", &self.rpc_base_url),
                    "pathfinder_getProof",
                    json!({ "block_id": { "block_number": block_number }, "contract_address": contract_address, "keys": keys }),
                )
                .await
            }
            ClientVersion::Rpcv08 => {
                let contracts_storage_keys = ContractStorageKeysItem { contract_address, storage_keys: keys.to_vec() };

                let response: StorageProof = post_jsonrpc_request(
                    &self.http_client,
                    &format!("{}/rpc/{}", &self.rpc_base_url, &self.rpc_version),
                    "starknet_getStorageProof",
                    json!({ "block_id": { "block_number": block_number }, "contract_addresses": &[contract_address], "contracts_storage_keys": &[contracts_storage_keys]  }),
                )
                .await?;

                Ok(convert_storage_to_pathfinder_proof(response))
            }
        }
    }

    pub async fn get_class_proof(
        &self,
        block_number: u64,
        class_hash: &Felt,
    ) -> Result<PathfinderClassProof, ClientError> {
        match &self.rpc_version {
            ClientVersion::Rpcv07 => {
                post_jsonrpc_request(
                    &self.http_client,
                    &format!("{}/rpc/pathfinder/v0_1", &self.rpc_base_url),
                    "pathfinder_getClassProof",
                    json!({ "block_id": { "block_number": block_number }, "class_hash": class_hash }),
                )
                .await
            }
            ClientVersion::Rpcv08 => {
                let response: StorageProof = post_jsonrpc_request(
                    &self.http_client,
                    &format!("{}/rpc/{}", &self.rpc_base_url, &self.rpc_version),
                    "starknet_getStorageProof",
                    json!({ "block_id": { "block_number": block_number }, "class_hashes": [&class_hash] }),
                )
                .await?;

                Ok(convert_storage_to_pathfinder_class_proof(response))
            }
        }
    }

    pub async fn get_block_traces(&self, block_number: u64) -> Result<Vec<TransactionTraceWithHash>, ClientError> {
        post_jsonrpc_request(
            &self.http_client,
            &format!("{}/rpc/v0_7", &self.rpc_base_url),
            "starknet_traceBlockTransactions",
            json!({ "block_id": { "block_number": block_number }}),
        )
        .await
    }
}

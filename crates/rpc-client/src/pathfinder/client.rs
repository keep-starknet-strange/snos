//! Pathfinder-specific RPC client implementation.

use crate::pathfinder::constants::{DEFAULT_REQUEST_TIMEOUT_SECONDS, MAX_STORAGE_KEYS_PER_REQUEST};
use crate::pathfinder::error::ClientError;
use crate::pathfinder::types::request::{Request, TransactionReceiptResponse};
use crate::pathfinder::types::{GetStorageProofResponse, PathfinderClassProof, PathfinderProof};
use anyhow::Result;
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use serde_json::json;
use starknet_types_core::felt::Felt;
use std::collections::VecDeque;
use std::time::Duration;

/// A specialized RPC client for Pathfinder nodes.
///
/// This client provides access to Pathfinder-specific RPC endpoints that are not
/// covered by the standard Starknet RPC specification. It includes functionality
/// for retrieving storage proofs and class proofs.
///
/// # Examples
///
/// ## Getting Storage Proofs
///
/// ```rust
/// use rpc_client::pathfinder::client::PathfinderRpcClient;
/// use starknet_types_core::felt::Felt;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let client = PathfinderRpcClient::new("https://your-pathfinder-node.com");
///
///     let contract_address = Felt::from_hex("0x123...").unwrap();
///     let storage_keys = vec![Felt::from_hex("0x456...").unwrap()];
///
///     let proof = client.get_proof(12345, contract_address, &storage_keys).await?;
///     println!("Proof obtained successfully");
///
///     Ok(())
/// }
/// ```
///
/// ## Getting Class Proofs
///
/// ```rust
/// use rpc_client::pathfinder::client::PathfinderRpcClient;
/// use starknet_types_core::felt::Felt;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let client = PathfinderRpcClient::new("https://your-pathfinder-node.com");
///
///     let class_hash = Felt::from_hex("0x789...").unwrap();
///     let proof = client.get_class_proof(12345, &class_hash).await?;
///     println!("Class proof obtained successfully");
///
///     Ok(())
/// }
/// ```
pub struct PathfinderRpcClient {
    /// HTTP client for making requests to Pathfinder RPC endpoints.
    http_client: reqwest::Client,
    /// The base URL of the Pathfinder RPC server.
    rpc_base_url: String,
}

impl PathfinderRpcClient {
    /// Attempts to create a new Pathfinder RPC client with proper error handling.
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL of the Pathfinder RPC server
    ///
    /// # Returns
    ///
    /// Returns `Ok(Self)` if the client was created successfully, or an error if the
    /// HTTP client cannot be created.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rpc_client::pathfinder::client::PathfinderRpcClient;
    ///
    /// match PathfinderRpcClient::try_new("https://your-pathfinder-node.com") {
    ///     Ok(client) => println!("Client created successfully"),
    ///     Err(e) => eprintln!("Failed to create client: {}", e),
    /// }
    /// ```
    pub fn try_new(base_url: &str) -> Result<Self, ClientError> {
        let starknet_rpc_url = base_url.to_string();
        log::trace!("Initializing Pathfinder RPC client with URL: {}", starknet_rpc_url);

        let http_client = reqwest::ClientBuilder::new()
            .timeout(Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECONDS))
            .build()
            .map_err(|e| ClientError::ConfigurationError(format!("Could not build reqwest client: {e}")))?;

        Ok(Self { http_client, rpc_base_url: base_url.to_string() })
    }

    /// Gets storage proofs for the specified contract and keys at the given block number.
    ///
    /// This method retrieves storage proofs for multiple keys in a single contract.
    /// If no keys are provided, it will return a proof for the entire contract.
    ///
    /// # Arguments
    ///
    /// * `block_number` - The block number at which to get the proof
    /// * `contract_address` - The address of the contract
    /// * `keys` - The storage keys to get proofs for
    ///
    /// # Returns
    ///
    /// Returns a `PathfinderProof` containing the storage proofs or an error if the
    /// request fails.
    ///
    /// # Errors
    ///
    /// Returns a `ClientError` if the RPC request fails, the response cannot be parsed,
    /// or if there are issues with the proof conversion.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rpc_client::pathfinder::client::PathfinderRpcClient;
    /// use starknet_types_core::felt::Felt;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let client = PathfinderRpcClient::new("https://your-pathfinder-node.com");
    ///
    ///     let contract_address = Felt::from_hex("0x123...").unwrap();
    ///     let keys = vec![Felt::from_hex("0x456...").unwrap()];
    ///
    ///     let proof = client.get_proof(12345, contract_address, &keys).await?;
    ///     println!("Proof obtained for {} keys", keys.len());
    ///
    ///     Ok(())
    /// }
    /// ```
    pub async fn get_proof(
        &self,
        block_number: u64,
        contract_address: Felt,
        keys: &[Felt],
    ) -> Result<PathfinderProof, ClientError> {
        let mut proofs = VecDeque::new();

        if keys.is_empty() {
            // Get proof for the entire contract
            let proof = self.get_proof_one_key(block_number, contract_address, None).await?;
            proofs.push_back(proof);
        } else {
            // Get proofs for each key, batching requests if possible
            for chunk in keys.chunks(MAX_STORAGE_KEYS_PER_REQUEST) {
                let proof = self.get_proof_multiple_keys(block_number, contract_address, chunk).await?;
                proofs.push_back(proof);
            }
        }

        // Merge all the proofs into a single proof
        let mut proof = proofs.pop_front().expect("must have at least one proof");
        let contract_data = proof.contract_data.as_mut().expect("must have contract data");

        for additional_proof in proofs {
            let additional_contract_data = additional_proof.contract_data.expect("must have contract data");
            contract_data.storage_proofs.extend(additional_contract_data.storage_proofs);
        }

        Ok(proof)
    }

    /// Gets a proof for a class at the given block number.
    ///
    /// # Arguments
    ///
    /// * `block_number` - The block number at which to get the proof
    /// * `class_hash` - The hash of the class to get the proof for
    ///
    /// # Returns
    ///
    /// Returns a `PathfinderClassProof` containing the class proof or an error if the
    /// request fails.
    ///
    /// # Errors
    ///
    /// Returns a `ClientError` if the RPC request fails or the response cannot be parsed.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rpc_client::pathfinder::client::PathfinderRpcClient;
    /// use starknet_types_core::felt::Felt;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let client = PathfinderRpcClient::new("https://your-pathfinder-node.com");
    ///
    ///     let class_hash = Felt::from_hex("0x789...").unwrap();
    ///     let proof = client.get_class_proof(12345, &class_hash).await?;
    ///     println!("Class proof obtained successfully");
    ///
    ///     Ok(())
    /// }
    /// ```
    pub async fn get_class_proof(
        &self,
        block_number: u64,
        class_hash: &Felt,
    ) -> Result<PathfinderClassProof, ClientError> {
        log::debug!("Querying starknet_getStorageProofs for class {:x} at block {:x}", class_hash, block_number);

        let response = self
            .send_request::<GetStorageProofResponse>(
                "starknet_getStorageProof",
                json!({ "block_id": { "block_number": block_number }, "class_hashes": [class_hash] }),
            )
            .await?;

        Ok(PathfinderClassProof::from(response))
    }

    /// Gets a proof for a single key for the given contract at the given block number.
    ///
    /// This is a helper method that gets a proof for a single storage key. For multiple
    /// keys, consider using `get_proof_multiple_keys` or `get_proof` for better efficiency.
    ///
    /// # Arguments
    ///
    /// * `block_number` - The block number at which to get the proof
    /// * `contract_address` - The address of the contract
    /// * `key` - The storage key to get the proof for, or `None` for the entire contract
    ///
    /// # Returns
    ///
    /// Returns a `PathfinderProof` containing the storage proof or an error if the
    /// request fails.
    ///
    /// # Errors
    ///
    /// Returns a `ClientError` if the RPC request fails or the response cannot be parsed.
    async fn get_proof_one_key(
        &self,
        block_number: u64,
        contract_address: Felt,
        key: Option<Felt>,
    ) -> Result<PathfinderProof, ClientError> {
        let keys = if let Some(key) = key { vec![key] } else { Vec::new() };
        self.get_proof_multiple_keys(block_number, contract_address, &keys).await
    }

    /// Gets a proof for multiple keys for the given contract at the given block number.
    ///
    /// This method efficiently retrieves proofs for multiple storage keys in a single
    /// RPC request, up to the maximum allowed number of keys per request.
    ///
    /// # Arguments
    ///
    /// * `block_number` - The block number at which to get the proof
    /// * `contract_address` - The address of the contract
    /// * `keys` - The storage keys to get proofs for
    ///
    /// # Returns
    ///
    /// Returns a `PathfinderProof` containing the storage proofs or an error if the
    /// request fails.
    ///
    /// # Errors
    ///
    /// Returns a `ClientError` if the RPC request fails or the response cannot be parsed.
    async fn get_proof_multiple_keys(
        &self,
        block_number: u64,
        contract_address: Felt,
        keys: &[Felt],
    ) -> Result<PathfinderProof, ClientError> {
        let json = json!({
            "block_id": { "block_number": block_number },
            "contract_addresses": [contract_address],
            "contracts_storage_keys": [{
                "contract_address": contract_address,
                "storage_keys": keys
            }]
        });

        log::debug!(
            "Querying starknet_getStorageProof for address {:x} with {} keys at block {:x}",
            contract_address,
            keys.len(),
            block_number
        );

        let response = self.send_request::<GetStorageProofResponse>("starknet_getStorageProof", json).await?;
        PathfinderProof::try_from(response)
    }

    /// Sends a JSON-RPC request to the Pathfinder server.
    ///
    /// # Arguments
    ///
    /// * `method` - The JSON-RPC method name
    /// * `params` - The JSON-RPC parameters
    ///
    /// # Returns
    ///
    /// Returns the deserialized response or an error if the request fails.
    ///
    /// # Errors
    ///
    /// Returns a `ClientError` if the HTTP request fails, the response status is not OK,
    /// or if the response cannot be deserialized.
    async fn send_request<T: DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T, ClientError> {
        let request = Request::new(method, params);
        let url = format!("{}/rpc/v0_8", self.rpc_base_url);

        let response = self.http_client.post(&url).json(&request).send().await?;

        match response.status() {
            StatusCode::OK => {
                let response: TransactionReceiptResponse<T> = response.json().await?;
                Ok(response.result())
            }
            status_code => {
                let error_text = response.text().await?;
                Err(ClientError::CustomError(format!("Received response: {status_code:?} Error: {error_text}")))
            }
        }
    }
}

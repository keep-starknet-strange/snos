//! Main RPC client implementation for unified Starknet and Pathfinder access.

use anyhow::anyhow;
use futures::stream::{self, StreamExt};
use log::info;
use reqwest::Url;
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Provider, ProviderError};
use starknet_core::types::{ConfirmedBlockId, ContractStorageKeys, StorageKey};
use starknet_types_core::felt::Felt;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use crate::constants::{MAX_CONCURRENT_PROOF_REQUESTS, MAX_STORAGE_KEYS_PER_REQUEST, STARKNET_RPC_VERSION};
use crate::types::{ClassProof, ContractProof};
use crate::utils::execute_with_retry;

const DEFAULT_RPC_REQUEST_TIMEOUT_SECS: u64 = 60;
const DEFAULT_RPC_CONNECT_TIMEOUT_SECS: u64 = 5;
const DEFAULT_RPC_POOL_MAX_IDLE_PER_HOST: usize = 0;
const RPC_REQUEST_TIMEOUT_ENV: &str = "SNOS_RPC_REQUEST_TIMEOUT_SECS";
const RPC_CONNECT_TIMEOUT_ENV: &str = "SNOS_RPC_CONNECT_TIMEOUT_SECS";
const RPC_POOL_MAX_IDLE_PER_HOST_ENV: &str = "SNOS_RPC_POOL_MAX_IDLE_PER_HOST";
const MAX_STORAGE_KEYS_PER_REQUEST_ENV: &str = "SNOS_MAX_STORAGE_KEYS_PER_PROOF_REQUEST";
const MAX_CONCURRENT_PROOF_REQUESTS_ENV: &str = "SNOS_MAX_CONCURRENT_PROOF_REQUESTS";

pub trait ProofClient {
    fn get_proof(
        &self,
        block_number: u64,
        contract_address: Felt,
        keys: &[Felt],
    ) -> impl std::future::Future<Output = Result<ContractProof, ProviderError>> + Send;
    fn get_class_proof(
        &self,
        block_number: u64,
        class_hash: &Felt,
    ) -> impl std::future::Future<Output = Result<ClassProof, ProviderError>> + Send;
    fn get_proof_one_key(
        &self,
        block_number: u64,
        contract_address: Felt,
        key: Option<Felt>,
    ) -> impl std::future::Future<Output = Result<ContractProof, ProviderError>> + Send;
    fn get_proof_multiple_keys(
        &self,
        block_number: u64,
        contract_address: Felt,
        keys: &[Felt],
    ) -> impl std::future::Future<Output = Result<ContractProof, ProviderError>> + Send;
}

/// Internal structure containing the underlying RPC clients.
///
/// This struct encapsulates both the standard Starknet RPC client and the Pathfinder-specific
/// client, providing a unified interface for accessing different types of RPC endpoints.
struct RpcClientInner {
    /// Starknet-rs client for accessing standard Starknet RPC endpoints.
    starknet_client: JsonRpcClient<HttpTransport>,
}

impl RpcClientInner {
    fn read_env_u64(name: &str, default: u64) -> u64 {
        std::env::var(name).ok().and_then(|value| value.parse::<u64>().ok()).unwrap_or(default)
    }

    fn read_env_usize(name: &str, default: usize) -> usize {
        std::env::var(name).ok().and_then(|value| value.parse::<usize>().ok()).unwrap_or(default)
    }

    /// Creates a new RPC client inner with both Starknet and Pathfinder clients.
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL of the RPC server
    ///
    /// # Error
    ///
    /// This function will throw an error if the URL cannot be parsed or if the HTTP client
    /// cannot be created.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rpc_client::client::RpcClientInner;
    ///
    /// let inner = RpcClientInner::new("https://your-starknet-node.com");
    /// ```
    fn try_new(base_url: &str) -> anyhow::Result<Self> {
        let starknet_rpc_url = format!("{}/rpc/{}", base_url, STARKNET_RPC_VERSION);
        info!("Initializing Starknet RPC client with URL: {}", starknet_rpc_url);

        let rpc_request_timeout_secs = Self::read_env_u64(RPC_REQUEST_TIMEOUT_ENV, DEFAULT_RPC_REQUEST_TIMEOUT_SECS);
        let rpc_connect_timeout_secs = Self::read_env_u64(RPC_CONNECT_TIMEOUT_ENV, DEFAULT_RPC_CONNECT_TIMEOUT_SECS);
        let rpc_pool_max_idle_per_host =
            Self::read_env_usize(RPC_POOL_MAX_IDLE_PER_HOST_ENV, DEFAULT_RPC_POOL_MAX_IDLE_PER_HOST);
        info!(
            "RPC client config: request_timeout={}s connect_timeout={}s pool_max_idle_per_host={}",
            rpc_request_timeout_secs, rpc_connect_timeout_secs, rpc_pool_max_idle_per_host
        );

        let starknet_rpc_url = Url::parse(starknet_rpc_url.as_str())
            .map_err(|e| anyhow!("Failed to parse URL ({}): {}", starknet_rpc_url, e))?;
        let http_client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(rpc_connect_timeout_secs))
            .pool_max_idle_per_host(rpc_pool_max_idle_per_host)
            .timeout(Duration::from_secs(rpc_request_timeout_secs))
            .build()
            .map_err(|e| anyhow!("Failed to create reqwest client for {}: {}", starknet_rpc_url, e))?;

        let provider = JsonRpcClient::new(HttpTransport::new_with_client(starknet_rpc_url, http_client));

        Ok(Self { starknet_client: provider })
    }
}

/// A unified RPC client for interacting with Starknet nodes.
///
/// This client provides access to both standard Starknet RPC endpoints and Pathfinder-specific
/// extensions through a single interface. It's designed to be thread-safe and can be cloned
/// for use across multiple tasks.
///
/// # Examples
///
/// ## Basic Usage
///
/// ```rust
/// use rpc_client::RpcClient;
/// use starknet::core::types::BlockId;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let client = RpcClient::new("https://your-starknet-node.com");
///
///     // Get the latest block
///     let block = client.starknet_rpc().get_block(BlockId::Latest).await?;
///     println!("Latest block number: {}", block.block_number);
///
///     Ok(())
/// }
/// ```
#[derive(Clone)]
pub struct RpcClient {
    /// The inner client containing both Starknet and Pathfinder clients.
    inner: Arc<RpcClientInner>,
}

impl RpcClient {
    /// Creates a new RPC client with the specified base URL.
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL of the RPC server (e.g., "https://your-starknet-node.com")
    ///
    /// # Returns
    ///
    /// A new `RpcClient` instance.
    ///
    /// # Error
    ///
    /// This function will throw an error if the URL is invalid or if the HTTP client cannot be created.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rpc_client::RpcClient;
    ///
    /// let client = RpcClient::new("https://your-starknet-node.com");
    /// ```
    pub fn try_new(base_url: &str) -> anyhow::Result<Self> {
        Ok(Self { inner: Arc::new(RpcClientInner::try_new(base_url)?) })
    }

    /// Returns a reference to the underlying Starknet RPC client.
    ///
    /// This client provides access to all standard Starknet RPC endpoints as defined
    /// in the Starknet RPC specification.
    ///
    /// # Returns
    ///
    /// A reference to the Starknet RPC client.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rpc_client::RpcClient;
    /// use starknet::core::types::BlockId;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let client = RpcClient::new("https://your-starknet-node.com");
    ///
    ///     // Use the Starknet RPC client directly
    ///     let block = client.starknet_rpc().get_block(BlockId::Latest).await?;
    ///     println!("Block hash: {:?}", block.block_hash);
    ///
    ///     Ok(())
    /// }
    /// ```
    #[must_use]
    pub fn starknet_rpc(&self) -> &JsonRpcClient<HttpTransport> {
        &self.inner.starknet_client
    }
}

impl ProofClient for JsonRpcClient<HttpTransport> {
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
    /// Returns a `ContractProof` containing the storage proofs or an error if the
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
    async fn get_proof(
        &self,
        block_number: u64,
        contract_address: Felt,
        keys: &[Felt],
    ) -> Result<ContractProof, ProviderError> {
        if keys.is_empty() {
            let operation_name =
                format!("get_proof(block_number: {block_number}, contract_address: {contract_address:#x}, keys: 0)");
            return execute_with_retry(&operation_name, || {
                self.get_proof_one_key(block_number, contract_address, None)
            })
            .await;
        }

        let max_storage_keys_per_request =
            RpcClientInner::read_env_usize(MAX_STORAGE_KEYS_PER_REQUEST_ENV, MAX_STORAGE_KEYS_PER_REQUEST).max(1);
        let max_concurrent_proof_requests =
            RpcClientInner::read_env_usize(MAX_CONCURRENT_PROOF_REQUESTS_ENV, MAX_CONCURRENT_PROOF_REQUESTS).max(1);

        let proof_chunks = fetch_proof_chunks(
            block_number,
            contract_address,
            keys,
            max_storage_keys_per_request,
            max_concurrent_proof_requests,
            |chunk_index, chunk| {
                let operation_name = format!(
                    "get_proof(block_number: {block_number}, contract_address: {contract_address:#x}, total_keys: {}, chunk_index: {}, chunk_keys: {})",
                    keys.len(),
                    chunk_index,
                    chunk.len()
                );
                async move {
                    execute_with_retry(&operation_name, || {
                        self.get_proof_multiple_keys(block_number, contract_address, &chunk)
                    })
                    .await
                }
            },
        )
        .await?;

        // TODO: Return proper errors
        let mut proofs: VecDeque<_> = proof_chunks.into();

        // Merge all the proofs into a single proof
        let mut proof = proofs.pop_front().ok_or(ProviderError::ArrayLengthMismatch)?;
        let contract_data = proof.contract_data.as_mut().ok_or(ProviderError::ArrayLengthMismatch)?;

        // Combine all storage proofs in contract data.
        // NOTE: storage_proof is a vector of proofs. Each of them is the union of all the paths
        // of storage keys from root to leave for a single contract.
        // So, storage_proofs.len() == num of contracts sent
        for additional_proof in proofs {
            contract_data
                .storage_proofs
                .extend(additional_proof.contract_data.ok_or(ProviderError::ArrayLengthMismatch)?.storage_proofs);
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
    /// Returns a `ClassProof` containing the class proof or an error if the
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
    async fn get_class_proof(&self, block_number: u64, class_hash: &Felt) -> Result<ClassProof, ProviderError> {
        info!("Querying starknet_getStorageProofs for class {:x} at block {:x}", class_hash, block_number);

        Ok(self.get_storage_proof(ConfirmedBlockId::Number(block_number), [*class_hash], [], []).await?.into())
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
    /// Returns a `ContractProof` containing the storage proof or an error if the
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
    ) -> Result<ContractProof, ProviderError> {
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
    /// Returns a `ContractProof` containing the storage proofs or an error if the
    /// request fails.
    ///
    /// # Errors
    ///
    /// Returns a `ClientError` if the RPC request fails or the response cannot be parsed.
    async fn get_proof_multiple_keys(
        &self,
        block_number: u64,
        contract_address: Felt,
        storage_keys: &[Felt],
    ) -> Result<ContractProof, ProviderError> {
        info!(
            "Querying starknet_getStorageProof for address {:x} with {} keys at block {:x}",
            contract_address,
            storage_keys.len(),
            block_number
        );

        self.get_storage_proof(
            ConfirmedBlockId::Number(block_number),
            [],
            [contract_address],
            [ContractStorageKeys {
                contract_address,
                storage_keys: storage_keys.iter().map(|k| StorageKey(k.to_hex_string())).collect(),
            }],
        )
        .await?
        .try_into()
    }
}

async fn fetch_proof_chunks<F, Fut>(
    block_number: u64,
    contract_address: Felt,
    keys: &[Felt],
    max_keys_per_request: usize,
    max_concurrent_proof_requests: usize,
    fetch_chunk: F,
) -> Result<Vec<ContractProof>, ProviderError>
where
    F: Fn(usize, Vec<Felt>) -> Fut + Clone,
    Fut: std::future::Future<Output = Result<ContractProof, ProviderError>>,
{
    let chunks: Vec<_> = keys.chunks(max_keys_per_request).map(|chunk| chunk.to_vec()).collect();

    info!("Fetching proofs for {} chunks with max {} concurrent requests", chunks.len(), max_concurrent_proof_requests);

    stream::iter(chunks.into_iter().enumerate())
        .map(|(chunk_index, chunk)| {
            let fetch_chunk = fetch_chunk.clone();
            async move {
                info!(
                    "Calling RPC for contract {:x} at block {:x} with chunk {} / {} keys",
                    contract_address,
                    block_number,
                    chunk_index,
                    chunk.len()
                );
                fetch_chunk(chunk_index, chunk).await
            }
        })
        .buffer_unordered(max_concurrent_proof_requests)
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use tokio::sync::Mutex;

    use super::*;

    fn dummy_contract_proof(chunk_index: usize) -> ContractProof {
        ContractProof {
            contract_data: Some(crate::types::ContractData {
                root: Felt::from(chunk_index as u64 + 1),
                storage_proofs: vec![vec![]],
            }),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn fetch_proof_chunks_retries_only_failed_chunk() {
        let keys: Vec<Felt> = (0..181).map(Felt::from).collect();
        let attempts: Arc<Mutex<HashMap<usize, usize>>> = Arc::new(Mutex::new(HashMap::new()));

        let proofs = fetch_proof_chunks(42, Felt::from(7_u64), &keys, 90, 10, {
            let attempts = Arc::clone(&attempts);
            move |chunk_index, chunk| {
                let attempts = Arc::clone(&attempts);
                let chunk_len = chunk.len();
                let operation_name = format!("test chunk {chunk_index} ({chunk_len} keys)");
                async move {
                    execute_with_retry(&operation_name, || {
                        let attempts = Arc::clone(&attempts);
                        async move {
                            let current_attempt = {
                                let mut attempts = attempts.lock().await;
                                let entry = attempts.entry(chunk_index).or_insert(0);
                                *entry += 1;
                                *entry
                            };

                            if chunk_index == 1 && current_attempt == 1 {
                                return Err(ProviderError::RateLimited);
                            }

                            assert!(chunk_len <= 90);
                            Ok(dummy_contract_proof(chunk_index))
                        }
                    })
                    .await
                }
            }
        })
        .await
        .expect("chunk fetch should succeed after retrying the flaky chunk");

        assert_eq!(proofs.len(), 3);

        let attempts = attempts.lock().await;
        assert_eq!(attempts.get(&0), Some(&1));
        assert_eq!(attempts.get(&1), Some(&2));
        assert_eq!(attempts.get(&2), Some(&1));
    }
}

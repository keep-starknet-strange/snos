//! Main RPC client implementation for unified Starknet and Pathfinder access.

use anyhow::anyhow;
use futures::stream::{self, StreamExt};
use log::{debug, info, warn};
use reqwest::Url;
use starknet::core::types::{
    BlockId, ConfirmedBlockId, MaybePreConfirmedBlockWithTxHashes, MaybePreConfirmedBlockWithTxs,
    MaybePreConfirmedStateUpdate, TransactionTraceWithHash,
};
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Provider, ProviderError};
use starknet_core::types::{ContractStorageKeys, StorageKey};
use starknet_types_core::felt::Felt;
use std::collections::VecDeque;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

use crate::constants::{MAX_CONCURRENT_PROOF_REQUESTS, MAX_STORAGE_KEYS_PER_REQUEST, STARKNET_RPC_VERSION};
use crate::types::{ClassProof, ContractProof};

const DEFAULT_RPC_REQUEST_TIMEOUT_SECS: u64 = 60;
const DEFAULT_RPC_CONNECT_TIMEOUT_SECS: u64 = 5;
const DEFAULT_RPC_POOL_MAX_IDLE_PER_HOST: usize = 0;
const RPC_REQUEST_TIMEOUT_ENV: &str = "SNOS_RPC_REQUEST_TIMEOUT_SECS";
const RPC_CONNECT_TIMEOUT_ENV: &str = "SNOS_RPC_CONNECT_TIMEOUT_SECS";
const RPC_POOL_MAX_IDLE_PER_HOST_ENV: &str = "SNOS_RPC_POOL_MAX_IDLE_PER_HOST";
const MAX_RPC_RETRIES: u32 = 5;
const INITIAL_RPC_RETRY_BACKOFF_MS: u64 = 100;
const MAX_RPC_RETRY_BACKOFF_MS: u64 = 2000;

fn is_retryable_provider_error(error: &ProviderError) -> bool {
    matches!(
        error,
        ProviderError::Other(_)
            | ProviderError::RateLimited
            | ProviderError::StarknetError(starknet::core::types::StarknetError::UnexpectedError(_))
    )
}

async fn execute_with_retry<T, F, Fut>(operation_name: &str, mut f: F) -> Result<T, ProviderError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, ProviderError>>,
{
    let mut attempt: u32 = 0;
    let mut backoff_ms = INITIAL_RPC_RETRY_BACKOFF_MS;

    loop {
        attempt += 1;

        match f().await {
            Ok(result) => {
                if attempt > 1 {
                    debug!("{}: succeeded after {} attempts", operation_name, attempt);
                }
                return Ok(result);
            }
            Err(error) => {
                let retries_used = attempt.saturating_sub(1);
                let retries_exhausted = retries_used >= MAX_RPC_RETRIES;
                let is_retryable = is_retryable_provider_error(&error);

                if !is_retryable || retries_exhausted {
                    if attempt > 1 {
                        warn!("{}: failed after {} attempts with error: {:?}", operation_name, attempt, error);
                    }
                    return Err(error);
                }

                let retries_left = MAX_RPC_RETRIES.saturating_sub(retries_used);
                info!(
                    "{}: attempt {} failed with retryable error: {:?}, retrying in {}ms ({} retries left)",
                    operation_name, attempt, error, backoff_ms, retries_left
                );

                sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms * 2).min(MAX_RPC_RETRY_BACKOFF_MS);
            }
        }
    }
}

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
///     let client = RpcClient::try_new("https://your-starknet-node.com")?;
///
///     let block = client.starknet().get_block_with_tx_hashes(BlockId::Number(12345)).await?;
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

/// Retry-enabled Starknet RPC facade returned by [`RpcClient::starknet`].
#[derive(Clone, Copy)]
pub struct StarknetRpc<'a> {
    provider: &'a JsonRpcClient<HttpTransport>,
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
    /// let client = RpcClient::try_new("https://your-starknet-node.com")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn try_new(base_url: &str) -> anyhow::Result<Self> {
        Ok(Self { inner: Arc::new(RpcClientInner::try_new(base_url)?) })
    }

    /// Returns the retrying Starknet RPC facade.
    ///
    /// All standard Starknet RPC calls should go through this accessor so transport retry
    /// behavior stays consistent across the codebase.
    #[must_use]
    pub fn starknet(&self) -> StarknetRpc<'_> {
        StarknetRpc { provider: &self.inner.starknet_client }
    }
}

impl StarknetRpc<'_> {
    pub async fn chain_id(&self) -> Result<Felt, ProviderError> {
        execute_with_retry("chain_id", || self.provider.chain_id()).await
    }

    pub async fn get_block_with_txs(&self, block_id: BlockId) -> Result<MaybePreConfirmedBlockWithTxs, ProviderError> {
        let operation_name = format!("get_block_with_txs(block_id: {:?})", block_id);
        execute_with_retry(&operation_name, || self.provider.get_block_with_txs(block_id)).await
    }

    pub async fn get_block_with_tx_hashes(
        &self,
        block_id: BlockId,
    ) -> Result<MaybePreConfirmedBlockWithTxHashes, ProviderError> {
        let operation_name = format!("get_block_with_tx_hashes(block_id: {:?})", block_id);
        execute_with_retry(&operation_name, || self.provider.get_block_with_tx_hashes(block_id)).await
    }

    pub async fn get_state_update(&self, block_id: BlockId) -> Result<MaybePreConfirmedStateUpdate, ProviderError> {
        let operation_name = format!("get_state_update(block_id: {:?})", block_id);
        execute_with_retry(&operation_name, || self.provider.get_state_update(block_id)).await
    }

    pub async fn trace_block_transactions(
        &self,
        block_id: ConfirmedBlockId,
    ) -> Result<Vec<TransactionTraceWithHash>, ProviderError> {
        let operation_name = format!("trace_block_transactions(block_id: {:?})", block_id);
        execute_with_retry(&operation_name, || self.provider.trace_block_transactions(block_id)).await
    }

    pub async fn get_storage_at(
        &self,
        contract_address: Felt,
        storage_key: Felt,
        block_id: BlockId,
    ) -> Result<Felt, ProviderError> {
        let operation_name = format!(
            "get_storage_at(contract_address: {:#x}, storage_key: {:#x}, block_id: {:?})",
            contract_address, storage_key, block_id
        );
        execute_with_retry(&operation_name, || self.provider.get_storage_at(contract_address, storage_key, block_id))
            .await
    }

    pub async fn get_nonce(&self, block_id: BlockId, contract_address: Felt) -> Result<Felt, ProviderError> {
        let operation_name = format!("get_nonce(contract_address: {:#x}, block_id: {:?})", contract_address, block_id);
        execute_with_retry(&operation_name, || self.provider.get_nonce(block_id, contract_address)).await
    }

    pub async fn get_class_hash_at(&self, block_id: BlockId, contract_address: Felt) -> Result<Felt, ProviderError> {
        let operation_name =
            format!("get_class_hash_at(contract_address: {:#x}, block_id: {:?})", contract_address, block_id);
        execute_with_retry(&operation_name, || self.provider.get_class_hash_at(block_id, contract_address)).await
    }

    pub async fn get_class(
        &self,
        block_id: BlockId,
        class_hash: Felt,
    ) -> Result<starknet::core::types::ContractClass, ProviderError> {
        let operation_name = format!("get_class(class_hash: {:#x}, block_id: {:?})", class_hash, block_id);
        execute_with_retry(&operation_name, || self.provider.get_class(block_id, class_hash)).await
    }

    pub async fn get_proof(
        &self,
        block_number: u64,
        contract_address: Felt,
        keys: &[Felt],
    ) -> Result<ContractProof, ProviderError> {
        let operation_name = format!(
            "get_proof(contract_address: {:#x}, keys: {}, block_number: {})",
            contract_address,
            keys.len(),
            block_number
        );
        execute_with_retry(&operation_name, || self.provider.get_proof(block_number, contract_address, keys)).await
    }

    pub async fn get_class_proof(&self, block_number: u64, class_hash: &Felt) -> Result<ClassProof, ProviderError> {
        let operation_name = format!("get_class_proof(class_hash: {:#x}, block_number: {})", class_hash, block_number);
        execute_with_retry(&operation_name, || self.provider.get_class_proof(block_number, class_hash)).await
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
        // TODO: Return proper errors
        let mut proofs = VecDeque::new();

        if keys.is_empty() {
            // Get proof for the entire contract
            let proof = self.get_proof_one_key(block_number, contract_address, None).await?;
            proofs.push_back(proof);
        } else {
            // Get proofs for each key chunk concurrently
            let chunks: Vec<_> = keys.chunks(MAX_STORAGE_KEYS_PER_REQUEST).map(|c| c.to_vec()).collect();

            info!(
                "Fetching proofs for {} chunks with max {} concurrent requests",
                chunks.len(),
                MAX_CONCURRENT_PROOF_REQUESTS
            );

            // Create futures for all chunks and execute them concurrently
            let chunk_proofs: Vec<ContractProof> = stream::iter(chunks)
                .map(|chunk| {
                    let chunk_len = chunk.len();
                    async move {
                        info!("Calling RPC with {} keys", chunk_len);
                        self.get_proof_multiple_keys(block_number, contract_address, &chunk).await
                    }
                })
                .buffer_unordered(MAX_CONCURRENT_PROOF_REQUESTS)
                .collect::<Vec<_>>()
                .await
                .into_iter()
                .collect::<Result<Vec<_>, _>>()?;

            proofs.extend(chunk_proofs);
        }

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

#[cfg(test)]
mod tests {
    use super::is_retryable_provider_error;
    use starknet::core::types::StarknetError;
    use starknet::providers::{ProviderError, ProviderImplError};
    use std::any::Any;

    #[derive(Debug, thiserror::Error)]
    #[error("test provider impl error")]
    struct TestProviderImplError;

    impl ProviderImplError for TestProviderImplError {
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[test]
    fn classifies_retryable_provider_errors() {
        assert!(is_retryable_provider_error(&ProviderError::RateLimited));
        assert!(is_retryable_provider_error(&ProviderError::Other(Box::new(TestProviderImplError))));
        assert!(is_retryable_provider_error(&ProviderError::StarknetError(StarknetError::UnexpectedError(
            "transient".to_string(),
        ))));
    }

    #[test]
    fn classifies_non_retryable_provider_errors() {
        assert!(!is_retryable_provider_error(&ProviderError::StarknetError(StarknetError::ContractNotFound)));
        assert!(!is_retryable_provider_error(&ProviderError::StarknetError(StarknetError::ClassHashNotFound)));
        assert!(!is_retryable_provider_error(&ProviderError::ArrayLengthMismatch));
    }
}

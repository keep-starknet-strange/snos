//! Main RPC client implementation for unified Starknet and Pathfinder access.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use reqwest::Url;
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::JsonRpcClient;

use crate::constants::STARKNET_RPC_VERSION;
use crate::pathfinder::client::PathfinderRpcClient;
/// Internal structure containing the underlying RPC clients.
///
/// This struct encapsulates both the standard Starknet RPC client and the Pathfinder-specific
/// client, providing a unified interface for accessing different types of RPC endpoints.
struct RpcClientInner {
    // TODO: Update this to remove the pathfinder client and merge it into the starknet client.
    /// Starknet-rs client for accessing standard Starknet RPC endpoints.
    starknet_client: JsonRpcClient<HttpTransport>,
    /// Pathfinder-specific client for accessing non-standard endpoints.
    pathfinder_client: PathfinderRpcClient,
}

impl RpcClientInner {
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
    fn try_new(base_url: &str) -> Result<Self> {
        let starknet_rpc_url = format!("{}/rpc/{}", base_url, STARKNET_RPC_VERSION);
        log::info!("Initializing Starknet RPC client with URL: {}", starknet_rpc_url);

        let provider = JsonRpcClient::new(HttpTransport::new(
            Url::parse(starknet_rpc_url.as_str())
                .map_err(|e| anyhow!("Failed to parse URL ({}): {}", starknet_rpc_url, e))?,
        ));

        let pathfinder_client = PathfinderRpcClient::try_new(base_url)?;

        Ok(Self { starknet_client: provider, pathfinder_client })
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
///
/// ## Using Pathfinder Extensions
///
/// ```rust
/// use rpc_client::RpcClient;
/// use starknet_types_core::felt::Felt;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let client = RpcClient::new("https://your-starknet-node.com");
///
///     // Get storage proof
///     let contract_address = Felt::from_hex("0x123...").unwrap();
///     let storage_key = Felt::from_hex("0x456...").unwrap();
///
///     let proof = client.pathfinder_rpc().get_proof(
///         12345, // block number
///         contract_address,
///         &[storage_key]
///     ).await?;
///
///     println!("Proof obtained successfully");
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
    pub fn try_new(base_url: &str) -> Result<Self> {
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

    /// Returns a reference to the Pathfinder-specific RPC client.
    ///
    /// This client provides access to Pathfinder-specific endpoints that are not part
    /// of the standard Starknet RPC specification, such as proof endpoints.
    ///
    /// # Returns
    ///
    /// A reference to the Pathfinder RPC client.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rpc_client::RpcClient;
    /// use starknet_types_core::felt::Felt;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let client = RpcClient::new("https://your-starknet-node.com");
    ///
    ///     // Use the Pathfinder RPC client directly
    ///     let contract_address = Felt::from_hex("0x123...").unwrap();
    ///     let proof = client.pathfinder_rpc().get_proof(
    ///         12345,
    ///         contract_address,
    ///         &[]
    ///     ).await?;
    ///
    ///     println!("Proof obtained successfully");
    ///     Ok(())
    /// }
    /// ```
    #[must_use]
    pub fn pathfinder_rpc(&self) -> &PathfinderRpcClient {
        &self.inner.pathfinder_client
    }
}

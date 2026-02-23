//! # RPC Client
//!
//! This crate provides a unified RPC client for interacting with Starknet nodes through
//! Starknet RPC endpoints, including storage/class proof calls used by SNOS.
//!
//! ## Features
//!
//! - **Unified Client**: Single interface for Starknet RPC + proof access
//! - **Async Support**: Full async/await support for all operations
//! - **Proof Verification**: Built-in support for storage and class proof verification
//! - **State Reading**: High-level state reading interface for contract interactions
//! - **Error Handling**: Comprehensive error handling with proper error types
//!
//! ## Modules
//!
//! - [`client`] - Main RPC client implementation
//! - [`state_reader`] - High-level state reading interface
//! - [`utils`] - Utility functions for async operations
//!
//! ## Usage
//!
//! ```no_run
//! use rpc_client::RpcClient;
//! use rpc_client::client::ProofClient;
//! use starknet::core::types::BlockId;
//! use starknet::providers::Provider;
//! use starknet_core::types::BlockTag;
//! use starknet_types_core::felt::Felt;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create a new RPC client
//!     let client = RpcClient::try_new("https://your-starknet-node.com")?;
//!
//!     // Use standard Starknet RPC
//!     let block = client
//!         .starknet_rpc()
//!         .get_block_with_txs(BlockId::Tag(BlockTag::Latest))
//!         .await?;
//!
//!     // Use proof RPC (same client)
//!     let proof = client.starknet_rpc().get_proof(
//!         12345,
//!         Felt::from(12345),
//!         &[Felt::from(12345)]
//!     ).await?;
//!
//!     Ok(())
//! }
//! ```

pub mod client;
pub mod constants;
pub mod error;
pub mod state_reader;
pub mod types;
pub mod utils;

pub use client::RpcClient;

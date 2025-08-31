//! Type definitions for Pathfinder RPC responses and data structures.
//!
//! This module contains type definitions that are specific to Pathfinder RPC endpoints
//! and are not covered by the standard Starknet RPC specification. These types are
//! used for handling storage proofs, class proofs, and other Pathfinder-specific
//! data structures.
//!
//! ## Modules
//!
//! - [`nodes`] - Merkle tree node types and structures
//! - [`proofs`] - Proof-related types for storage and class proofs
//! - [`storage_proof`] - Storage proof response types
//! - [`request`] - JSON-RPC request and response types
//! - [`hash`] - Hash-related type definitions
//!
//! ## Note
//!
//! These types are copied from `katana-rpc-types` to avoid dependency on `katana-rpc-types`
//! which makes it difficult to manage dependencies in this project.

pub mod hash;
pub mod nodes;
pub mod proofs;
pub mod request;
pub mod storage_proof;

pub use nodes::{MerkleNode, NodeWithHash, Nodes};
pub use proofs::{ContractData, PathfinderClassProof, PathfinderProof, TrieNode};
pub use storage_proof::GetStorageProofResponse;

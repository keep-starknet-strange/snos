use crate::pathfinder::types::proofs::Height;
use crate::pathfinder::types::TrieNode;
use starknet_types_core::felt::Felt;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("Encountered a request error: {0}")]
    ReqwestError(#[from] reqwest::Error),
    #[error("Encountered a custom error: {0}")]
    CustomError(String),
    #[error("Failed to convert response to PathfinderProof: {0}")]
    ProofConversionError(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ProofVerificationError {
    #[error("Non-inclusion proof for key {}. Height {}.", key.to_hex_string(), height.0)]
    NonExistenceProof { key: Felt, height: Height, node: TrieNode },

    #[error("Proof verification failed, node_hash {node_hash:x} != parent_hash {parent_hash:x}")]
    InvalidChildNodeHash { node_hash: Felt, parent_hash: Felt },

    #[error("Proof is empty")]
    EmptyProof,

    #[error("Conversion error")]
    ConversionError,

    #[error("Proof error: {0}")]
    ProofError(String),
}

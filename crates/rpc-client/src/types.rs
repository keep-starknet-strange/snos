//! Copied from `katana-rpc-types` to avoid dependency on `katana-rpc-types` (makes it difficult to manage dependencies)

use std::ops::{Deref, DerefMut};

use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContractStorageKeys {
    #[serde(rename = "contract_address")]
    pub address: Felt,
    #[serde(rename = "storage_keys")]
    pub keys: Vec<Felt>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GlobalRoots {
    /// The associated block hash (needed in case the caller used a block tag for the block_id
    /// parameter).
    pub block_hash: Felt,
    pub classes_tree_root: Felt,
    pub contracts_tree_root: Felt,
}

/// Node in the Merkle-Patricia trie.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MerkleNode {
    /// Represents a path to the highest non-zero descendant node.
    Edge {
        /// An integer whose binary representation represents the path from the current node to its
        /// highest non-zero descendant (bounded by 2^251)
        path: Felt,
        /// The length of the path (bounded by 251).
        length: u8,
        /// The hash of the unique non-zero maximal-height descendant node.
        child: Felt,
        /// The hash of this node
        #[serde(skip_serializing_if = "Option::is_none")]
        node_hash: Option<Felt>,
    },

    /// An internal node whose both children are non-zero.
    Binary {
        /// The hash of the left child.
        left: Felt,
        /// The hash of the right child.
        right: Felt,
        /// The hash of this node
        #[serde(skip_serializing_if = "Option::is_none")]
        node_hash: Option<Felt>,
    },
}

/// The response type for `starknet_getStorageProof` method.
///
/// The requested storage proofs. Note that if a requested leaf has the default value, the path to
/// it may end in an edge node whose path is not a prefix of the requested leaf, thus effectively
/// proving non-membership
#[derive(Debug, Serialize, Deserialize)]
pub struct GetStorageProofResponse {
    pub global_roots: GlobalRoots,
    pub classes_proof: ClassesProof,
    pub contracts_proof: ContractsProof,
    pub contracts_storage_proofs: ContractStorageProofs,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClassesProof {
    pub nodes: Nodes,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ContractsProof {
    /// The nodes in the union of the paths from the contracts tree root to the requested leaves.
    pub nodes: Nodes,
    /// The nonce and class hash for each requested contract address, in the order in which they
    /// appear in the request. These values are needed to construct the associated leaf node.
    pub contract_leaves_data: Vec<ContractLeafData>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ContractLeafData {
    // NOTE: This field is not specified in the RPC specs, but the contract storage root is
    // required to compute the contract state hash (ie the value of the contracts trie). We
    // include this in the response for now to ease the conversions over on SNOS side.
    pub storage_root: Felt,
    pub nonce: Felt,
    pub class_hash: Felt,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ContractStorageProofs {
    pub nodes: Vec<Nodes>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeWithHash {
    pub node_hash: Felt,
    pub node: MerkleNode,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Nodes(pub Vec<NodeWithHash>);

impl Deref for Nodes {
    type Target = Vec<NodeWithHash>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Nodes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

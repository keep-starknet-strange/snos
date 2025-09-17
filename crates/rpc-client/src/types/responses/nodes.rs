use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;
use std::ops::{Deref, DerefMut};

/// Node in the Merkle-Patricia trie
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MerkleNode {
    /// An internal node who's both children is non-zero.
    Binary {
        /// The hash of the left child.
        left: Felt,
        /// The hash of the right child.
        right: Felt,
        /// The hash of this node
        #[serde(skip_serializing_if = "Option::is_none")]
        node_hash: Option<Felt>,
    },
    /// Represents a path to the highest non-zero descendant node.
    Edge {
        /// The hash of the unique non-zero maximal-height descendant node.
        child: Felt,
        /// An integer whose binary representation represents the path from the current node to its
        /// highest non-zero descendant (bounded by 2^251)
        path: Felt,
        /// The hash of this node
        #[serde(skip_serializing_if = "Option::is_none")]
        node_hash: Option<Felt>,
        /// The length of the path (bounded by 251).
        length: u8,
    },
}

/// Node in the Merkle-Patricia trie along with its hash
#[derive(Debug, Serialize, Deserialize)]
pub struct MerkleNodeWithHash {
    pub node_hash: Felt,
    pub node: MerkleNode,
}

/// A collection of Merkle-Patricia trie nodes along with their hashes
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MerkleNodes(pub Vec<MerkleNodeWithHash>);

impl Deref for MerkleNodes {
    type Target = Vec<MerkleNodeWithHash>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for MerkleNodes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

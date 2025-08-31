use std::ops::{Deref, DerefMut};

use crate::pathfinder::types::TrieNode;
use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;

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

impl From<MerkleNode> for TrieNode {
    fn from(node: MerkleNode) -> Self {
        match node {
            MerkleNode::Edge { path, length, child, node_hash } => super::proofs::TrieNode::Edge {
                path: super::proofs::EdgePath { value: path, len: length as u64 },
                child,
                node_hash,
            },
            MerkleNode::Binary { left, right, node_hash } => super::proofs::TrieNode::Binary { left, right, node_hash },
        }
    }
}

use crate::pathfinder::types::responses::MerkleNode;
use crate::Hash;
use cairo_vm::Felt252;
use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;

/// A node in the Merkle-Patricia trie
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub enum TrieNode {
    #[serde(rename = "binary")]
    Binary {
        left: Felt,
        right: Felt,
        #[serde(skip_serializing_if = "Option::is_none")]
        node_hash: Option<Felt>,
    },
    #[serde(rename = "edge")]
    Edge {
        child: Felt,
        path: EdgeNodePath,
        #[serde(skip_serializing_if = "Option::is_none")]
        node_hash: Option<Felt>,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct EdgeNodePath {
    pub len: u64,
    pub value: Felt,
}

impl TrieNode {
    pub fn hash<H: Hash>(&self) -> Felt {
        match self {
            TrieNode::Binary { left, right, node_hash: _ } => H::hash(left, right),
            TrieNode::Edge { child, path, node_hash: _ } => {
                // For edge nodes, we hash the child with the path value
                // This is a simplified implementation
                let bottom_path_hash = H::hash(child, &path.value);
                bottom_path_hash + Felt252::from(path.len)
            }
        }
    }

    pub fn node_hash(&self) -> Option<Felt> {
        match self {
            TrieNode::Binary { node_hash, .. } => *node_hash,
            TrieNode::Edge { node_hash, .. } => *node_hash,
        }
    }
}

// Implementing conversion from MerkleNode to TrieNode
impl From<MerkleNode> for TrieNode {
    fn from(node: MerkleNode) -> Self {
        match node {
            MerkleNode::Edge { path, length, child, node_hash } => {
                TrieNode::Edge { path: EdgeNodePath { value: path, len: length as u64 }, child, node_hash }
            }
            MerkleNode::Binary { left, right, node_hash } => TrieNode::Binary { left, right, node_hash },
        }
    }
}

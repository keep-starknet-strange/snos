use crate::pathfinder::constants::DEFAULT_STORAGE_TREE_HEIGHT;
use crate::pathfinder::error::ProofVerificationError;
use crate::pathfinder::types::responses::MerkleNode;
use crate::pathfinder::types::Height;
use crate::Hash;
use anyhow::{anyhow, Result};
use bitvec::order::Msb0;
use bitvec::prelude::BitVec;
use cairo_vm::Felt252;
use num_bigint::BigInt;
use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;
use std::collections::HashMap;

/// A node in the Merkle-Patricia trie
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub enum TrieNode {
    #[serde(rename = "binary")]
    /// Binary nodes always have two children
    Binary {
        left: Felt,
        right: Felt,
        #[serde(skip_serializing_if = "Option::is_none")]
        node_hash: Option<Felt>,
    },
    /// Edge nodes always have one child
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
    pub fn new_binary(left: Felt, right: Felt, node_hash: Option<Felt>) -> Self {
        TrieNode::Binary { left, right, node_hash }
    }

    pub fn new_edge(child: Felt, path_len: u64, path_value: Felt, node_hash: Option<Felt>) -> Self {
        TrieNode::Edge { child, path: EdgeNodePath { len: path_len, value: path_value }, node_hash }
    }

    /// Returns the hash of the node by calculating it using the child hash and path
    pub fn calculate_node_hash<H: Hash>(&self) -> Felt {
        match self {
            TrieNode::Binary { left, right, node_hash: _ } => H::hash(left, right),
            TrieNode::Edge { child, path, node_hash: _ } => {
                // For edge nodes, we hash the child with the path value
                // This is a simplified implementation
                H::hash(child, &path.value) + Felt252::from(path.len)
            }
        }
    }

    /// Returns the node hash if it exists, otherwise returns None
    pub fn get_node_hash(&self) -> Option<Felt> {
        match self {
            TrieNode::Binary { node_hash, .. } => *node_hash,
            TrieNode::Edge { node_hash, .. } => *node_hash,
        }
    }
}

impl EdgeNodePath {
    /// Returns a modified key that follows the specified edge path.
    /// This function is used to work around an issue where the OS fails if it encounters a
    /// writing to 0, and the last node in the storage proof is an edge node of length 1.
    /// In this situation the OS will still look up the node in the preimage and will fail
    /// on an "Edge bottom not found in preimage" error.
    /// To resolve this, we fetch the storage proof for a node that follows this edge
    /// to get the bottom node in the preimage and resolve the issue.
    ///
    /// For example, if following a key 0x00A0 we encounter an edge 0xB0 starting from height 8
    /// to height 4 (i.e., the length of the edge is 4), then the bottom node of the edge will
    /// not be included in the proof as the key does not follow the edge. We need to compute a key
    /// that will follow the edge to get that bottom node. For example, the key 0x00B0 will
    /// follow that edge.
    ///
    /// An important note is that heigh = 0 at the level of leaf nodes (as opposed to the rest of the OS)
    ///
    /// To achieve this, we zero the part of the key at the height of the edge and then replace it
    /// with the path of the edge. This is achieved with bitwise operations. For our example,
    /// this function will compute the new key as `(key & 0xFF0F) | 0x00B0`.
    pub fn get_key_following_edge(&self, key: Felt, height: Height) -> Felt {
        assert!(height.0 < DEFAULT_STORAGE_TREE_HEIGHT);

        let shift = height.0;
        let clear_mask = ((BigInt::from(1) << self.len) - BigInt::from(1)) << shift;
        let mask = self.value.to_bigint() << shift;
        let new_key = (key.to_bigint() & !clear_mask) | mask;

        Felt::from(new_key)
    }
}

pub trait Proof {
    fn to_hashmap(&self) -> Result<HashMap<Felt, TrieNode>>;
    #[allow(clippy::result_large_err)]
    fn verify_proof<H: Hash>(&self, key: Felt, commitment: Felt) -> Result<(), ProofVerificationError>;
}

impl Proof for [TrieNode] {
    fn to_hashmap(&self) -> Result<HashMap<Felt252, TrieNode>> {
        self.iter()
            .map(|node| {
                let hash = node.get_node_hash().ok_or(anyhow!("Failed to get node hash"))?;
                Ok((hash, node.clone()))
            })
            .collect()
    }

    /// This method goes through the tree from top to bottom and verifies that the hash of each node
    /// is equal to the corresponding hash in the parent node
    fn verify_proof<H: Hash>(&self, key: Felt252, commitment: Felt252) -> Result<(), ProofVerificationError> {
        // The tree height is 251, so the first 5 bits are ignored
        let start = 5;
        let mut index = start;

        let bits: BitVec<_, Msb0> = BitVec::from_slice(&key.to_bytes_be());
        let mut next_node_hash = commitment;
        let proof_nodes_map = self.to_hashmap().map_err(|e| ProofVerificationError::ConversionError(e.to_string()))?;
        loop {
            let node = proof_nodes_map.get(&next_node_hash).ok_or_else(|| {
                ProofVerificationError::ProofError(format!(
                    "proof did not contain preimage for node 0x{:x} (index: {})",
                    next_node_hash, index
                ))
            })?;

            match node {
                TrieNode::Binary { left, right, .. } => {
                    let actual_node_hash = node.calculate_node_hash::<H>();
                    if actual_node_hash != next_node_hash {
                        return Err(ProofVerificationError::InvalidChildNodeHash {
                            node_hash: actual_node_hash,
                            parent_hash: next_node_hash,
                        });
                    }
                    next_node_hash = if bits[index] { *right } else { *left };
                    index += 1;
                }

                TrieNode::Edge { child, path, .. } => {
                    let length = path.len as usize;
                    let relevant_path = &bits[index..index + length];

                    let path_bits: BitVec<_, Msb0> = BitVec::from_slice(&path.value.to_bytes_be());
                    let relevant_node_path = &path_bits[256 - length..];

                    let actual_node_hash = node.calculate_node_hash::<H>();
                    if actual_node_hash != next_node_hash {
                        return Err(ProofVerificationError::InvalidChildNodeHash {
                            node_hash: actual_node_hash,
                            parent_hash: next_node_hash,
                        });
                    }
                    next_node_hash = *child;
                    index += length;

                    if relevant_path != relevant_node_path {
                        // If paths don't match, we've found a proof of non-membership because:
                        // 1. We correctly moved towards the target as far as possible, and
                        // 2. Hashing all the nodes along the path results in the root hash, which means
                        // 3. The target definitely does not exist in this tree
                        return Err(ProofVerificationError::NonExistenceProof {
                            key,
                            height: Height(DEFAULT_STORAGE_TREE_HEIGHT - (index - start) as u64),
                            node: node.clone(),
                        });
                    }
                }
            }

            if index > 256 {
                return Err(ProofVerificationError::ProofError(format!(
                    "invalid proof, path too long ({})",
                    index - start
                )));
            }
            if index == 256 {
                break;
            }
        }
        Ok(())
    }
}

// Implementing conversion from MerkleNode to TrieNode
// MerkleNode is returned in the getStorageProof response from the RPC client
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

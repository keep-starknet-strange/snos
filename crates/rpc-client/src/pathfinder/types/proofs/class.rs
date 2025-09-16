use crate::pathfinder::error::ProofVerificationError;
use crate::pathfinder::types::nodes::Proof;
use crate::pathfinder::types::{GetStorageProofResponse, MerkleNodeWithHash, PoseidonHash, TrieNode};
use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;

#[allow(dead_code)]
#[derive(Clone, Deserialize, Serialize)]
pub struct ClassProof {
    pub class_commitment: Felt,
    pub class_proof: Vec<TrieNode>,
}

// Implementations for ClassProof
impl ClassProof {
    #[allow(clippy::result_large_err)]
    pub fn verify(&self, class_hash: Felt) -> Result<(), ProofVerificationError> {
        self.class_proof.verify_proof::<PoseidonHash>(class_hash, self.class_commitment()?)
    }

    /// Gets the "class_commitment" which is aka the root node of the class Merkle tree.
    ///
    /// Proof always starts with the root node, which means all we have to do is hash the
    /// first node in the proof to get the same thing.
    #[allow(clippy::result_large_err)]
    pub fn class_commitment(&self) -> Result<Felt, ProofVerificationError> {
        if !self.class_proof.is_empty() {
            let hash = self.class_proof[0].calculate_node_hash::<PoseidonHash>();
            Ok(hash)
        } else {
            Err(ProofVerificationError::EmptyProof)
        }
    }
}

impl From<GetStorageProofResponse> for ClassProof {
    fn from(proof: GetStorageProofResponse) -> Self {
        let class_proof = proof
            .classes_proof
            .nodes
            .iter()
            .map(|node_with_hash| {
                let MerkleNodeWithHash { node, node_hash } = node_with_hash;
                let mut trie_node: TrieNode = node.clone().into();
                // Set the node_hash from the NodeWithHash
                match &mut trie_node {
                    TrieNode::Binary { node_hash: nh, .. } => *nh = Some(*node_hash),
                    TrieNode::Edge { node_hash: nh, .. } => *nh = Some(*node_hash),
                }
                trie_node
            })
            .collect();
        let class_commitment = proof.global_roots.classes_tree_root;
        ClassProof { class_commitment, class_proof }
    }
}

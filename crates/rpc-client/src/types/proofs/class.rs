use serde::{Deserialize, Serialize};
use starknet_core::types::StorageProof;

use crate::types::TrieNode;

#[derive(Clone, Deserialize, Serialize)]
pub struct ClassProof {
    pub class_proof: Vec<TrieNode>,
}

impl From<StorageProof> for ClassProof {
    fn from(proof: StorageProof) -> Self {
        let class_proof = proof
            .classes_proof
            .iter()
            .map(|(node_hash, node)| {
                let mut trie_node: TrieNode = node.clone().into();
                // Set the node_hash from the NodeWithHash
                trie_node.set_node_hash(*node_hash);
                trie_node
            })
            .collect();
        ClassProof { class_proof }
    }
}

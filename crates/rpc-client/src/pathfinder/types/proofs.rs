use crate::pathfinder::error::ProofVerificationError;
use crate::pathfinder::proofs::verify_proof;
use crate::pathfinder::types::hash::{PedersenHash, PoseidonHash};
use crate::SimpleHashFunction;
use cairo_vm::Felt252;
use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct PathfinderProof {
    pub state_commitment: Option<Felt>,
    pub contract_commitment: Felt,
    pub class_commitment: Option<Felt>,
    pub contract_proof: Vec<TrieNode>,
    pub contract_data: Option<ContractData>,
}

#[allow(dead_code)]
#[derive(Clone, Deserialize, Serialize)]
pub struct PathfinderClassProof {
    pub class_commitment: Felt,
    pub class_proof: Vec<TrieNode>,
}

impl PathfinderClassProof {
    #[allow(clippy::result_large_err)]
    pub fn verify(&self, class_hash: Felt) -> Result<(), ProofVerificationError> {
        verify_proof::<PoseidonHash>(class_hash, self.class_commitment()?, &self.class_proof)
    }

    /// Gets the "class_commitment" which is aka the root node of the class Merkle tree.
    ///
    /// Proof always starts with the root node, which means all we have to do is hash the
    /// first node in the proof to get the same thing.
    #[allow(clippy::result_large_err)]
    pub fn class_commitment(&self) -> Result<Felt, ProofVerificationError> {
        if !self.class_proof.is_empty() {
            let hash = self.class_proof[0].hash::<PoseidonHash>();
            Ok(hash)
        } else {
            Err(ProofVerificationError::EmptyProof) // TODO: give an error type or change fn return type
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ContractData {
    /// Root of the Contract state tree
    pub root: Felt,
    /// The proofs associated with the queried storage values
    pub storage_proofs: Vec<Vec<TrieNode>>,
}

impl ContractData {
    /// Verifies that each contract state proof is valid.
    pub fn verify(&self, storage_keys: &[Felt]) -> Result<(), Vec<ProofVerificationError>> {
        let mut errors = vec![];

        for (index, storage_key) in storage_keys.iter().enumerate() {
            if let Err(e) = verify_proof::<PedersenHash>(*storage_key, self.root, &self.storage_proofs[index]) {
                errors.push(e);
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct EdgePath {
    pub len: u64,
    pub value: Felt,
}

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
        path: EdgePath,
        #[serde(skip_serializing_if = "Option::is_none")]
        node_hash: Option<Felt>,
    },
}

// TODO: the hashing is not right here, solve this before proceeding
impl TrieNode {
    pub fn hash<H: SimpleHashFunction>(&self) -> Felt {
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

#[derive(Debug, Copy, Clone, PartialEq, Default, Eq, Hash, Serialize, Deserialize)]
pub struct Height(pub u64);

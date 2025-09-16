use crate::pathfinder::error::{ClientError, ProofVerificationError};
use crate::pathfinder::proofs::verify_proof;
use crate::pathfinder::types::{GetStorageProofResponse, MerkleNodeWithHash, PedersenHash, PoseidonHash, TrieNode};
use serde::{Deserialize, Serialize};
use starknet::macros::short_string;
use starknet_types_core::felt::Felt;

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct ContractProof {
    pub state_commitment: Option<Felt>,
    pub contract_commitment: Felt,
    pub class_commitment: Option<Felt>,
    pub contract_proof: Vec<TrieNode>,
    pub contract_data: Option<ContractData>,
}

#[allow(dead_code)]
#[derive(Clone, Deserialize, Serialize)]
pub struct ClassProof {
    pub class_commitment: Felt,
    pub class_proof: Vec<TrieNode>,
}

#[derive(Debug, Copy, Clone, PartialEq, Default, Eq, Hash, Serialize, Deserialize)]
pub struct Height(pub u64);

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ContractData {
    /// Root of the Contract state tree
    pub root: Felt,
    /// The proofs associated with the queried storage values
    pub storage_proofs: Vec<Vec<TrieNode>>,
}

// Implementations for ClassProof
impl ClassProof {
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
            Err(ProofVerificationError::EmptyProof)
        }
    }
}

// Implementations for ContractData
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

impl TryFrom<GetStorageProofResponse> for ContractProof {
    type Error = ClientError;

    fn try_from(proof: GetStorageProofResponse) -> Result<Self, Self::Error> {
        let contract_proof = proof.contracts_proof;
        let contract_leaf = contract_proof
            .contract_leaves_data
            .first()
            .ok_or(ClientError::ProofConversionError(String::from("Must have exactly one contract leaf")))?;
        let storage_proofs = proof
            .contracts_storage_proofs
            .nodes
            .first()
            .ok_or(ClientError::ProofConversionError(String::from("Must have exactly one storage proof")))?;

        let state_commitment = starknet_crypto::poseidon_hash_many(&[
            short_string!("STARKNET_STATE_V0"),
            proof.global_roots.contracts_tree_root,
            proof.global_roots.classes_tree_root,
        ]);

        // convert storage proofs from response to SNOS types
        let mut pf_storage_proofs = Vec::with_capacity(1);
        let mut pf_storage_proof: Vec<TrieNode> = Vec::with_capacity(pf_storage_proofs.len());

        for n in &storage_proofs.0 {
            let MerkleNodeWithHash { node, node_hash } = n;
            let mut trie_node: TrieNode = node.clone().into();
            // Set the node_hash from the NodeWithHash
            match &mut trie_node {
                TrieNode::Binary { node_hash: nh, .. } => *nh = Some(*node_hash),
                TrieNode::Edge { node_hash: nh, .. } => *nh = Some(*node_hash),
            }
            pf_storage_proof.push(trie_node);
        }

        pf_storage_proofs.push(pf_storage_proof);

        // convert contract proofs from response to SNOS types
        let mut pf_contract_proof: Vec<TrieNode> = Vec::with_capacity(contract_proof.nodes.len());
        for n in &contract_proof.nodes.0 {
            let MerkleNodeWithHash { node, node_hash } = n;
            let mut trie_node: TrieNode = node.clone().into();
            // Set the node_hash from the NodeWithHash
            match &mut trie_node {
                TrieNode::Binary { node_hash: nh, .. } => *nh = Some(*node_hash),
                TrieNode::Edge { node_hash: nh, .. } => *nh = Some(*node_hash),
            }
            pf_contract_proof.push(trie_node);
        }

        Ok(ContractProof {
            state_commitment: Some(state_commitment),
            contract_commitment: proof.global_roots.contracts_tree_root,
            class_commitment: Some(proof.global_roots.classes_tree_root),
            contract_proof: pf_contract_proof,
            contract_data: Some(ContractData { root: contract_leaf.storage_root, storage_proofs: pf_storage_proofs }),
        })
    }
}

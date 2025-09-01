use crate::pathfinder::error::ClientError;
use crate::pathfinder::types::{ContractData, PathfinderClassProof, PathfinderProof, TrieNode};
use crate::pathfinder::types::{NodeWithHash, Nodes};
use serde::{Deserialize, Serialize};
use starknet::macros::short_string;
use starknet_types_core::felt::Felt;

/// The response type for the `starknet_getStorageProof` method.
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

#[derive(Debug, Serialize, Deserialize)]
pub struct GlobalRoots {
    /// The associated block hash (needed in case the caller used a block tag for the block_id
    /// parameter).
    pub block_hash: Felt,
    pub classes_tree_root: Felt,
    pub contracts_tree_root: Felt,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClassesProof {
    pub nodes: Nodes,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ContractsProof {
    /// The nodes in the union of the paths from the contract tree root to the requested leaves.
    pub nodes: Nodes,
    /// The nonce and class hash for each requested contract address, in the order in which they
    /// appear in the request. These values are needed to construct the associated leaf node.
    pub contract_leaves_data: Vec<ContractLeafData>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ContractStorageProofs {
    pub nodes: Vec<Nodes>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ContractLeafData {
    // NOTE: This field is not specified in the RPC specs, but the contract storage root is
    // required to compute the contract state hash (i.e., the value of the contracts trie). We
    // include this in the response for now to ease the conversions over on the SNOS side.
    pub storage_root: Felt,
    pub nonce: Felt,
    pub class_hash: Felt,
}

impl From<GetStorageProofResponse> for PathfinderClassProof {
    fn from(proof: GetStorageProofResponse) -> Self {
        let class_proof = proof
            .classes_proof
            .nodes
            .iter()
            .map(|node_with_hash| {
                let NodeWithHash { node, node_hash } = node_with_hash;
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
        PathfinderClassProof { class_commitment, class_proof }
    }
}

impl TryFrom<GetStorageProofResponse> for PathfinderProof {
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

        // convert storage proofs to pathfinder types
        let mut pf_storage_proofs = Vec::with_capacity(1);
        let mut pf_storage_proof: Vec<TrieNode> = Vec::with_capacity(pf_storage_proofs.len());

        for n in &storage_proofs.0 {
            let NodeWithHash { node, node_hash } = n;
            let mut trie_node: TrieNode = node.clone().into();
            // Set the node_hash from the NodeWithHash
            match &mut trie_node {
                TrieNode::Binary { node_hash: nh, .. } => *nh = Some(*node_hash),
                TrieNode::Edge { node_hash: nh, .. } => *nh = Some(*node_hash),
            }
            pf_storage_proof.push(trie_node);
        }

        pf_storage_proofs.push(pf_storage_proof);

        // convert contract proofs to pathfinder types
        let mut pf_contract_proof: Vec<TrieNode> = Vec::with_capacity(contract_proof.nodes.len());
        for n in &contract_proof.nodes.0 {
            let NodeWithHash { node, node_hash } = n;
            let mut trie_node: TrieNode = node.clone().into();
            // Set the node_hash from the NodeWithHash
            match &mut trie_node {
                TrieNode::Binary { node_hash: nh, .. } => *nh = Some(*node_hash),
                TrieNode::Edge { node_hash: nh, .. } => *nh = Some(*node_hash),
            }
            pf_contract_proof.push(trie_node);
        }

        Ok(PathfinderProof {
            state_commitment: Some(state_commitment),
            contract_commitment: proof.global_roots.contracts_tree_root,
            class_commitment: Some(proof.global_roots.classes_tree_root),
            contract_proof: pf_contract_proof,
            contract_data: Some(ContractData { root: contract_leaf.storage_root, storage_proofs: pf_storage_proofs }),
        })
    }
}

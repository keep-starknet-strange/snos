use serde::{Deserialize, Serialize};
use starknet_os::config::DEFAULT_STORAGE_TREE_HEIGHT;
use starknet_os::crypto::pedersen::PedersenHash;
use starknet_os::crypto::poseidon::PoseidonHash;
use starknet_os::starkware_utils::commitment_tree::base_types::{Height, Length, NodePath};
use starknet_os::starkware_utils::commitment_tree::patricia_tree::nodes::{BinaryNodeFact, EdgeNodeFact};
use starknet_os::storage::dict_storage::DictStorage;
use starknet_os::storage::storage::{Fact, HashFunctionType};
use starknet_types_core::felt::Felt;

#[derive(thiserror::Error, Debug)]
pub enum ProofVerificationError<'a> {
    #[error("Non-inclusion proof for key {}. Height {}.", key.to_hex_string(), height.0)]
    NonExistenceProof { key: Felt, height: Height, proof: &'a [TrieNode] },

    #[error("Proof verification failed, node_hash {node_hash:x} != parent_hash {parent_hash:x}")]
    InvalidChildNodeHash { node_hash: Felt, parent_hash: Felt },

    #[error("Conversion error")]
    ConversionError,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub enum TrieNode {
    #[serde(rename = "binary")]
    Binary { left: Felt, right: Felt },
    #[serde(rename = "edge")]
    Edge { child: Felt, path: EdgePath },
}

impl TrieNode {
    pub fn hash<H: HashFunctionType>(&self) -> Felt {
        match self {
            TrieNode::Binary { left, right } => {
                let fact = BinaryNodeFact::new((*left).into(), (*right).into())
                    .expect("storage proof endpoint gave us an invalid binary node");

                // TODO: the hash function should probably be split from the Fact trait.
                //       we use a placeholder for the Storage trait in the meantime.
                Felt::from(<BinaryNodeFact as Fact<DictStorage, H>>::hash(&fact))
            }
            TrieNode::Edge { child, path } => {
                let fact = EdgeNodeFact::new((*child).into(), NodePath(path.value.to_biguint()), Length(path.len))
                    .expect("storage proof endpoint gave us an invalid edge node");
                // TODO: the hash function should probably be split from the Fact trait.
                //       we use a placeholder for the Storage trait in the meantime.
                Felt::from(<EdgeNodeFact as Fact<DictStorage, H>>::hash(&fact))
            }
        }
    }
}

// Types defined for Deserialize functionality
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct EdgePath {
    pub len: u64,
    pub value: Felt,
}

#[derive(Debug, Clone, Deserialize, Default)]
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

        if errors.is_empty() { Ok(()) } else { Err(errors) }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PathfinderProof {
    pub state_commitment: Option<Felt>,
    pub class_commitment: Option<Felt>,
    pub contract_proof: Vec<TrieNode>,
    pub contract_data: Option<ContractData>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct PathfinderClassProof {
    pub class_commitment: Felt,
    pub class_proof: Vec<TrieNode>,
}

impl PathfinderClassProof {
    /// Verifies that the class proof is valid.
    pub fn verify(&self, class_hash: Felt) -> Result<(), ProofVerificationError> {
        verify_proof::<PoseidonHash>(class_hash, self.class_commitment, &self.class_proof)
    }
}

/// This function goes through the tree from top to bottom and verifies that
/// the hash of each node is equal to the corresponding hash in the parent node.
pub fn verify_proof<H: HashFunctionType>(
    key: Felt,
    commitment: Felt,
    proof: &[TrieNode],
) -> Result<(), ProofVerificationError> {
    let bits = key.to_bits_be();

    let mut parent_hash = commitment;

    // The tree height is 251, so the first 5 bits are ignored.
    let start = 5;
    let mut index = start;

    for node in proof.iter() {
        let node_hash = node.hash::<H>();
        if node_hash != parent_hash {
            return Err(ProofVerificationError::InvalidChildNodeHash { node_hash, parent_hash });
        }

        match node {
            TrieNode::Binary { left, right } => {
                parent_hash = if bits[index as usize] { *right } else { *left };
                index += 1;
            }
            TrieNode::Edge { child, path } => {
                let path_len_usize: usize = path.len.try_into().map_err(|_| ProofVerificationError::ConversionError)?;
                let index_usize: usize = index.try_into().map_err(|_| ProofVerificationError::ConversionError)?;

                let path_bits = path.value.to_bits_be();
                let relevant_path_bits = &path_bits[path_bits.len() - path_len_usize..];
                let key_bits_slice = &bits[index_usize..(index_usize + path_len_usize)];

                parent_hash = *child;
                index += path.len;

                if relevant_path_bits != key_bits_slice {
                    // If paths don't match, we've found a proof of non-membership because:
                    // 1. We correctly moved towards the target as far as possible, and
                    // 2. Hashing all the nodes along the path results in the root hash, which means
                    // 3. The target definitely does not exist in this tree
                    return Err(ProofVerificationError::NonExistenceProof {
                        key,
                        height: Height(DEFAULT_STORAGE_TREE_HEIGHT - (index - start)),
                        proof,
                    });
                }
            }
        }
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ContractStorageKeysItem {
    pub contract_address: Felt,
    pub storage_keys: Vec<Felt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum MerkleNode {
    Binary { left: Felt, right: Felt },
    Edge { child: Felt, path: Felt, length: usize },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct NodeHashToNodeMappingItem {
    pub node_hash: Felt,
    pub node: MerkleNode,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ContractLeavesDataItem {
    pub nonce: Felt,
    pub class_hash: Felt,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ContractsProof {
    pub nodes: Vec<NodeHashToNodeMappingItem>,
    pub contract_leaves_data: Vec<ContractLeavesDataItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct GlobalRoots {
    pub contracts_tree_root: Felt,
    pub classes_tree_root: Felt,
    pub block_hash: Felt,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct StorageProof {
    pub classes_proof: Vec<NodeHashToNodeMappingItem>,
    pub contracts_proof: ContractsProof,
    pub contracts_storage_proofs: Vec<Vec<NodeHashToNodeMappingItem>>,
    pub global_roots: GlobalRoots,
}

pub fn convert_storage_to_pathfinder_proof(storage_proof: StorageProof) -> PathfinderProof {
    let contract_proof: Vec<TrieNode> = storage_proof.contracts_proof.nodes.iter().map(convert_to_trie_node).collect();

    let storage_proofs: Vec<Vec<TrieNode>> = storage_proof
        .contracts_storage_proofs
        .iter()
        .map(|nodes| nodes.iter().map(convert_to_trie_node).collect())
        .collect();

    // This is a temporary solution due to the root not being explicitely returned
    let contract_data = storage_proof
        .contracts_storage_proofs
        // Get the first "proof" only if it exists
        .first()
        // Filter out if the first proof is empty
        .filter(|proof_nodes| !proof_nodes.is_empty())
        .map(|proof_nodes| {
            let first_node = &proof_nodes[0];
            let root = first_node.node_hash;

            match &first_node.node {
                MerkleNode::Binary { left, .. } if left.to_hex_string() == "0x0" => {
                    // If left is "0x0", then there is a root but storage_proofs is empty
                    ContractData {
                        root,
                        storage_proofs: vec![],
                    }
                }
                // For all other cases (including `MerkleNode::Edge`),
                // store the computed `storage_proofs`.
                _ => ContractData { root, storage_proofs },
            }
        });

    PathfinderProof {
        state_commitment: None,
        class_commitment: Some(storage_proof.global_roots.classes_tree_root),
        contract_proof,
        contract_data,
    }
}

pub fn convert_storage_to_pathfinder_class_proof(storage_proof: StorageProof) -> PathfinderClassProof {
    let class_proof: Vec<TrieNode> = storage_proof.classes_proof.iter().map(convert_to_trie_node).collect();
    PathfinderClassProof { class_commitment: storage_proof.classes_proof[0].node_hash, class_proof }
}

pub fn convert_to_trie_node(node: &NodeHashToNodeMappingItem) -> TrieNode {
    match node.node {
        MerkleNode::Binary { left, right } => TrieNode::Binary { left, right },
        MerkleNode::Edge { child, path, length } => TrieNode::Edge {
            child,
            path: EdgePath { len: length.try_into().expect("length must be a valid integer"), value: path },
        },
    }
}

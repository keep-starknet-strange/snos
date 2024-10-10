use serde::Deserialize;
use starknet_os::config::DEFAULT_STORAGE_TREE_HEIGHT;
use starknet_os::crypto::pedersen::PedersenHash;
use starknet_os::crypto::poseidon::PoseidonHash;
use starknet_os::starkware_utils::commitment_tree::base_types::{Height, Length, NodePath};
use starknet_os::starkware_utils::commitment_tree::patricia_tree::nodes::{BinaryNodeFact, EdgeNodeFact};
use starknet_os::storage::dict_storage::DictStorage;
use starknet_os::storage::storage::{Fact, HashFunctionType};
use starknet_types_core::felt::Felt;

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
pub struct ContractData {
    /// Root of the Contract state tree
    pub root: Felt,
    /// The proofs associated with the queried storage values
    pub storage_proofs: Vec<Vec<TrieNode>>,
}

#[derive(thiserror::Error, Debug)]
pub enum ProofVerificationError<'a> {
    #[error("Non-inclusion proof for key {}. Height {}.", key.to_hex_string(), height.0)]
    NonExistenceProof { key: Felt, height: Height, proof: &'a [TrieNode] },

    #[error("Proof verification failed, node_hash {node_hash:x} != parent_hash {parent_hash:x}")]
    InvalidChildNodeHash { node_hash: Felt, parent_hash: Felt },

    #[error("Proof verification failed for key {:#x}.", key)]
    KeyNotInProof { key: Felt },
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
    pub state_commitment: Felt,
    pub class_commitment: Felt,
    pub contract_proof: Vec<TrieNode>,
    pub contract_data: Option<ContractData>,
}

#[allow(dead_code)]
#[derive(Clone, Deserialize)]
pub struct PathfinderClassProof {
    pub class_commitment: Felt,
    pub class_proof: Vec<TrieNode>,
}

impl PathfinderClassProof {
    /// Verifies that the class proof is valid.
    pub fn verify(&self, class_hash: Felt) -> Result<(), ProofVerificationError> {
        if let Err(e) = verify_proof::<PoseidonHash>(class_hash, self.class_commitment, &self.class_proof) {
            match e {
                ProofVerificationError::NonExistenceProof { .. } => {}
                _ => return Err(e),
            }
        }
        Ok(())
    }
}

// Types defined for Deserialize functionality
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct EdgePath {
    pub len: u64,
    pub value: Felt,
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
    let mut trie_node_iter = proof.iter();

    // The tree height is 251, so the first 5 bits are ignored.
    let start = 5;
    let mut index = start;
    let mut non_existence_proof = false;

    loop {
        match trie_node_iter.next() {
            None => {
                if non_existence_proof {
                    return Err(ProofVerificationError::NonExistenceProof {
                        key,
                        height: Height(DEFAULT_STORAGE_TREE_HEIGHT - (index - start)),
                        proof,
                    });
                } else if index - start != DEFAULT_STORAGE_TREE_HEIGHT {
                    return Err(ProofVerificationError::KeyNotInProof { key });
                }
                break;
            }
            Some(node) => {
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
                        let path_bits = path.value.to_bits_be();
                        let relevant_path_bits = &path_bits[path_bits.len() - path.len as usize..];
                        let key_bits_slice = &bits[index as usize..(index + path.len) as usize];
                        if relevant_path_bits != key_bits_slice {
                            // If paths don't match, we've found a proof of non-membership because:
                            // 1. We correctly moved towards the target as far as possible, and
                            // 2. Hashing all the nodes along the path results in the root hash, which means
                            // 3. The target definitely does not exist in this tree
                            non_existence_proof = true;
                        }
                        parent_hash = *child;
                        index += path.len;
                    }
                }
            }
        }
    }

    Ok(())
}

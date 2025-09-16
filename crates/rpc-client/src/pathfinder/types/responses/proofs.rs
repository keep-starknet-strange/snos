use crate::pathfinder::types::MerkleNodes;
use serde::{Deserialize, Serialize};
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
    pub nodes: MerkleNodes,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ContractsProof {
    /// The nodes in the union of the paths from the contract tree root to the requested leaves.
    pub nodes: MerkleNodes,
    /// The nonce and class hash for each requested contract address, in the order in which they
    /// appear in the request. These values are needed to construct the associated leaf node.
    pub contract_leaves_data: Vec<ContractLeafData>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ContractStorageProofs {
    pub nodes: Vec<MerkleNodes>,
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

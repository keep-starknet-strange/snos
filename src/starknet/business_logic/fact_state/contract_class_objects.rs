use cairo_vm::Felt252;
use serde::{Deserialize, Serialize};

use crate::config::CONTRACT_CLASS_LEAF_VERSION;
use crate::starkware_utils::commitment_tree::leaf_fact::LeafFact;
use crate::starkware_utils::commitment_tree::patricia_tree::patricia_tree::EMPTY_NODE_HASH;
use crate::storage::storage::{DbObject, Fact, HashFunctionType, Storage};

/// Represents a leaf in the Starknet contract class tree.
#[derive(Deserialize, Clone, Debug, Serialize, PartialEq)]
pub struct ContractClassLeaf {
    compiled_class_hash: Felt252,
}

impl ContractClassLeaf {
    pub fn create(compiled_class_hash: Felt252) -> Self {
        Self { compiled_class_hash }
    }

    pub fn empty() -> Self {
        Self { compiled_class_hash: Felt252::ZERO }
    }
}

impl<S, H> Fact<S, H> for ContractClassLeaf
where
    H: HashFunctionType,
    S: Storage,
{
    /// Computes the hash of the contract class leaf.
    fn hash(&self) -> Vec<u8> {
        if <ContractClassLeaf as LeafFact<S, H>>::is_empty(self) {
            return EMPTY_NODE_HASH.to_vec();
        }

        // Return H(CONTRACT_CLASS_LEAF_VERSION, compiled_class_hash).
        H::hash(CONTRACT_CLASS_LEAF_VERSION, &self.compiled_class_hash.to_bytes_be())
    }
}

impl DbObject for ContractClassLeaf {}

impl<S, H> LeafFact<S, H> for ContractClassLeaf
where
    H: HashFunctionType,
    S: Storage,
{
    fn is_empty(&self) -> bool {
        self.compiled_class_hash == Felt252::ZERO
    }
}

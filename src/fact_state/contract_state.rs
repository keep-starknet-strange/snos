use cairo_felt::Felt252;

use crate::{
    storage::{DBObject, Fact},
    utils::{
        commitment_tree::{
            leaf_fact::LeafFact, nodes::EMPTY_NODE_HASH, patricia_tree::PatriciaTree,
        },
        definitions::constants::UNINITIALIZED_CLASS_HASH,
        hasher::HasherT,
    },
};

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ContractState {
    contract_hash: Felt252,
    storage_commitment_tree: PatriciaTree,
    nonce: Felt252,
}

impl LeafFact for ContractState {
    fn is_empty(&self) -> bool {
        self.storage_commitment_tree.root == Felt252::from_bytes_be(EMPTY_NODE_HASH.as_slice())
            && self.contract_hash == Felt252::from_bytes_be(UNINITIALIZED_CLASS_HASH.as_slice())
            && self.nonce == Felt252::new(0)
    }
}

impl Fact for ContractState {
    /// Computes the hash of the node containing the contract's information, including the contract
    /// definition and storage.
    fn _hash<H: HasherT>(&self) -> Vec<u8> {
        if self.is_empty() {
            return EMPTY_NODE_HASH.to_vec();
        }

        let contract_state_hash_version = Felt252::new(0);

        // Set hash_value = H(H(contract_hash, storage_root), RESERVED)
        let hash_value = H::hash_elements(
            self.contract_hash.clone(),
            self.storage_commitment_tree.root.clone(),
        );
        let hash_value = H::hash_elements(hash_value, self.nonce.clone());

        // Return H(hash_value, CONTRACT_STATE_HASH_VERSION). CONTRACT_STATE_HASH_VERSION must be in
        // the outermost hash to guarantee unique "decoding".
        H::hash_elements(hash_value, contract_state_hash_version)
            .to_bytes_be()
            .to_vec()
    }
}

impl DBObject for ContractState {
    fn db_key(suffix: Vec<u8>) -> Vec<u8> {
        let prefix: &[u8] = "contract_state".as_bytes();
        let sep: &[u8] = ":".as_bytes();

        [prefix, sep, suffix.as_slice()].concat()
    }
}

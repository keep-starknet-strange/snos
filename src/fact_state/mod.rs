use cairo_felt::Felt252;

use crate::utils::sn_to_path_address;

use blockifier::state::cached_state::CommitmentStateDiff;

use pathfinder_common::{
    class_hash_bytes, contract_address_bytes, felt_bytes, storage_address_bytes,
    storage_value_bytes, ClassCommitment, ContractNonce, ContractRoot, StorageAddress,
    StorageCommitment, StorageValue,
};
use pathfinder_merkle_tree::{
    contract_state::update_contract_state, ClassCommitmentTree, ContractsStorageTree,
    StorageCommitmentTree,
};
use pathfinder_storage::Transaction;

use std::collections::HashMap;

// TODO: parse from cairo-lang
const STARKNET_VERSION: &str = "0.12.2";

pub struct ContractState<'tx> {
    contract_hash: Felt252,
    storage_commitment_tree: StorageCommitmentTree<'tx>,
    nonce: Felt252,
}

pub struct SharedState<'tx> {
    contract_states: ContractsStorageTree<'tx>,
    storage_commitment_tree: StorageCommitmentTree<'tx>,
    contract_classes: ClassCommitmentTree<'tx>,
}

impl<'tx> SharedState<'tx> {
    pub fn apply_diff(tx: &'tx Transaction<'tx>, diff: CommitmentStateDiff) -> StorageCommitment {
        let mut commitment = StorageCommitment::ZERO;
        for addr in diff.address_to_class_hash.keys().into_iter() {
            let mut updates: HashMap<StorageAddress, StorageValue> = HashMap::new();
            if let Some(storage_updates) = diff.storage_updates.get(addr) {
                for update in storage_updates.into_iter() {
                    updates.insert(
                        storage_address_bytes!(update.0 .0.key().bytes()),
                        storage_value_bytes!(update.1.bytes()),
                    );
                }
            }

            let mut sct = StorageCommitmentTree::load(tx, commitment);
            let nonce = ContractNonce(felt_bytes!(diff
                .address_to_nonce
                .get(addr)
                .unwrap()
                .0
                .bytes()));
            let class_hash = diff.address_to_class_hash.get(addr).unwrap();

            let contract_state_hash = update_contract_state(
                sn_to_path_address(*addr),
                &updates,
                Some(nonce),
                Some(class_hash_bytes!(class_hash.0.bytes())),
                &sct,
                tx,
                false,
            )
            .unwrap();

            sct.set(sn_to_path_address(*addr), contract_state_hash)
                .unwrap();
            let (storage_commitment, nodes) = sct.commit().unwrap();
            tx.insert_storage_trie(storage_commitment, &nodes).unwrap();
            commitment = storage_commitment;
        }
        commitment
    }
}

use cairo_felt::Felt252;

use blockifier::state::cached_state::CommitmentStateDiff;

use pathfinder_common::{
    class_hash_bytes, contract_address_bytes, felt_bytes, storage_address_bytes,
    storage_value_bytes, BlockNumber, ContractAddress, ContractNonce, ContractRoot, StorageAddress,
    StorageCommitment, StorageValue,
};
use pathfinder_merkle_tree::{
    contract_state::update_contract_state, ClassCommitmentTree, ContractsStorageTree,
    StorageCommitmentTree,
};
use pathfinder_storage::{Storage, Transaction};
use starknet_api::core::ContractAddress as SnContractAddress;
use std::collections::HashMap;

// TODO: parse from cairo-lang
const STARKNET_VERSION: &str = "0.12.2";

pub struct ContractState {
    contract_hash: Felt252,
    storage_commitment_tree: Storage,
    nonce: Felt252,
}

pub struct SharedState {
    storage: Storage,
}

impl SharedState {
    pub fn new() -> Self {
        Self {
            storage: Storage::in_memory().unwrap(),
        }
    }

    pub fn apply_diff(&self, diff: CommitmentStateDiff) -> StorageCommitment {
        let mut connection = self.storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let mut sct = StorageCommitmentTree::load(&tx, BlockNumber::GENESIS).unwrap();
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
                &tx,
                false,
                BlockNumber::GENESIS,
            )
            .unwrap();

            println!(
                "PATH SET: {:?} {:?}",
                sn_to_path_address(*addr),
                contract_state_hash
            );
            sct.set(sn_to_path_address(*addr), contract_state_hash)
                .unwrap();
        }
        let (storage_commitment, nodes) = sct.commit().unwrap();
        let root_idx = tx.insert_storage_trie(storage_commitment, &nodes).unwrap();
        // println!("ROOT COMM: {storage_commitment}");
        // println!("ROOT NODES: {nodes:?}");
        storage_commitment
    }
}

fn sn_to_path_address(sn_addr: SnContractAddress) -> ContractAddress {
    contract_address_bytes!(sn_addr.0.key().bytes())
}

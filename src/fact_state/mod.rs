use anyhow::Context;

use cairo_felt::Felt252;

use blockifier::block_context::BlockContext;
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

// { address_to_class_hash: {ContractAddress(PatriciaKey(StarkFelt("0x05ca2b81086d3fbb4f4af2f1deba4b7fd35e8f4b2caee4e056005c51c05c3dd0"))): ClassHash(StarkFelt("0x016dc3038da22dde8ad61a786ab9930699cc496c8bccb90d77cc8abee89803f7")), ContractAddress(PatriciaKey(StarkFelt("0x03400a86fdc294a70fac1cf84f81a2127419359096b846be9814786d4fc056b8"))): ClassHash(StarkFelt("0x07cea4d7710723fa9e33472b6ceb71587a0ce4997ef486638dd0156bdb6c2daa"))},
//  address_to_nonce: {ContractAddress(PatriciaKey(StarkFelt("0x05ca2b81086d3fbb4f4af2f1deba4b7fd35e8f4b2caee4e056005c51c05c3dd0"))): Nonce(StarkFelt("0x0000000000000000000000000000000000000000000000000000000000000001")), ContractAddress(PatriciaKey(StarkFelt("0x03400a86fdc294a70fac1cf84f81a2127419359096b846be9814786d4fc056b8"))): Nonce(StarkFelt("0x0000000000000000000000000000000000000000000000000000000000000002"))},
// storage_updates: {ContractAddress(PatriciaKey(StarkFelt("0x0000000000000000000000000000000000000000000000000000000000000001"))): {StorageKey(PatriciaKey(StarkFelt("0x0000000000000000000000000000000000000000000000000000000000000000"))): StarkFelt("0x0000000000000000000000000000000000000000000000000000000000000014")}}, class_hash_to_compiled_class_hash: {} }

impl<'tx> SharedState<'tx> {
    pub fn load_new(tx: &'tx Transaction<'tx>) -> Self {
        Self {
            contract_states: ContractsStorageTree::load(tx, ContractRoot::ZERO),
            storage_commitment_tree: StorageCommitmentTree::load(tx, StorageCommitment::ZERO),
            contract_classes: ClassCommitmentTree::load(tx, ClassCommitment::ZERO),
        }
    }

    pub fn apply_diff(&mut self, tx: &'tx Transaction<'tx>, diff: CommitmentStateDiff) {
        let accessed = diff.address_to_class_hash.keys();
        for addr in accessed.into_iter() {
            let mut updates: HashMap<StorageAddress, StorageValue> = HashMap::new();
            if let Some(storage_updates) = diff.storage_updates.get(addr) {
                for update in storage_updates.into_iter() {
                    updates.insert(
                        storage_address_bytes!(update.0 .0.key().bytes()),
                        storage_value_bytes!(update.1.bytes()),
                    );
                }
            }

            println!("ADDR: {:?}", addr);
            println!("UPDATES: {:?}", diff.storage_updates);
            println!("FOR ADDR: {:?}", diff.storage_updates.get(addr));
            let mut sct = StorageCommitmentTree::load(tx, StorageCommitment::ZERO);
            let nonce = ContractNonce(felt_bytes!(diff
                .address_to_nonce
                .get(addr)
                .unwrap()
                .0
                .bytes()));
            let class_hash = diff.address_to_class_hash.get(addr).unwrap();

            let contract_state_hash = update_contract_state(
                contract_address_bytes!(addr.0.key().bytes()),
                &updates,
                Some(nonce),
                Some(class_hash_bytes!(class_hash.0.bytes())),
                &sct,
                tx,
                false,
            )
            .unwrap();
            sct.set(
                contract_address_bytes!(addr.0.key().bytes()),
                contract_state_hash,
            )
            .unwrap();
            let (commitment, nodes) = sct.commit().unwrap();
            println!("COMMITMENT: {commitment:?}");
            println!("NODE: {nodes:?}");
        }
        // println!("KEYS: {:?}", storage_accessed);
    }
}

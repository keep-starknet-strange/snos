pub mod node;
pub mod trie;

use blockifier::state::state_api::State;
use cairo_felt::Felt252;
use indexmap::IndexMap;

use papyrus_storage::state::{StateStorageReader, StateStorageWriter};
use papyrus_storage::{db::DbConfig, open_storage, StorageConfig, StorageScope};

use starknet_api::block::BlockNumber;
use starknet_api::core::{ChainId, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::patricia_key;
use starknet_api::state::{StateDiff, StateNumber};
use tempfile::{tempdir, TempDir};

use crate::config::DEFAULT_STORAGE_TREE_HEIGHT;
use crate::storage::DefaultStorage;
use crate::utils::{bits_from_felt, calculate_contract_state_hash};
use trie::{MerkleTrie, PedersenHash};

pub struct ContractState {
    _contract_hash: Felt252,
    _storage_commitment_tree: Felt252,
    _nonce: Felt252,
}

pub struct SharedState {
    db_conf: StorageConfig,
    cache: Box<dyn State>,
    _tmp: TempDir,
}

impl SharedState {
    pub fn new(chain_id: ChainId, cache: Box<dyn State>) -> Self {
        let _tmp = tempdir().unwrap();
        let db_conf = StorageConfig {
            db_config: DbConfig {
                chain_id,
                path_prefix: _tmp.path().to_path_buf(),
                ..DbConfig::default()
            },
            scope: StorageScope::default(),
        };
        open_storage(db_conf.clone()).unwrap();
        Self {
            db_conf,
            cache,
            _tmp,
        }
    }

    pub fn apply_diff(&mut self, block_number: BlockNumber) -> StarkFelt {
        let diff = self.cache.to_state_diff();

        let state_diff = StateDiff {
            deployed_contracts: diff.address_to_class_hash.clone(),
            storage_diffs: diff.storage_updates.clone(),
            nonces: diff.address_to_nonce.clone(),
            ..StateDiff::default()
        };
        // if let Some(dep_classes) = deprecated_class_mapping {
        //     state_diff.deprecated_declared_classes = dep_classes;
        // }

        let (_, mut writer) = open_storage(self.db_conf.clone()).unwrap();

        let txn = writer.begin_rw_txn().unwrap();

        txn.append_state_diff(block_number, state_diff, IndexMap::new())
            .unwrap();

        let txn = writer.begin_rw_txn().unwrap();

        let mut contract_commitments: Vec<StarkHash> = Vec::new();
        // TODO: use config const and reconcile usize -> u64
        let mut tree: MerkleTrie<PedersenHash, 251> = MerkleTrie::empty();
        let storage = DefaultStorage::default();
        let statetxn = txn.get_state_reader().unwrap();
        for (addr, nonce) in diff.address_to_nonce {
            let class_hash = statetxn
                .get_class_hash_at(StateNumber::right_after_block(BlockNumber(0)), &addr)
                .unwrap()
                .unwrap();

            // TODO: dynamically get new root
            let contract_commitment =
                calculate_contract_state_hash(class_hash, patricia_key!("0x0"), nonce);

            tree.set(&storage, bits_from_felt(*addr.0.key()), contract_commitment)
                .unwrap();
            contract_commitments.push(contract_commitment);
        }
        tree.commit(&storage).unwrap().root
    }
}

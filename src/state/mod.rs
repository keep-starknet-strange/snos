pub mod node;
pub mod trie;

use blockifier::block_context::BlockContext;
use blockifier::execution::contract_class::ContractClass;
use blockifier::state::cached_state::CachedState;
use blockifier::state::state_api::{State, StateReader};
use cairo_felt::Felt252;
use indexmap::IndexMap;

use papyrus_storage::state::{StateStorageReader, StateStorageWriter};
use papyrus_storage::StorageResult;
use papyrus_storage::{db::DbConfig, open_storage, StorageConfig, StorageScope};

use starknet_api::block::BlockNumber;
use starknet_api::core::{ClassHash, PatriciaKey};
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedContractClass;
use starknet_api::hash::StarkHash;
use starknet_api::patricia_key;
use starknet_api::state::{StateDiff, ThinStateDiff};
use tempfile::{tempdir, TempDir};

use std::collections::HashMap;

use crate::config::DEFAULT_STORAGE_TREE_HEIGHT;
use crate::storage::{starknet::CommitmentInfo, DefaultTrieStorage};
use crate::utils::{bits_from_felt, calculate_contract_state_hash, vm_class_to_api_v0};
use trie::{MerkleTrie, PedersenHash};

pub struct ContractState {
    _contract_hash: Felt252,
    _storage_commitment_tree: Felt252,
    _nonce: Felt252,
}

pub struct SharedState<S: StateReader> {
    pub db_conf: StorageConfig,
    pub cache: CachedState<S>,
    pub block_context: BlockContext,
    _tmp: TempDir,
}

impl<S: StateReader> SharedState<S> {
    pub fn new(cache: CachedState<S>, block_context: BlockContext) -> Self {
        let _tmp = tempdir().unwrap();
        let db_conf = StorageConfig {
            db_config: DbConfig {
                chain_id: block_context.chain_id.clone(),
                path_prefix: _tmp.path().to_path_buf(),
                ..DbConfig::default()
            },
            scope: StorageScope::default(),
        };
        open_storage(db_conf.clone()).unwrap();
        Self {
            db_conf,
            cache,
            block_context,
            _tmp,
        }
    }
    pub fn get_block_num(&self) -> BlockNumber {
        self.block_context.block_number
    }

    pub fn increment_block(&mut self) {
        self.block_context.block_number = self.block_context.block_number.next();
    }

    pub fn get_diff(&self, block_num: BlockNumber) -> StorageResult<Option<ThinStateDiff>> {
        let (reader, _) = open_storage(self.db_conf.clone()).unwrap();
        let diff = reader.begin_ro_txn().unwrap().get_state_diff(block_num);
        diff
    }

    pub fn apply_diff(&mut self) -> CommitmentInfo {
        let diff = self.cache.to_state_diff();

        let mut deprecated_declared_classes: IndexMap<ClassHash, DeprecatedContractClass> =
            IndexMap::new();

        for (_addr, class_hash) in diff.address_to_class_hash.clone().into_iter() {
            match self.cache.get_compiled_contract_class(&class_hash).unwrap() {
                ContractClass::V0(class_inner) => {
                    deprecated_declared_classes.insert(class_hash, vm_class_to_api_v0(class_inner));
                }
                ContractClass::V1(_) => todo!("handle v1"),
            }
        }

        let state_diff = StateDiff {
            deprecated_declared_classes,
            deployed_contracts: diff.address_to_class_hash.clone(),
            storage_diffs: diff.storage_updates.clone(),
            nonces: diff.address_to_nonce.clone(),
            ..StateDiff::default()
        };

        let mut tree: MerkleTrie<PedersenHash, DEFAULT_STORAGE_TREE_HEIGHT> = MerkleTrie::empty();
        let storage = DefaultTrieStorage::default();

        for (addr, nonce) in diff.address_to_nonce {
            let class_hash = diff.address_to_class_hash.get(&addr).unwrap();

            // TODO: dynamically get contract root
            let contract_commitment =
                calculate_contract_state_hash(*class_hash, patricia_key!("0x0"), nonce);

            tree.set(&storage, bits_from_felt(*addr.0.key()), contract_commitment)
                .unwrap();
        }
        let updated_root = Felt252::from_bytes_be(tree.commit(&storage).unwrap().root.bytes());

        let (_, mut writer) = open_storage(self.db_conf.clone()).unwrap();

        writer
            .begin_rw_txn()
            .unwrap()
            .append_state_diff(self.block_context.block_number, state_diff, IndexMap::new())
            .unwrap()
            .commit()
            .unwrap();

        self.increment_block();

        CommitmentInfo {
            updated_root,
            previous_root: Felt252::from(0_u32),
            tree_height: DEFAULT_STORAGE_TREE_HEIGHT,
            commitment_facts: HashMap::new(),
        }
    }
}

pub mod node;
pub mod storage;
pub mod trie;

use blockifier::block_context::BlockContext;
use blockifier::execution::contract_class::ContractClass;
use blockifier::state::cached_state::{CachedState, CommitmentStateDiff};
use blockifier::state::state_api::{State, StateReader};
use cairo_felt::Felt252;
use indexmap::{IndexMap, IndexSet};
use storage::DefaultTrieStorage;

use papyrus_storage::state::{StateStorageReader, StateStorageWriter};
use papyrus_storage::StorageResult;
use papyrus_storage::{db::DbConfig, open_storage, StorageConfig, StorageScope};

use starknet_api::block::BlockNumber;
use starknet_api::core::{ClassHash, ContractAddress, PatriciaKey};
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedContractClass;
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::patricia_key;
use starknet_api::state::{StateDiff, ThinStateDiff};
use tempfile::{tempdir, TempDir};

use std::collections::HashMap;

use crate::config::DEFAULT_STORAGE_TREE_HEIGHT;
use crate::utils::{bits_from_felt, calculate_contract_state_hash, vm_class_to_api_v0};
use serde::{Deserialize, Serialize};
use trie::{MerkleTrie, PedersenHash};

type CommitmentFacts = HashMap<Felt252, Vec<Felt252>>;

#[derive(Debug, Serialize, Deserialize)]
pub struct CommitmentInfo {
    pub previous_root: Felt252,
    pub updated_root: Felt252,
    pub(crate) tree_height: usize,
    pub(crate) commitment_facts: CommitmentFacts,
}

pub struct ContractState {
    _contract_hash: Felt252,
    _storage_commitment_tree: Felt252,
    _nonce: Felt252,
}

pub struct SharedState<S: StateReader> {
    pub db_conf: StorageConfig,
    pub cache: CachedState<S>,
    pub block_context: BlockContext,
    pub commitment_storage: DefaultTrieStorage,
    pub contract_storage: DefaultTrieStorage,
    pub previous_storage_root: (StarkFelt, u64),
    pub previous_contract_root: (StarkFelt, u64),
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
        let commitment_storage = DefaultTrieStorage::default();
        let contract_storage = DefaultTrieStorage::default();
        open_storage(db_conf.clone()).unwrap();
        Self {
            db_conf,
            cache,
            block_context,
            commitment_storage,
            contract_storage,
            previous_storage_root: (StarkFelt::ZERO, 0_u64),
            previous_contract_root: (StarkFelt::ZERO, 0_u64),
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
        let mut accessed_addrs = IndexSet::new();

        let diff = self.cache.to_state_diff();

        let mut deprecated_declared_classes: IndexMap<ClassHash, DeprecatedContractClass> =
            IndexMap::new();

        for (addr, class_hash) in diff.address_to_class_hash.clone().into_iter() {
            match self.cache.get_compiled_contract_class(&class_hash).unwrap() {
                ContractClass::V0(class_inner) => {
                    deprecated_declared_classes.insert(class_hash, vm_class_to_api_v0(class_inner));
                }
                ContractClass::V1(_) => todo!("handle v1"),
            }
            accessed_addrs.insert(addr);
        }

        let state_diff = StateDiff {
            deprecated_declared_classes,
            deployed_contracts: diff.address_to_class_hash.clone(),
            storage_diffs: diff.storage_updates.clone(),
            nonces: diff.address_to_nonce.clone(),
            ..StateDiff::default()
        };

        let (_, mut writer) = open_storage(self.db_conf.clone()).unwrap();

        writer
            .begin_rw_txn()
            .unwrap()
            .append_state_diff(
                self.block_context.block_number,
                state_diff.clone(),
                IndexMap::new(),
            )
            .unwrap()
            .commit()
            .unwrap();

        let mut root_map = HashMap::new();

        for (addr, updates) in diff.storage_updates {
            let mut contract_trie: MerkleTrie<PedersenHash, DEFAULT_STORAGE_TREE_HEIGHT> =
                MerkleTrie::empty();

            for update in updates.clone() {
                contract_trie
                    .set(
                        &self.contract_storage,
                        bits_from_felt(*update.0 .0.key()),
                        update.1,
                    )
                    .unwrap();
            }
            let (contract_root, contract_idx) =
                self.contract_storage.commit_and_persist(contract_trie);
            root_map.insert(addr, patricia_key!(contract_root));
            accessed_addrs.insert(addr);
        }

        for (addr, _) in diff.address_to_nonce.clone().into_iter() {
            accessed_addrs.insert(addr);
        }

        let previous_storage_root = self.previous_storage_root;
        let mut storage_trie: MerkleTrie<PedersenHash, DEFAULT_STORAGE_TREE_HEIGHT> =
            if previous_storage_root.1 > 0 {
                MerkleTrie::new(previous_storage_root.1)
            } else {
                MerkleTrie::empty()
            };
        for addr in accessed_addrs {
            let nonce = match state_diff.nonces.get(&addr) {
                Some(new_nonce) => *new_nonce,
                None => self.cache.get_nonce_at(addr).unwrap(),
            };
            let root = match root_map.get(&addr) {
                Some(inner_root) => *inner_root,
                None => patricia_key!("0x0"),
            };
            let class_hash = self.cache.get_class_hash_at(addr).unwrap();

            let contract_commitment = calculate_contract_state_hash(class_hash, root, nonce);

            storage_trie
                .set(
                    &self.commitment_storage,
                    bits_from_felt(*addr.0.key()),
                    contract_commitment,
                )
                .unwrap();
        }

        let updated_root = self.commitment_storage.commit_and_persist(storage_trie);

        self.increment_block();
        self.previous_storage_root = updated_root;

        CommitmentInfo {
            previous_root: Felt252::from_bytes_be(previous_storage_root.0.bytes()),
            updated_root: Felt252::from_bytes_be(updated_root.0.bytes()),
            tree_height: DEFAULT_STORAGE_TREE_HEIGHT,
            commitment_facts: HashMap::new(),
        }
    }
}

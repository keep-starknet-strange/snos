pub mod node;
pub mod storage;
pub mod trie;

use blockifier::block_context::BlockContext;
use blockifier::execution::contract_class::ContractClass;
use blockifier::state::cached_state::{CachedState, CommitmentStateDiff};
use blockifier::state::state_api::{State, StateReader};
use cairo_felt::Felt252;
use indexmap::{IndexMap, IndexSet};
use storage::TrieStorage;

use starknet_api::block::BlockNumber;
use starknet_api::core::{ClassHash, ContractAddress, PatriciaKey};
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedContractClass;
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::{patricia_key, stark_felt};

use std::collections::HashMap;

use crate::config::DEFAULT_STORAGE_TREE_HEIGHT;
use crate::utils::{bits_from_felt, calculate_contract_state_hash, vm_class_to_api_v0};
use serde::{Deserialize, Serialize};
use trie::{MerkleTrie, PedersenHash};

type CommitmentFacts = HashMap<Felt252, Vec<Felt252>>;

#[derive(Debug, Default, Serialize, Deserialize)]
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
    pub cache: CachedState<S>,
    pub block_context: BlockContext,
    pub commitment_storage: TrieStorage,
    pub contract_storage: TrieStorage,
    pub class_storage: TrieStorage,
}

impl<S: StateReader> SharedState<S> {
    pub fn new(cache: CachedState<S>, block_context: BlockContext) -> Self {
        Self {
            cache,
            block_context,
            commitment_storage: TrieStorage::default(),
            contract_storage: TrieStorage::default(),
            class_storage: TrieStorage::default(),
        }
    }
    pub fn get_block_num(&self) -> BlockNumber {
        self.block_context.block_number
    }

    pub fn increment_block(&mut self) {
        self.block_context.block_number = self.block_context.block_number.next();
    }

    pub fn get_storage_root(&self, block_num: BlockNumber) -> (StarkFelt, u64) {
        *self
            .commitment_storage
            .root_map
            .get(&stark_felt!(block_num.0))
            .unwrap_or(&(StarkFelt::ZERO, 0_u64))
    }

    pub fn get_contract_root(&self, addr: ContractAddress) -> Option<&(StarkFelt, u64)> {
        self.contract_storage.root_map.get(addr.0.key())
    }

    pub fn apply_state(&mut self) -> CommitmentInfo {
        let (accessed_addrs, diff) = self.apply_diff();

        let mut storage_trie: MerkleTrie<PedersenHash, DEFAULT_STORAGE_TREE_HEIGHT> =
            match self.get_block_num().prev() {
                Some(block_num) => MerkleTrie::new(self.get_storage_root(block_num).1),
                None => MerkleTrie::empty(),
            };

        for addr in accessed_addrs {
            let nonce = match diff.address_to_nonce.get(&addr) {
                Some(new_nonce) => *new_nonce,
                None => self.cache.get_nonce_at(addr).unwrap_or_default(),
            };
            let root = match self.get_contract_root(addr) {
                Some(inner_root) => patricia_key!(inner_root.0),
                None => patricia_key!("0x0"),
            };
            let class_hash = match diff.address_to_class_hash.get(&addr) {
                Some(class_hash) => *class_hash,
                None => self.cache.get_class_hash_at(addr).unwrap(),
            };

            let contract_commitment = calculate_contract_state_hash(class_hash, root, nonce);

            storage_trie
                .set(
                    &self.commitment_storage,
                    bits_from_felt(*addr.0.key()),
                    contract_commitment,
                )
                .unwrap();
        }
        let block_num = self.get_block_num();
        let previous_root = self.get_storage_root(block_num);
        let updated_root = self
            .commitment_storage
            .commit_and_persist(storage_trie, stark_felt!(block_num.0));
        self.increment_block();

        CommitmentInfo {
            previous_root: Felt252::from_bytes_be(previous_root.0.bytes()),
            updated_root: Felt252::from_bytes_be(updated_root.0.bytes()),
            tree_height: DEFAULT_STORAGE_TREE_HEIGHT,
            commitment_facts: HashMap::new(),
        }
    }

    pub fn apply_diff(&mut self) -> (IndexSet<ContractAddress>, CommitmentStateDiff) {
        let diff = self.cache.to_state_diff();
        let mut accessed_addrs = IndexSet::new();

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

        for (addr, updates) in diff.storage_updates.clone() {
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
            self.contract_storage
                .commit_and_persist(contract_trie, *addr.0.key());

            accessed_addrs.insert(addr);
        }

        for (addr, _) in diff.address_to_nonce.clone().into_iter() {
            accessed_addrs.insert(addr);
        }

        (accessed_addrs, diff)
    }
}

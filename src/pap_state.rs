use blockifier::execution::contract_address;
use blockifier::state::state_api::{State, StateReader};
use indexmap::IndexMap;

use papyrus_storage::state::{StateStorageReader, StateStorageWriter};
use papyrus_storage::{db::DbConfig, open_storage, StorageConfig, StorageScope};

use starknet_api::block::BlockNumber;
use starknet_api::core::{ClassHash, ContractAddress, Nonce, PatriciaKey};
use starknet_api::hash::{pedersen_hash, StarkFelt, StarkHash};
use starknet_api::state::{DeprecatedDeclaredClasses, StateNumber};
use starknet_api::{
    class_hash, contract_address, core::ChainId, patricia_key, stark_felt, state::StateDiff,
};
use tempfile::{tempdir, TempDir};

use crate::state::trie::{MerkleTrie, PedersenHash};
use crate::storage::{bits_from_felt, DefaultStorage, Storage};

pub struct PapSharedState {
    db_conf: StorageConfig,
    cache: Box<dyn State>,
    _tmp: TempDir,
}

impl PapSharedState {
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

    pub fn apply_diff(
        &mut self,
        deprecated_class_mapping: Option<DeprecatedDeclaredClasses>,
    ) -> StarkFelt {
        let diff = self.cache.to_state_diff();

        let (_, mut writer) = open_storage(self.db_conf.clone()).unwrap();
        let mut state_diff = StateDiff {
            deployed_contracts: diff.address_to_class_hash,
            storage_diffs: diff.storage_updates.clone(),
            nonces: diff.address_to_nonce.clone(),
            ..StateDiff::default()
        };

        if let Some(dep_classes) = deprecated_class_mapping {
            state_diff.deprecated_declared_classes = dep_classes;
        }

        let mut txn = writer.begin_rw_txn().unwrap();
        txn = txn
            .append_state_diff(BlockNumber(0), state_diff.clone(), IndexMap::new())
            .unwrap();

        let statetxn = txn.get_state_reader().unwrap();
        let mut contract_commitments: Vec<StarkHash> = Vec::new();
        let mut tree: MerkleTrie<PedersenHash, 251> = MerkleTrie::empty();
        let storage = DefaultStorage::default();
        for (addr, nonce) in diff.address_to_nonce {
            let class_hash = statetxn
                .get_class_hash_at(StateNumber::right_after_block(BlockNumber(0)), &addr)
                .unwrap()
                .unwrap();

            let contract_commitment =
                calculate_contract_state_hash(class_hash, patricia_key!("0x0"), nonce);
            println!(
                "PAPY SET({}): {:?} {:?}",
                bits_from_felt(*addr.0.key()).len(),
                bits_from_felt(*addr.0.key()),
                contract_commitment
            );
            tree.set(&storage, bits_from_felt(*addr.0.key()), contract_commitment)
                .unwrap();
            contract_commitments.push(contract_commitment);
        }
        tree.commit(&storage).unwrap().root
    }
}

/// Calculates the contract state hash from its preimage.
pub fn calculate_contract_state_hash(
    class_hash: ClassHash,
    contract_root: PatriciaKey,
    nonce: Nonce,
) -> StarkHash {
    const CONTRACT_STATE_HASH_VERSION: StarkFelt = StarkFelt::ZERO;

    // The contract state hash is defined as H(H(H(hash, root), nonce), CONTRACT_STATE_HASH_VERSION)
    let hash = pedersen_hash(&class_hash.0, &contract_root.key());
    let hash = pedersen_hash(&hash, &nonce.0);
    pedersen_hash(&hash, &CONTRACT_STATE_HASH_VERSION)
}

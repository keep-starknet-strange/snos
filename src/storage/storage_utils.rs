use std::collections::{HashMap, HashSet};

use blockifier::state::cached_state::{CachedState, StorageEntry};
use blockifier::state::state_api::State;
use blockifier::test_utils::dict_state_reader::DictStateReader;
use cairo_vm::Felt252;
use starknet_api::hash::StarkFelt;

use crate::execution::helper::ContractStorageMap;
use crate::starknet::starknet_storage::{execute_coroutine_threadsafe, OsSingleStarknetStorage, StorageLeaf};
use crate::starkware_utils::commitment_tree::base_types::Height;
use crate::starkware_utils::commitment_tree::binary_fact_tree::BinaryFactTree;
use crate::starkware_utils::commitment_tree::errors::TreeError;
use crate::starkware_utils::commitment_tree::leaf_fact::LeafFact;
use crate::starkware_utils::commitment_tree::patricia_tree::patricia_tree::PatriciaTree;
use crate::starkware_utils::serializable::{DeserializeError, Serializable, SerializeError};
use crate::storage::dict_storage::DictStorage;
use crate::storage::storage::{DbObject, Fact, FactFetchingContext, HashFunctionType, Storage};
use crate::utils::felt_api2vm;

#[derive(Clone, Debug, PartialEq)]
pub struct SimpleLeafFact {
    pub value: Felt252,
}

impl SimpleLeafFact {
    pub fn new(value: Felt252) -> Self {
        Self { value }
    }

    pub fn empty() -> Self {
        Self::new(Felt252::ZERO)
    }
}

impl<S, H> Fact<S, H> for SimpleLeafFact
where
    H: HashFunctionType,
    S: Storage,
{
    fn hash(&self) -> Vec<u8> {
        self.serialize().unwrap()
    }
}

impl DbObject for SimpleLeafFact {}

impl Serializable for SimpleLeafFact {
    fn serialize(&self) -> Result<Vec<u8>, SerializeError> {
        Ok(self.value.to_bytes_be().to_vec())
    }

    fn deserialize(data: &[u8]) -> Result<Self, DeserializeError> {
        let value = Felt252::from_bytes_be_slice(data);
        Ok(Self { value })
    }
}

impl<S, H> LeafFact<S, H> for SimpleLeafFact
where
    S: Storage,
    H: HashFunctionType,
{
    fn is_empty(&self) -> bool {
        self.value == Felt252::ZERO
    }
}

/// An intermediate contract -> [(key, value), ...] map representation.
type StorageMap = HashMap<Felt252, Vec<(Felt252, Felt252)>>;

/// CachedState's `state.state.storage_view` is a mapping of (contract, storage_key) -> value
/// but we need a mapping of (contract) -> [(storage_key, value)] so we can build the tree
/// in one go.
fn get_contract_storage_map(storage_view: &HashMap<StorageEntry, StarkFelt>) -> StorageMap {
    let mut contract_storage_map: HashMap<Felt252, Vec<(Felt252, Felt252)>> = Default::default();
    for ((contract_address, storage_key), value) in storage_view {
        let contract_address = felt_api2vm(*contract_address.0.key());
        let storage_key = felt_api2vm(*storage_key.0.key());
        let value = felt_api2vm(*value);

        contract_storage_map.entry(contract_address).or_default();
        contract_storage_map.get_mut(&contract_address).unwrap().push((storage_key, value));
    }

    contract_storage_map
}

/// Builds the final state storage map.
fn build_final_storage_map(final_state: &mut CachedState<DictStateReader>) -> StorageMap {
    let mut storage = final_state.state.storage_view.clone();
    let storage_updates = final_state.to_state_diff().storage_updates;

    for (contract_address, contract_storage_updates) in storage_updates {
        for (key, value) in contract_storage_updates {
            storage.insert((contract_address, key), value);
        }
    }

    get_contract_storage_map(&storage)
}

/// Builds a Patricia tree for a specific contract.
///
/// Applies the `contract_storage` values as modifications to an empty Patricia tree and returns
/// the updated tree.
async fn build_patricia_tree_from_contract_storage<S, H>(
    ffc: &mut FactFetchingContext<S, H>,
    contract_storage: &[(Felt252, Felt252)],
) -> Result<PatriciaTree, TreeError>
where
    S: Storage + Send + Sync + 'static,
    H: HashFunctionType + Send + Sync + 'static,
{
    let modifications: Vec<_> =
        contract_storage.iter().map(|(key, value)| (key.to_biguint(), StorageLeaf::new(*value))).collect();

    let mut facts = None;
    let mut tree = PatriciaTree::empty_tree(ffc, Height(251), StorageLeaf::empty()).await.unwrap();
    tree.update(ffc, modifications, &mut facts).await
}

/// Translates the (final) Blockifier state into an OS-compatible structure.
///
/// This function uses the fact that `CachedState` is a wrapper around a read-only `DictStateReader`
/// object. The initial state is obtained through this read-only view while the final storage
/// is obtained by extracting the state diff from the `CachedState` part.
pub fn build_starknet_storage(blockifier_state: &mut CachedState<DictStateReader>) -> ContractStorageMap {
    let initial_contract_storage_map = get_contract_storage_map(&blockifier_state.state.storage_view);
    let final_contract_storage_map = build_final_storage_map(blockifier_state);

    let all_contracts =
        initial_contract_storage_map.keys().chain(final_contract_storage_map.keys()).collect::<HashSet<&Felt252>>();

    let mut storage_by_address = ContractStorageMap::new();

    let empty_state = Default::default();

    let mut ffc = FactFetchingContext::new(DictStorage::default());
    for contract_address in all_contracts {
        println!("Creating initial state for contract {}", contract_address);
        let initial_contract_storage = initial_contract_storage_map.get(contract_address).unwrap_or(&empty_state);
        let final_contract_storage =
            final_contract_storage_map.get(contract_address).expect("any contract should appear in final storage");

        execute_coroutine_threadsafe(async {
            let initial_tree =
                build_patricia_tree_from_contract_storage(&mut ffc, initial_contract_storage).await.unwrap();
            let updated_tree =
                build_patricia_tree_from_contract_storage(&mut ffc, final_contract_storage).await.unwrap();

            let contract_storage =
                OsSingleStarknetStorage::new(initial_tree, updated_tree, &[], ffc.clone()).await.unwrap();
            storage_by_address.insert(*contract_address, contract_storage);
        });
    }

    storage_by_address
}

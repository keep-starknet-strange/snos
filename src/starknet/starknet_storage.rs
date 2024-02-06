use std::collections::HashMap;

use cairo_vm::Felt252;

use crate::starkware_utils::commitment_tree::binary_fact_tree::BinaryFactTree;
use crate::starkware_utils::commitment_tree::leaf_fact::LeafFact;
use crate::starkware_utils::commitment_tree::patricia_tree::patricia_tree::{PatriciaTree, EMPTY_NODE_HASH};
use crate::starkware_utils::serializable::{DeserializeError, Serializable, SerializeError};
use crate::storage::storage::{DbObject, Fact, FactFetchingContext, HashFunctionType, Storage};

#[derive(Clone, Debug, PartialEq)]
pub struct StorageLeaf {
    pub value: Felt252,
}

impl<S, H> Fact<S, H> for StorageLeaf
where
    H: HashFunctionType,
    S: Storage,
{
    fn hash(&self) -> Vec<u8> {
        if <StorageLeaf as LeafFact<S, H>>::is_empty(self) {
            return EMPTY_NODE_HASH.to_vec();
        }
        self.serialize().unwrap()
    }
}

impl DbObject for StorageLeaf {}

impl Serializable for StorageLeaf {
    fn prefix() -> Vec<u8> {
        "starknet_storage_leaf".as_bytes().to_vec()
    }
    fn serialize(&self) -> Result<Vec<u8>, SerializeError> {
        Ok(self.value.to_bytes_be().to_vec())
    }

    fn deserialize(data: &[u8]) -> Result<Self, DeserializeError> {
        let value = Felt252::from_bytes_be_slice(data);
        Ok(Self { value })
    }
}

impl<S, H> LeafFact<S, H> for StorageLeaf
where
    S: Storage,
    H: HashFunctionType,
{
    fn is_empty(&self) -> bool {
        self.value == Felt252::ZERO
    }
}

#[derive(Clone, Debug)]
pub struct OsSingleStarknetStorage<S, H>
where
    S: Storage,
    H: HashFunctionType,
{
    previous_tree: PatriciaTree,
    _expected_updated_root: Felt252,
    ongoing_storage_changes: HashMap<Felt252, Felt252>,
    ffc: FactFetchingContext<S, H>,
}

fn execute_coroutine_threadsafe<F, T>(coroutine: F) -> T
where
    F: std::future::Future<Output = T>,
{
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(coroutine)
}

impl<S, H> OsSingleStarknetStorage<S, H>
where
    S: Storage + 'static,
    H: HashFunctionType + Sync + Send + 'static,
{
    pub fn read(&mut self, key: Felt252) -> Option<Felt252> {
        let mut value = self.ongoing_storage_changes.get(&key).cloned();

        if value.is_none() {
            let value_from_storage = self.fetch_storage_leaf(key).value;
            self.ongoing_storage_changes.insert(key, value_from_storage);
            value = Some(value_from_storage);
        }

        value
    }

    fn fetch_storage_leaf(&mut self, key: Felt252) -> StorageLeaf {
        let coroutine = self.previous_tree.get_leaf(&mut self.ffc, key.to_biguint());
        let result: Result<Option<StorageLeaf>, _> = execute_coroutine_threadsafe(coroutine);

        // TODO: resolve this double unwrap() somehow
        result.unwrap().unwrap()
    }
}

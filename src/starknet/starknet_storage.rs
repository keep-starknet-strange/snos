use std::collections::HashMap;

use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::Felt252;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::starkware_utils::commitment_tree::base_types::TreeIndex;
use crate::starkware_utils::commitment_tree::binary_fact_tree::{
    binary_fact_dict_to_felts, BinaryFactDict, BinaryFactTree,
};
use crate::starkware_utils::commitment_tree::errors::TreeError;
use crate::starkware_utils::commitment_tree::leaf_fact::LeafFact;
use crate::starkware_utils::commitment_tree::patricia_tree::patricia_tree::{PatriciaTree, EMPTY_NODE_HASH};
use crate::starkware_utils::serializable::{DeserializeError, Serializable, SerializeError};
use crate::storage::storage::{DbObject, Fact, FactFetchingContext, HashFunctionType, Storage};
use crate::utils::{Felt252Num, Felt252Str};

#[derive(Clone, Debug, PartialEq)]
pub struct StorageLeaf {
    pub value: Felt252,
}

impl StorageLeaf {
    pub fn new(value: Felt252) -> Self {
        Self { value }
    }

    pub fn empty() -> Self {
        Self::new(Felt252::ZERO)
    }
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

/// Contains hints needed for the commitment tree update in the OS.
#[serde_as]
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
pub struct CommitmentInfo {
    #[serde_as(as = "Felt252Num")]
    pub previous_root: Felt252,
    #[serde_as(as = "Felt252Num")]
    pub updated_root: Felt252,
    pub tree_height: usize,
    #[serde_as(as = "HashMap<Felt252Str, Vec<Felt252Str>>")]
    pub commitment_facts: HashMap<Felt252, Vec<Felt252>>,
}

#[derive(thiserror::Error, Debug)]
pub enum CommitmentInfoError {
    #[error(transparent)]
    Tree(#[from] TreeError),

    #[error("Inconsistent commitment tree roots")]
    UpdatedRootMismatch,
}

impl From<CommitmentInfoError> for HintError {
    fn from(error: CommitmentInfoError) -> Self {
        HintError::CustomHint(error.to_string().into_boxed_str())
    }
}

impl CommitmentInfo {
    /// Returns a commitment info that corresponds to the given modifications.
    pub async fn create_from_modifications<S, H, LF>(
        mut previous_tree: PatriciaTree,
        expected_updated_root: Felt252,
        modifications: Vec<(TreeIndex, LF)>,
        ffc: &mut FactFetchingContext<S, H>,
    ) -> Result<Self, CommitmentInfoError>
    where
        S: Storage + 'static,
        H: HashFunctionType + Sync + Send + 'static,
        LF: LeafFact<S, H> + Send + 'static,
    {
        let previous_tree_root = Felt252::from_bytes_be_slice(&previous_tree.root);

        let mut commitment_facts = Some(BinaryFactDict::new());
        let actual_updated_tree = previous_tree.update(ffc, modifications, &mut commitment_facts).await?;
        let actual_updated_root = Felt252::from_bytes_be_slice(&actual_updated_tree.root);

        if actual_updated_root != expected_updated_root {
            return Err(CommitmentInfoError::UpdatedRootMismatch);
        }

        // Note: unwrapping is safe here as we wrap the value ourselves a few lines above.
        let commitment_facts = binary_fact_dict_to_felts(commitment_facts.unwrap());

        Ok(Self {
            previous_root: previous_tree_root,
            updated_root: actual_updated_root,
            tree_height: previous_tree.height.0 as usize,
            commitment_facts,
        })
    }
}

#[derive(Clone, Debug)]
pub struct OsSingleStarknetStorage<S, H>
where
    S: Storage,
    H: HashFunctionType,
{
    previous_tree: PatriciaTree,
    expected_updated_root: Felt252,
    ongoing_storage_changes: HashMap<TreeIndex, Felt252>,
    ffc: FactFetchingContext<S, H>,
}

impl<S, H> OsSingleStarknetStorage<S, H>
where
    S: Storage + 'static,
    H: HashFunctionType + Sync + Send + 'static,
{
    pub async fn new(
        previous_tree: PatriciaTree,
        updated_tree: PatriciaTree,
        accessed_addresses: &[TreeIndex],
        mut ffc: FactFetchingContext<S, H>,
    ) -> Result<Self, TreeError> {
        // Fetch initial values of keys accessed by this contract.
        // NOTE: this is an optimization - not all values can be fetched ahead.
        let mut facts = None;
        let initial_leaves: HashMap<TreeIndex, StorageLeaf> =
            previous_tree.get_leaves(&mut ffc, accessed_addresses, &mut facts).await?;
        let initial_entries: HashMap<_, _> = initial_leaves.into_iter().map(|(key, leaf)| (key, leaf.value)).collect();

        let expected_updated_root = Felt252::from_bytes_be_slice(&updated_tree.root);

        Ok(Self { previous_tree, expected_updated_root, ongoing_storage_changes: initial_entries, ffc })
    }

    /// Computes the commitment info based on the ongoing storage changes which is maintained
    /// during the transaction execution phase; should be called after the execution phase.
    pub async fn compute_commitment(&mut self) -> Result<CommitmentInfo, CommitmentInfoError> {
        let final_modifications: Vec<_> = self
            .ongoing_storage_changes
            .clone()
            .into_iter()
            .map(|(key, value)| (key, StorageLeaf::new(value)))
            .collect();

        CommitmentInfo::create_from_modifications(
            self.previous_tree.clone(),
            self.expected_updated_root,
            final_modifications,
            &mut self.ffc,
        )
        .await
    }
}

pub fn execute_coroutine_threadsafe<F, T>(coroutine: F) -> T
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
        let mut value = self.ongoing_storage_changes.get(&key.to_biguint()).cloned();

        if value.is_none() {
            let leaf = self.fetch_storage_leaf(key);
            let value_from_storage = leaf.value;
            self.ongoing_storage_changes.insert(key.to_biguint(), value_from_storage);
            value = Some(value_from_storage);
        }

        value
    }

    pub fn write(&mut self, key: TreeIndex, value: Felt252) {
        self.ongoing_storage_changes.insert(key, value);
    }

    fn fetch_storage_leaf(&mut self, key: Felt252) -> StorageLeaf {
        let coroutine = self.previous_tree.get_leaf(&mut self.ffc, key.to_biguint());
        let result: Result<Option<StorageLeaf>, _> = execute_coroutine_threadsafe(coroutine);

        // TODO: resolve this double unwrap() somehow
        result.unwrap().unwrap()
    }
}

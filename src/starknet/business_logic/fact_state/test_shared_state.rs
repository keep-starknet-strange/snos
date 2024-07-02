use std::collections::{HashMap, HashSet};

use blockifier::execution::contract_class::ContractClass;
use blockifier::state::cached_state::CommitmentStateDiff;
use blockifier::state::state_api::{StateReader, StateResult};
use cairo_vm::Felt252;
use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use crate::starknet::business_logic::fact_state::contract_class_objects::{
    get_ffc_for_contract_class_facts, ContractClassLeaf,
};
use crate::starknet::business_logic::fact_state::contract_state_objects::ContractState;
use crate::starknet::business_logic::fact_state::state::SharedState;
use crate::starkware_utils::commitment_tree::base_types::TreeIndex;
use crate::starkware_utils::commitment_tree::binary_fact_tree::BinaryFactTree;
use crate::starkware_utils::commitment_tree::errors::TreeError;
use crate::storage::storage::{FactFetchingContext, HashFunctionType, Storage};
use crate::utils::felt_api2vm;

#[derive(Debug)]
/// A Starknet shared state compatible with Blockifier and with some caching features
/// to make life easier during integration tests.
pub struct TestSharedState<S, H>
where
    S: Storage + 'static,
    H: HashFunctionType + Send + Sync + 'static,
{
    /// The Starknet state.
    shared_state: SharedState<S, H>,
    /// Set of all the contracts in this state. Used to cache contract values and avoid
    /// traversing the tree.
    contract_addresses: HashSet<TreeIndex>,
}

// For some reason, derive(Clone) wants to have S: Clone and H: Clone.
// There is no reason to require that, so we implement Clone manually.
impl<S, H> Clone for TestSharedState<S, H>
where
    S: Storage + 'static,
    H: HashFunctionType + Send + Sync + 'static,
{
    fn clone(&self) -> Self {
        Self { shared_state: self.shared_state.clone(), contract_addresses: self.contract_addresses.clone() }
    }
}

impl<S, H> TestSharedState<S, H>
where
    S: Storage + 'static,
    H: HashFunctionType + Send + Sync + 'static,
{
    pub fn ffc(&self) -> &FactFetchingContext<S, H> {
        &self.shared_state.ffc
    }

    pub fn shared_state(&self) -> &SharedState<S, H> {
        &self.shared_state
    }

    pub fn contract_addresses(&self) -> &HashSet<TreeIndex> {
        &self.contract_addresses
    }

    pub async fn empty(ffc: FactFetchingContext<S, H>) -> Result<Self, TreeError> {
        Ok(Self { shared_state: SharedState::empty(ffc).await?, contract_addresses: Default::default() })
    }

    pub async fn from_blockifier_state(
        ffc: FactFetchingContext<S, H>,
        blockifier_state: blockifier::test_utils::dict_state_reader::DictStateReader,
    ) -> Result<Self, TreeError> {
        let empty_state = Self::empty(ffc).await?;

        let mut storage_updates: HashMap<ContractAddress, HashMap<StorageKey, StarkFelt>> = HashMap::new();
        for ((address, key), value) in blockifier_state.storage_view {
            storage_updates.entry(address).or_default().insert(key, value);
        }

        let updated_state = empty_state
            .apply_state_updates_starknet_api(
                blockifier_state.address_to_class_hash,
                blockifier_state.address_to_nonce,
                blockifier_state.class_hash_to_compiled_class_hash,
                storage_updates,
            )
            .await?;

        Ok(updated_state)
    }

    /// Updates the global state using a state diff generated with Blockifier.
    pub async fn apply_commitment_state_diff(self, state_diff: CommitmentStateDiff) -> Result<Self, TreeError> {
        // TODO: find a better solution than creating new hashmaps
        self.apply_state_updates_starknet_api(
            state_diff.address_to_class_hash.into_iter().collect(),
            state_diff.address_to_nonce.into_iter().collect(),
            state_diff.class_hash_to_compiled_class_hash.into_iter().collect(),
            state_diff
                .storage_updates
                .into_iter()
                .map(|(address, updates)| (address, updates.into_iter().collect()))
                .collect(),
        )
        .await
    }

    /// A compatibility function to apply state updates specified in the Starknet API types.
    async fn apply_state_updates_starknet_api(
        self,
        address_to_class_hash: HashMap<ContractAddress, ClassHash>,
        address_to_nonce: HashMap<ContractAddress, Nonce>,
        class_hash_to_compiled_class_hash: HashMap<ClassHash, CompiledClassHash>,
        storage_updates: HashMap<ContractAddress, HashMap<StorageKey, StarkFelt>>,
    ) -> Result<Self, TreeError> {
        let address_to_class_hash: HashMap<_, _> = address_to_class_hash
            .into_iter()
            .map(|(address, class_hash)| (felt_api2vm(*address.0.key()), felt_api2vm(class_hash.0)))
            .collect();

        let address_to_nonce: HashMap<_, _> = address_to_nonce
            .into_iter()
            .map(|(address, nonce)| (felt_api2vm(*address.0.key()), felt_api2vm(nonce.0)))
            .collect();

        let class_hash_to_compiled_class_hash: HashMap<_, _> = class_hash_to_compiled_class_hash
            .into_iter()
            .map(|(class_hash, compiled_class_hash)| (felt_api2vm(class_hash.0), felt_api2vm(compiled_class_hash.0)))
            .collect();

        let storage_updates: HashMap<_, HashMap<_, _>> = storage_updates
            .into_iter()
            .map(|(address, contract_storage_updates)| {
                (
                    felt_api2vm(*address.0.key()),
                    contract_storage_updates
                        .into_iter()
                        .map(|(k, v)| (felt_api2vm(*k.0.key()), felt_api2vm(v)))
                        .collect(),
                )
            })
            .collect();

        self.apply_state_updates(
            address_to_class_hash,
            address_to_nonce,
            class_hash_to_compiled_class_hash,
            storage_updates,
        )
        .await
    }

    /// Applies state updates and recomputes the per-contract and global trees.
    async fn apply_state_updates(
        self,
        address_to_class_hash: HashMap<Felt252, Felt252>,
        address_to_nonce: HashMap<Felt252, Felt252>,
        class_hash_to_compiled_class_hash: HashMap<Felt252, Felt252>,
        storage_updates: HashMap<Felt252, HashMap<Felt252, Felt252>>,
    ) -> Result<Self, TreeError> {
        let accessed_addresses_felts: HashSet<_> = address_to_class_hash
            .keys()
            // .chain(address_to_class_hash.values()) // TODO: should this be included?
            .chain(address_to_nonce.keys())
            .chain(storage_updates.keys())
            .collect();
        let accessed_addresses: Vec<TreeIndex> = accessed_addresses_felts.iter().map(|x| x.to_biguint()).collect();

        let mut facts = None;
        let mut ffc = self.shared_state.ffc;
        let mut current_contract_states: HashMap<TreeIndex, ContractState> =
            self.shared_state.contract_states.get_leaves(&mut ffc, &accessed_addresses, &mut facts).await?;

        // Update contract storage roots with cached changes.
        let empty_updates = HashMap::new();
        let mut updated_contract_states = HashMap::new();
        for address in accessed_addresses_felts {
            // unwrap() is safe as an entry is guaranteed to be present with `get_leaves()`.
            let tree_index = address.to_biguint();
            let updates = storage_updates.get(address).unwrap_or(&empty_updates);
            let nonce = address_to_nonce.get(address).cloned();
            let class_hash = address_to_class_hash.get(address).cloned();
            let updated_contract_state = current_contract_states
                .remove(&tree_index)
                .unwrap()
                .update(&mut ffc, updates, nonce, class_hash)
                .await?;

            updated_contract_states.insert(tree_index, updated_contract_state);
        }

        // Apply contract changes on global root.
        log::debug!("Updating contract state tree with {} modifications...", accessed_addresses.len());
        let global_state_modifications: Vec<_> = updated_contract_states.into_iter().collect();

        let updated_global_contract_root =
            self.shared_state.contract_states.update(&mut ffc, global_state_modifications, &mut facts).await?;

        let mut ffc_for_contract_class = get_ffc_for_contract_class_facts(&ffc);

        let updated_contract_classes = match self.shared_state.contract_classes {
            Some(tree) => {
                log::debug!(
                    "Updating contract class tree with {} modifications...",
                    class_hash_to_compiled_class_hash.len()
                );
                let modifications: Vec<_> = class_hash_to_compiled_class_hash
                    .into_iter()
                    .map(|(key, value)| (key.to_biguint(), ContractClassLeaf::create(value)))
                    .collect();
                Some(tree.update(&mut ffc_for_contract_class, modifications, &mut facts).await?)
            }
            None => {
                assert_eq!(
                    class_hash_to_compiled_class_hash.len(),
                    0,
                    "contract_classes must be concrete before update."
                );
                None
            }
        };

        let accessed_addresses: HashSet<_> = accessed_addresses.into_iter().collect();
        let contract_addresses: HashSet<_> = self.contract_addresses.union(&accessed_addresses).cloned().collect();

        Ok(Self {
            shared_state: SharedState {
                contract_states: updated_global_contract_root,
                contract_classes: updated_contract_classes,
                ffc,
                ffc_for_class_hash: ffc_for_contract_class,
            },
            contract_addresses,
        })
    }
}

impl<S, H> StateReader for TestSharedState<S, H>
where
    S: Storage + 'static,
    H: HashFunctionType + Send + Sync + 'static,
{
    fn get_storage_at(&mut self, contract_address: ContractAddress, key: StorageKey) -> StateResult<StarkFelt> {
        self.shared_state.get_storage_at(contract_address, key)
    }

    fn get_nonce_at(&mut self, contract_address: ContractAddress) -> StateResult<Nonce> {
        self.shared_state.get_nonce_at(contract_address)
    }

    fn get_class_hash_at(&mut self, contract_address: ContractAddress) -> StateResult<ClassHash> {
        self.shared_state.get_class_hash_at(contract_address)
    }

    fn get_compiled_contract_class(&mut self, class_hash: ClassHash) -> StateResult<ContractClass> {
        self.shared_state.get_compiled_contract_class(class_hash)
    }

    fn get_compiled_class_hash(&mut self, class_hash: ClassHash) -> StateResult<CompiledClassHash> {
        self.shared_state.get_compiled_class_hash(class_hash)
    }
}

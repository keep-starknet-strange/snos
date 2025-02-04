use std::collections::{HashMap, HashSet};
use std::ops::Deref;

use blockifier::execution::contract_class::ContractClass;
use blockifier::state::cached_state::CommitmentStateDiff;
use blockifier::state::errors::StateError;
use blockifier::state::state_api::{StateReader, StateResult};
use cairo_vm::types::errors::math_errors::MathError;
use cairo_vm::Felt252;
use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::state::StorageKey;
use starknet_os_types::casm_contract_class::GenericCasmContractClass;
use starknet_os_types::deprecated_compiled_class::GenericDeprecatedCompiledClass;
use starknet_os_types::hash::Hash;

use crate::config::{
    COMPILED_CLASS_HASH_COMMITMENT_TREE_HEIGHT, CONTRACT_ADDRESS_BITS, CONTRACT_STATES_COMMITMENT_TREE_HEIGHT,
    GLOBAL_STATE_VERSION,
};
use crate::crypto::poseidon::{poseidon_hash_many_bytes, PoseidonHash};
use crate::starknet::business_logic::fact_state::contract_class_objects::{
    get_ffc_for_contract_class_facts, CompiledClassFact, ContractClassLeaf, DeprecatedCompiledClassFact,
};
use crate::starknet::business_logic::fact_state::contract_state_objects::ContractState;
use crate::starknet::starknet_storage::StorageLeaf;
use crate::starkware_utils::commitment_tree::base_types::{Height, TreeIndex};
use crate::starkware_utils::commitment_tree::binary_fact_tree::BinaryFactTree;
use crate::starkware_utils::commitment_tree::errors::TreeError;
use crate::starkware_utils::commitment_tree::leaf_fact::LeafFact;
use crate::starkware_utils::commitment_tree::patricia_tree::patricia_tree::PatriciaTree;
use crate::storage::storage::{DbObject, FactFetchingContext, HashFunctionType, Storage, StorageError};
use crate::utils::execute_coroutine;

/// A class representing a combination of the onchain and offchain state.
#[derive(Debug)]
pub struct SharedState<S, H>
where
    S: Storage + 'static,
    H: HashFunctionType + Send + Sync + 'static,
{
    pub contract_states: PatriciaTree,
    /// Leaf addresses are class hashes; leaf values contain compiled class hashes.
    /// Optional because some older states did not have class commitment.
    pub contract_classes: Option<PatriciaTree>,
    pub ffc: FactFetchingContext<S, H>,
    pub ffc_for_class_hash: FactFetchingContext<S, PoseidonHash>,
    /// Set of all the contracts in this state. Used to cache contract values to avoid
    /// traversing the tree.
    pub contract_addresses: HashSet<TreeIndex>,
}

// For some reason, derive(Clone) wants to have S: Clone and H: Clone.
// There is no reason to require that, so we implement Clone manually.
impl<S, H> Clone for SharedState<S, H>
where
    S: Storage + 'static,
    H: HashFunctionType + Send + Sync + 'static,
{
    fn clone(&self) -> Self {
        Self {
            contract_states: self.contract_states.clone(),
            contract_classes: self.contract_classes.clone(),
            ffc: self.ffc.clone(),
            ffc_for_class_hash: self.ffc_for_class_hash.clone(),
            contract_addresses: self.contract_addresses.clone(),
        }
    }
}

impl<S, H> SharedState<S, H>
where
    S: Storage + 'static,
    H: HashFunctionType + Send + Sync + 'static,
{
    pub fn state_version() -> Felt252 {
        Felt252::from_bytes_be_slice(GLOBAL_STATE_VERSION)
    }

    /// Returns an empty contract state tree.
    pub async fn create_empty_contract_states(ffc: &mut FactFetchingContext<S, H>) -> Result<PatriciaTree, TreeError> {
        let empty_contract_state =
            ContractState::empty(Height(CONTRACT_STATES_COMMITMENT_TREE_HEIGHT as u64), ffc).await?;
        PatriciaTree::empty_tree(ffc, Height(CONTRACT_ADDRESS_BITS as u64), empty_contract_state).await
    }

    /// Returns an empty contract class tree.
    async fn create_empty_contract_class_tree(ffc: &mut FactFetchingContext<S, H>) -> Result<PatriciaTree, TreeError> {
        PatriciaTree::empty_tree(
            ffc,
            Height(COMPILED_CLASS_HASH_COMMITMENT_TREE_HEIGHT as u64),
            ContractClassLeaf::empty(),
        )
        .await
    }

    /// Returns an empty state. This is called before creating very first block.
    pub async fn empty(mut ffc: FactFetchingContext<S, H>) -> Result<Self, TreeError> {
        let empty_contract_states = Self::create_empty_contract_states(&mut ffc).await?;
        let empty_contract_classes = Self::create_empty_contract_class_tree(&mut ffc).await?;

        let ffc_for_class_hash = get_ffc_for_contract_class_facts(&ffc);

        Ok(Self {
            contract_states: empty_contract_states,
            contract_classes: Some(empty_contract_classes),
            ffc,
            ffc_for_class_hash,
            contract_addresses: Default::default(),
        })
    }

    /// Returns the set of all known contract addresses.
    pub fn contract_addresses(&self) -> HashSet<TreeIndex> {
        self.contract_addresses.clone()
    }

    /// Returns the state's contract class Patricia tree if it exists;
    /// Otherwise returns an empty tree.
    pub async fn get_contract_class_tree(
        &self,
        ffc: &mut FactFetchingContext<S, H>,
    ) -> Result<PatriciaTree, TreeError> {
        match &self.contract_classes {
            Some(tree) => Ok(tree.clone()),
            None => Self::create_empty_contract_class_tree(ffc).await,
        }
    }

    /// Returns the global state root.
    /// If both the contract class and contract state trees are empty, the global root is set to
    /// 0. If no contract class state exists or if it is empty, the global state root is equal to
    /// the contract state root (for backward compatibility);
    /// Otherwise, the global root is obtained by:
    /// global_root =  H(state_version, contract_state_root, contract_class_root).
    #[allow(unused)] // TODO: remove
    fn get_global_state_root(&self) -> Result<Felt252, MathError> {
        let contract_states_root = &self.contract_states.root;

        let empty_tree_root = Hash::empty();
        let contract_classes_root = match &self.contract_classes {
            Some(tree) => &tree.root,
            None => &empty_tree_root,
        };

        if *contract_states_root == empty_tree_root && *contract_classes_root == empty_tree_root {
            // The shared state is empty.
            return Ok(Felt252::ZERO);
        }

        // Backward compatibility; Used during the migration from a state without a
        // contract class tree to a state with a contract class tree.
        if *contract_classes_root == empty_tree_root {
            // The contract classes' state is empty.
            return Ok(Felt252::from_bytes_be_slice(contract_states_root));
        }

        // Return H(contract_state_root, contract_class_root, state_version).
        poseidon_hash_many_bytes(&[&Self::state_version().to_bytes_be(), contract_states_root, contract_classes_root])
            .map(|x| Felt252::from_bytes_be_slice(&x))
    }

    pub async fn from_blockifier_state(
        ffc: FactFetchingContext<S, H>,
        blockifier_state: blockifier::test_utils::dict_state_reader::DictStateReader,
    ) -> Result<Self, TreeError> {
        let empty_state = Self::empty(ffc).await?;

        let mut storage_updates: HashMap<ContractAddress, HashMap<StorageKey, Felt252>> = HashMap::new();
        for ((address, key), value) in blockifier_state.storage_view {
            storage_updates.entry(address).or_default().insert(key, value);
        }

        let shared_state = empty_state
            .apply_state_updates_starknet_api(
                blockifier_state.address_to_class_hash,
                blockifier_state.address_to_nonce,
                blockifier_state.class_hash_to_compiled_class_hash,
                storage_updates,
            )
            .await?;

        Ok(shared_state)
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
        storage_updates: HashMap<ContractAddress, HashMap<StorageKey, Felt252>>,
    ) -> Result<Self, TreeError> {
        let address_to_class_hash: HashMap<_, _> =
            address_to_class_hash.into_iter().map(|(address, class_hash)| (*address.0.key(), class_hash.0)).collect();

        let address_to_nonce: HashMap<_, _> =
            address_to_nonce.into_iter().map(|(address, nonce)| (*address.0.key(), nonce.0)).collect();

        let class_hash_to_compiled_class_hash: HashMap<_, _> = class_hash_to_compiled_class_hash
            .into_iter()
            .map(|(class_hash, compiled_class_hash)| (class_hash.0, compiled_class_hash.0))
            .collect();

        let storage_updates: HashMap<_, HashMap<_, _>> = storage_updates
            .into_iter()
            .map(|(address, contract_storage_updates)| {
                (*address.0.key(), contract_storage_updates.into_iter().map(|(k, v)| (*k.0.key(), v)).collect())
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
        mut self,
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
        let mut current_contract_states: HashMap<TreeIndex, ContractState> =
            self.contract_states.get_leaves(&mut self.ffc, &accessed_addresses, &mut facts).await?;

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
                .update(&mut self.ffc, updates, nonce, class_hash)
                .await?;

            updated_contract_states.insert(tree_index, updated_contract_state);
        }

        // Apply contract changes on global root.
        log::debug!("Updating contract state tree with {} modifications...", accessed_addresses.len());
        let global_state_modifications: Vec<_> = updated_contract_states.into_iter().collect();
        let updated_global_contract_root =
            self.contract_states.update(&mut self.ffc, global_state_modifications, &mut facts).await?;

        let mut ffc_for_contract_class = get_ffc_for_contract_class_facts(&self.ffc);

        let updated_contract_classes = match self.contract_classes {
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
            contract_states: updated_global_contract_root,
            contract_classes: updated_contract_classes,
            ffc: self.ffc,
            ffc_for_class_hash: self.ffc_for_class_hash,
            contract_addresses,
        })
    }

    async fn get_contract_state_async(&self, contract_address: ContractAddress) -> StateResult<ContractState> {
        let contract_address: TreeIndex = contract_address.0.key().to_biguint();

        let mut ffc = self.ffc.clone();

        let contract_states: HashMap<TreeIndex, ContractState> =
            self.contract_states.get_leaves(&mut ffc, &[contract_address.clone()], &mut None).await?;

        let contract_state = contract_states
            .get(&contract_address.clone())
            .ok_or(StateError::StateReadError(format!("{:?}", contract_address.clone())))?;

        if contract_state.contract_hash.clone().into_iter().fold(0u64, |acc, b| acc + b as u64) == 0 {
            log::debug!("found contract state with no contract hash!");
        }

        Ok(contract_state.clone())
    }

    /// helper to get contract_state
    pub fn get_contract_state(&self, contract_address: ContractAddress) -> StateResult<ContractState> {
        execute_coroutine(self.get_contract_state_async(contract_address))
            .map_err(|e| StateError::StateReadError(format!("Failed to execute contract state coroutine: {e}")))?
    }

    async fn get_compiled_class_hash_async(&self, class_hash: ClassHash) -> StateResult<CompiledClassHash> {
        let class_hash_as_index: TreeIndex = class_hash.0.to_biguint();

        log::debug!("class_hash_as_index: {:?}", class_hash_as_index);
        log::debug!("have contract_class_tree? {:?}", self.contract_classes.is_some());

        let compiled_class_hash = match &self.contract_classes {
            Some(contract_class_tree) => {
                let mut ffc_for_class_hash = self.ffc_for_class_hash.clone();

                log::debug!("Should get something from get_leaf()...");

                // TODO: `get_leaf()` should not return an option
                let contract_class_leaf =
                    <PatriciaTree as BinaryFactTree<S, PoseidonHash, ContractClassLeaf>>::get_leaf(
                        contract_class_tree,
                        &mut ffc_for_class_hash,
                        class_hash_as_index.clone(),
                    )
                    .await?
                    .ok_or(StateError::UndeclaredClassHash(class_hash))?;

                // Return an error if we get an empty leaf
                if <ContractClassLeaf as LeafFact<S, H>>::is_empty(&contract_class_leaf) {
                    return Err(StateError::UndeclaredClassHash(class_hash))?;
                }

                contract_class_leaf.compiled_class_hash
            }
            // The tree is not initialized; may happen if the reader is based on an old state
            // without class commitment.
            None => Felt252::ZERO,
        };

        Ok(CompiledClassHash(compiled_class_hash))
    }

    async fn get_deprecated_compiled_class(
        &self,
        compiled_class_hash: CompiledClassHash,
    ) -> Result<Option<GenericDeprecatedCompiledClass>, StorageError> {
        let storage = self.ffc.acquire_storage().await;

        DeprecatedCompiledClassFact::get(storage.deref(), &compiled_class_hash.0.to_bytes_be())
            .await
            .map(|option| option.map(|fact| fact.contract_definition))
    }

    async fn get_compiled_class(
        &self,
        compiled_class_hash: CompiledClassHash,
    ) -> Result<Option<GenericCasmContractClass>, StorageError> {
        let storage = self.ffc.acquire_storage().await;

        CompiledClassFact::get(storage.deref(), &compiled_class_hash.0.to_bytes_be())
            .await
            .map(|option| option.map(|fact| fact.compiled_class))
    }

    /// Returns the contract class of the given class hash.
    async fn get_compiled_contract_class_async(
        &self,
        compiled_class_hash: CompiledClassHash,
    ) -> StateResult<ContractClass> {
        log::debug!("SharedState as StateReader: get_compiled_contract_class {:?}", compiled_class_hash);

        // Try the deprecated compiled classes.
        let deprecated_compiled_class = self.get_deprecated_compiled_class(compiled_class_hash).await?;

        if let Some(deprecated_compiled_class) = deprecated_compiled_class {
            let blockifier_class = deprecated_compiled_class.to_blockifier_contract_class().unwrap();
            return Ok(blockifier_class.into());
        }

        // The given hash does not match any deprecated class; try the new compiled classes.
        let compiled_class = self.get_compiled_class(compiled_class_hash).await?;

        if let Some(compiled_class) = compiled_class {
            let blockifier_contract_class = compiled_class
                .to_blockifier_contract_class()
                .map_err(|e| StateError::StateReadError(format!("failed to convert to Blockifier CASM class: {e}")))?;
            return Ok(blockifier_contract_class.into());
        }

        Err(StateError::UndeclaredClassHash(ClassHash(compiled_class_hash.0)))
    }

    async fn get_storage_at_async(&self, contract_address: ContractAddress, key: StorageKey) -> StateResult<Felt252> {
        let storage_key: TreeIndex = key.0.key().to_biguint();

        let mut ffc = self.ffc.clone();

        let contract_state = self.get_contract_state_async(contract_address).await?;

        let storage_items: HashMap<TreeIndex, StorageLeaf> =
            contract_state.storage_commitment_tree.get_leaves(&mut ffc, &[storage_key.clone()], &mut None).await?;
        let state = storage_items
            .get(&storage_key)
            .ok_or(StateError::StateReadError(format!("get_storage_at_async: {:?}", storage_key)))?;

        Ok(state.value)
    }
}

impl<S, H> StateReader for SharedState<S, H>
where
    S: Storage + 'static,
    H: HashFunctionType + Send + Sync + 'static,
{
    /// Returns the storage value under the given key in the given contract instance (represented by
    /// its address).
    /// Default: 0 for an uninitialized contract address.
    fn get_storage_at(&self, contract_address: ContractAddress, key: StorageKey) -> StateResult<Felt252> {
        log::debug!("SharedState as StateReader: get_storage_at {:?} / {:?}", contract_address, key);
        let value = execute_coroutine(self.get_storage_at_async(contract_address, key)).unwrap(); // TODO: unwrap
        log::debug!("       -> {:?}", value);
        value
    }

    /// Returns the nonce of the given contract instance.
    /// Default: 0 for an uninitialized contract address.
    fn get_nonce_at(&self, contract_address: ContractAddress) -> StateResult<Nonce> {
        log::debug!("SharedState as StateReader: get_nonce_at {:?}", contract_address);
        let contract_state = self.get_contract_state(contract_address)?;
        let nonce = Nonce(contract_state.nonce);
        log::debug!("       -> {:?}", nonce);
        Ok(nonce)
    }

    /// Returns the class hash of the contract class at the given contract instance.
    /// Default: 0 (uninitialized class hash) for an uninitialized contract address.
    fn get_class_hash_at(&self, contract_address: ContractAddress) -> StateResult<ClassHash> {
        log::debug!("SharedState as StateReader: get_class_hash_at {:?}", contract_address);
        let contract_state = self.get_contract_state(contract_address)?;
        // TODO: this can be simplified once hashes are stored as [u8; 32]. Until then, this is fine.
        let felt = Felt252::from_bytes_be_slice(&contract_state.contract_hash);
        log::debug!("       -> {:?}", felt);
        Ok(ClassHash(felt))
    }

    /// Returns the contract class of the given class hash.
    fn get_compiled_contract_class(&self, class_hash: ClassHash) -> StateResult<ContractClass> {
        execute_coroutine(async {
            let compiled_class_hash = self.get_compiled_class_hash_async(class_hash).await?;
            self.get_compiled_contract_class_async(compiled_class_hash).await
        })
        .unwrap()
    }

    /// Returns the compiled class hash of the given class hash.
    fn get_compiled_class_hash(&self, class_hash: ClassHash) -> StateResult<CompiledClassHash> {
        log::debug!("SharedState as StateReader: get_compiled_class_hash {:?}", class_hash);
        execute_coroutine(self.get_compiled_class_hash_async(class_hash)).unwrap()
        // TODO: unwrap
    }
}

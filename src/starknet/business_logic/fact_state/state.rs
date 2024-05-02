use std::collections::{HashMap, HashSet};

use blockifier::execution::contract_class::ContractClass;
use blockifier::state::cached_state::CommitmentStateDiff;
use blockifier::state::errors::StateError;
use blockifier::state::state_api::{StateReader, StateResult};
use blockifier::test_utils::dict_state_reader::DictStateReader;
use cairo_vm::types::errors::math_errors::MathError;
use cairo_vm::Felt252;
use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce, PatriciaKey};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use crate::config::{
    StarknetGeneralConfig, COMPILED_CLASS_HASH_COMMITMENT_TREE_HEIGHT, CONTRACT_ADDRESS_BITS,
    CONTRACT_STATES_COMMITMENT_TREE_HEIGHT, GLOBAL_STATE_VERSION,
};
use crate::crypto::poseidon::poseidon_hash_many_bytes;
use crate::starknet::business_logic::fact_state::contract_class_objects::{
    get_ffc_for_contract_class_facts, ContractClassLeaf,
};
use crate::starknet::business_logic::fact_state::contract_state_objects::ContractState;
use crate::starknet::business_logic::state::state_api_objects::BlockInfo;
use crate::starknet::starknet_storage::{execute_coroutine_threadsafe, StorageLeaf};
use crate::starkware_utils::commitment_tree::base_types::{Height, TreeIndex};
use crate::starkware_utils::commitment_tree::binary_fact_tree::BinaryFactTree;
use crate::starkware_utils::commitment_tree::errors::TreeError;
use crate::starkware_utils::commitment_tree::patricia_tree::patricia_tree::PatriciaTree;
use crate::storage::storage::{FactFetchingContext, HashFunctionType, Storage};
use crate::utils::{felt_api2vm, felt_vm2api};

/// A class representing a combination of the onchain and offchain state.
pub struct SharedState<S, H>
where
    S: Storage + 'static,
    H: HashFunctionType + Send + Sync + 'static,
{
    contract_states: PatriciaTree,
    /// Leaf addresses are class hashes; leaf values contain compiled class hashes.
    contract_classes: Option<PatriciaTree>,
    block_info: BlockInfo,
    ffc: FactFetchingContext<S, H>,
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
    pub async fn empty(mut ffc: FactFetchingContext<S, H>, config: &StarknetGeneralConfig) -> Result<Self, TreeError> {
        let empty_contract_states = Self::create_empty_contract_states(&mut ffc).await?;
        let empty_contract_classes = Self::create_empty_contract_class_tree(&mut ffc).await?;

        Ok(Self {
            contract_states: empty_contract_states,
            contract_classes: Some(empty_contract_classes),
            block_info: BlockInfo::empty(Some(felt_api2vm(*config.sequencer_address.0.key())), config.use_kzg_da),
            ffc,
        })
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
    fn get_global_state_root(&self) -> Result<Felt252, MathError> {
        let contract_states_root = &self.contract_states.root;

        let empty_tree_root = vec![0u8; 32];
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
        blockifier_state: DictStateReader,
        block_info: BlockInfo,
        config: &StarknetGeneralConfig,
    ) -> Result<Self, TreeError> {
        let empty_state = Self::empty(ffc, config).await?;

        let mut storage_updates: HashMap<ContractAddress, HashMap<StorageKey, StarkFelt>> = HashMap::new();
        for ((address, key), value) in blockifier_state.storage_view {
            storage_updates.entry(address).or_default().insert(key, value);
        }

        let shared_state = empty_state
            .apply_state_updates_starknet_api(
                blockifier_state.address_to_class_hash,
                blockifier_state.address_to_nonce,
                blockifier_state.class_hash_to_compiled_class_hash,
                storage_updates,
                block_info,
            )
            .await?;

        Ok(shared_state)
    }

    /// Updates the global state using a state diff generated with Blockifier.
    async fn apply_commitment_state_diff(
        self,
        state_diff: CommitmentStateDiff,
        block_info: BlockInfo,
    ) -> Result<Self, TreeError> {
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
            block_info,
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
        block_info: BlockInfo,
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
            block_info,
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
        block_info: BlockInfo,
    ) -> Result<Self, TreeError> {
        let accessed_addresses_felts: HashSet<_> =
            address_to_class_hash.keys().chain(address_to_nonce.keys().chain(storage_updates.keys())).collect();
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
            let updates = storage_updates.get(&address).unwrap_or(&empty_updates);
            let nonce = address_to_nonce.get(&address).cloned();
            let class_hash = address_to_class_hash.get(&address).cloned();
            let updated_contract_state = current_contract_states
                .remove(&tree_index)
                .unwrap()
                .update(&mut self.ffc, updates, nonce, class_hash)
                .await?;

            updated_contract_states.insert(tree_index, updated_contract_state);
        }

        // Apply contract changes on global root.
        println!("Updating contract state tree with {} modifications...", accessed_addresses.len());
        let global_state_modifications: Vec<_> = updated_contract_states.into_iter().map(|(k, v)| (k, v)).collect();
        let updated_global_contract_root =
            self.contract_states.update(&mut self.ffc, global_state_modifications, &mut facts).await?;

        let mut ffc_for_contract_class = get_ffc_for_contract_class_facts(&mut self.ffc);

        let updated_contract_classes = match self.contract_classes {
            Some(mut tree) => {
                println!(
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

        Ok(Self {
            contract_states: updated_global_contract_root,
            contract_classes: updated_contract_classes,
            block_info,
            ffc: self.ffc,
        })
    }

    async fn get_contract_state_async(&self, contract_address: ContractAddress) -> StateResult<ContractState> {
        let contract_address: TreeIndex = felt_api2vm(*contract_address.0.key()).to_biguint();

        let mut ffc = self.ffc.clone();

        let contract_states: HashMap<TreeIndex, ContractState> =
            self.contract_states.get_leaves(&mut ffc, &[contract_address.clone()], &mut None).await?;

        let contract_state = contract_states
            .get(&contract_address.clone())
            .ok_or(StateError::StateReadError(format!("{:?}", contract_address.clone())))?;

        Ok(contract_state.clone())
    }

    /// helper to get contract_state
    pub fn get_contract_state(&self, contract_address: ContractAddress) -> StateResult<ContractState> {
        execute_coroutine_threadsafe(self.get_contract_state_async(contract_address))
    }

    /// helper to get contract_state
    pub fn get_contract_class(&self, contract_address: ContractAddress) -> StateResult<ContractClassLeaf> {
        let contract_address: TreeIndex = felt_api2vm(*contract_address.0.key()).to_biguint();

        if self.contract_classes.is_none() {
            return Err(StateError::StateReadError(format!("{:?}", contract_address.clone())));
        }

        let mut ffc = self.ffc.clone();

        let contract_class = execute_coroutine_threadsafe(async {
            let contract_classes: HashMap<TreeIndex, ContractClassLeaf> = self
                .contract_classes
                .as_ref()
                .unwrap()
                .get_leaves(&mut ffc, &[contract_address.clone()], &mut None)
                .await
                .unwrap(); // TODO: error
            let contract_class = contract_classes
                .get(&contract_address.clone())
                .ok_or(StateError::StateReadError(format!("{:?}", contract_address.clone())))?
                .clone();
            StateResult::Ok(contract_class)
        })?;

        Ok(contract_class)
    }

    async fn get_storage_at_async(
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> StateResult<StarkFelt> {
        let storage_key: TreeIndex = felt_api2vm(*key.0.key()).to_biguint();

        let contract_state = self.get_contract_state(contract_address)?;

        let storage_items: HashMap<TreeIndex, StorageLeaf> =
            contract_state.storage_commitment_tree.get_leaves(&mut self.ffc, &[storage_key.clone()], &mut None).await?;
        let state =
            storage_items.get(&storage_key.clone()).ok_or(StateError::StateReadError(format!("{:?}", storage_key)))?;

        Ok(felt_vm2api(state.value))
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
    fn get_storage_at(&mut self, contract_address: ContractAddress, key: StorageKey) -> StateResult<StarkFelt> {
        execute_coroutine_threadsafe(self.get_storage_at_async(contract_address, key))
    }

    /// Returns the nonce of the given contract instance.
    /// Default: 0 for an uninitialized contract address.
    fn get_nonce_at(&mut self, contract_address: ContractAddress) -> StateResult<Nonce> {
        let contract_state = self.get_contract_state(contract_address)?;
        Ok(Nonce(felt_vm2api(contract_state.nonce)))
    }

    /// Returns the class hash of the contract class at the given contract instance.
    /// Default: 0 (uninitialized class hash) for an uninitialized contract address.
    fn get_class_hash_at(&mut self, contract_address: ContractAddress) -> StateResult<ClassHash> {
        let contract_state = self.get_contract_state(contract_address)?;
        Ok(ClassHash(felt_vm2api(contract_state.nonce)))
    }

    /// Returns the contract class of the given class hash.
    fn get_compiled_contract_class(&mut self, class_hash: ClassHash) -> StateResult<ContractClass> {
        let contract_address = ContractAddress(PatriciaKey::try_from(class_hash.0).unwrap());
        let leaf = self.get_contract_class(contract_address)?;
        // TODO: convert ContractClassLeaf -> ContractClass
        // TODO: how can we know whether v0 or v1 here?
        unimplemented!();
    }

    /// Returns the compiled class hash of the given class hash.
    fn get_compiled_class_hash(&mut self, class_hash: ClassHash) -> StateResult<CompiledClassHash> {
        let contract_address = ContractAddress(PatriciaKey::try_from(class_hash.0).unwrap());
        let leaf = self.get_contract_class(contract_address)?;
        let hash = felt_vm2api(leaf.compiled_class_hash);
        Ok(CompiledClassHash(hash))
    }

    // TODO: do we care about `fn get_free_token_balance()`?
}

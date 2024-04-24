use cairo_lang_starknet::casm_contract_class::CasmContractClass;
use cairo_lang_starknet::contract_class::ContractClass;
use cairo_vm::Felt252;
use pathfinder_gateway_types::class_hash::compute_class_hash;
use serde::{Deserialize, Serialize};
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedCompiledClass;

use crate::config::CONTRACT_CLASS_LEAF_VERSION;
use crate::crypto::poseidon::PoseidonHash;
use crate::starkware_utils::commitment_tree::leaf_fact::LeafFact;
use crate::starkware_utils::commitment_tree::patricia_tree::patricia_tree::EMPTY_NODE_HASH;
use crate::starkware_utils::serializable::SerializationPrefix;
use crate::storage::storage::{DbObject, Fact, FactFetchingContext, HashFunctionType, Storage};

/// Represents a single contract class which is stored in the Starknet state.
#[derive(Debug, Serialize, Deserialize)]
pub struct ContractClassFact {
    pub contract_class: ContractClass,
}

impl SerializationPrefix for ContractClassFact {}

impl DbObject for ContractClassFact {}
impl<S, H> Fact<S, H> for ContractClassFact
where
    S: Storage,
    H: HashFunctionType,
{
    fn hash(&self) -> Vec<u8> {
        // Dump the contract definition to JSON and let Pathfinder hashing code decide
        // what to do with it.

        // Panicking is okay-ish here, for now this code is test-only.
        let contract_dump = serde_json::to_vec(&self.contract_class).expect("JSON serialization failed unexpectedly.");
        let computed_class_hash =
            compute_class_hash(&contract_dump).unwrap_or_else(|e| panic!("Failed to compute class hash: {}", e));

        computed_class_hash.hash().0.to_be_bytes().to_vec()
    }
}

/// Represents a single compiled contract class which is stored in the Starknet state.
#[derive(Debug, Serialize, Deserialize)]
pub struct CompiledClassFact {
    pub compiled_class: CasmContractClass,
}

impl SerializationPrefix for CompiledClassFact {}

impl DbObject for CompiledClassFact {}
impl<S, H> Fact<S, H> for CompiledClassFact
where
    S: Storage,
    H: HashFunctionType,
{
    fn hash(&self) -> Vec<u8> {
        self.compiled_class.compiled_class_hash().to_be_bytes().to_vec()
    }
}

/// Represents a single deprecated compiled contract class which is stored in the Starknet state.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeprecatedCompiledClassFact {
    pub contract_definition: DeprecatedCompiledClass,
}

const DEPRECATED_COMPILED_CLASS_PREFIX: &[u8] = "contract_definition_fact".as_bytes();

impl SerializationPrefix for DeprecatedCompiledClassFact {
    fn prefix() -> Vec<u8> {
        DEPRECATED_COMPILED_CLASS_PREFIX.to_vec()
    }
}

impl DbObject for DeprecatedCompiledClassFact {}
impl<S, H> Fact<S, H> for DeprecatedCompiledClassFact
where
    S: Storage,
    H: HashFunctionType,
{
    fn hash(&self) -> Vec<u8> {
        // Dump the contract definition to JSON and let Pathfinder hashing code decide
        // what to do with it.

        // Panicking is okay-ish here, for now this code is test-only.
        let contract_dump =
            serde_json::to_vec(&self.contract_definition).expect("JSON serialization failed unexpectedly.");
        let computed_class_hash =
            compute_class_hash(&contract_dump).unwrap_or_else(|e| panic!("Failed to compute class hash: {}", e));

        computed_class_hash.hash().0.to_be_bytes().to_vec()
    }
}

/// Represents a leaf in the Starknet contract class tree.
#[derive(Deserialize, Clone, Debug, Serialize, PartialEq)]
pub struct ContractClassLeaf {
    compiled_class_hash: Felt252,
}

impl SerializationPrefix for ContractClassLeaf {}

impl ContractClassLeaf {
    pub fn create(compiled_class_hash: Felt252) -> Self {
        Self { compiled_class_hash }
    }

    pub fn empty() -> Self {
        Self { compiled_class_hash: Felt252::ZERO }
    }
}

impl<S, H> Fact<S, H> for ContractClassLeaf
where
    H: HashFunctionType,
    S: Storage,
{
    /// Computes the hash of the contract class leaf.
    fn hash(&self) -> Vec<u8> {
        if <ContractClassLeaf as LeafFact<S, H>>::is_empty(self) {
            return EMPTY_NODE_HASH.to_vec();
        }

        // Return H(CONTRACT_CLASS_LEAF_VERSION, compiled_class_hash).
        H::hash(CONTRACT_CLASS_LEAF_VERSION, &self.compiled_class_hash.to_bytes_be())
    }
}

impl DbObject for ContractClassLeaf {}

impl<S, H> LeafFact<S, H> for ContractClassLeaf
where
    H: HashFunctionType,
    S: Storage,
{
    fn is_empty(&self) -> bool {
        self.compiled_class_hash == Felt252::ZERO
    }
}

/// Replaces the given FactFetchingContext object with a corresponding one used for·
/// fetching contract class facts.
pub fn get_ffc_for_contract_class_facts<S, H>(
    ffc: &mut FactFetchingContext<S, H>,
) -> FactFetchingContext<S, PoseidonHash>
where
    S: Storage,
    H: HashFunctionType,
{
    ffc.clone_with_different_hash::<PoseidonHash>()
}

// def get_ffc_for_contract_class_facts(ffc: FactFetchingContext) -> FactFetchingContext:
// """
//     Replaces the given FactFetchingContext object with a corresponding one used for·
//     fetching contract class facts.
//     """
// return FactFetchingContext(
// storage=ffc.storage, hash_func=poseidon_hash_func, n_workers=ffc.n_workers
// )

use cairo_lang_starknet::casm_contract_class::CasmContractClass;
use cairo_lang_starknet::contract_class::ContractClass;
use pathfinder_gateway_types::class_hash::compute_class_hash;
use serde::{Deserialize, Serialize};
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedCompiledClass;

use crate::starkware_utils::serializable::SerializationPrefix;
use crate::storage::storage::{DbObject, Fact, HashFunctionType, Storage};

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
        self.compiled_class.compiled_class_hash().to_bytes_be()
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

use pathfinder_gateway_types::class_hash::compute_class_hash;
use serde::{Deserialize, Serialize};
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedCompiledClass;

use crate::storage::storage::{DbObject, Fact, HashFunctionType, Storage};

/// Represents a single deprecated compiled contract class which is stored in the Starknet state.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeprecatedCompiledClassFact {
    contract_definition: DeprecatedCompiledClass,
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

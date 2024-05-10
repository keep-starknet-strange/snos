use serde::{Deserialize, Serialize};
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedCompiledClass;
use crate::starknet::business_logic::fact_state::deprecated_class_hash::calculate_deprecated_class_hash;

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
        let hash = calculate_deprecated_class_hash(&self.contract_definition).0.bytes().into();
        println!("Calculated hash class for this DbObject: {:?}", hash);
        hash
    }
}


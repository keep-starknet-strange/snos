use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use sha3::Digest as _;
use starknet_api::{core::ClassHash, deprecated_contract_class::ContractClass as DeprecatedCompiledClass, hash::{pedersen_hash_array, poseidon_hash_array, StarkFelt}, deprecated_contract_class::EntryPointType};
use starknet_crypto::FieldElement;
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
        calculate_deprecated_class_hash(&self.contract_definition).0.bytes().into()
    }
}


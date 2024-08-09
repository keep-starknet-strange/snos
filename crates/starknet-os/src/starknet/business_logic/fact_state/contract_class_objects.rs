use cairo_lang_starknet_classes::contract_class::{ContractClass, ContractEntryPoints};
use cairo_vm::Felt252;
use pathfinder_gateway_types::class_hash::compute_class_hash;
use serde::{Deserialize, Serialize};
use starknet_os_types::casm_contract_class::GenericCasmContractClass;
use starknet_os_types::deprecated_compiled_class::GenericDeprecatedCompiledClass;
use starknet_os_types::hash::Hash;
use starknet_os_types::sierra_contract_class::GenericSierraContractClass;

use crate::config::CONTRACT_CLASS_LEAF_VERSION;
use crate::crypto::poseidon::PoseidonHash;
use crate::starkware_utils::commitment_tree::leaf_fact::LeafFact;
use crate::starkware_utils::serializable::SerializationPrefix;
use crate::storage::storage::{DbObject, Fact, FactFetchingContext, HashFunctionType, Storage};

/// Represents a single contract class which is stored in the Starknet state.
#[derive(Debug, Serialize, Deserialize)]
pub struct ContractClassFact {
    pub contract_class: GenericSierraContractClass,
}

impl SerializationPrefix for ContractClassFact {}

impl DbObject for ContractClassFact {}
impl<S, H> Fact<S, H> for ContractClassFact
where
    S: Storage,
    H: HashFunctionType,
{
    fn hash(&self) -> Hash {
        *self.contract_class.class_hash().expect("hash() is infallible")
    }
}

/// Represents a single compiled contract class which is stored in the Starknet state.
#[derive(Debug, Serialize, Deserialize)]
pub struct CompiledClassFact {
    pub compiled_class: GenericCasmContractClass,
}

impl SerializationPrefix for CompiledClassFact {}

impl DbObject for CompiledClassFact {}
impl<S, H> Fact<S, H> for CompiledClassFact
where
    S: Storage,
    H: HashFunctionType,
{
    fn hash(&self) -> Hash {
        let class_hash = self.compiled_class.class_hash().expect("failed to compute CASM class hash");
        *class_hash
    }
}

/// Represents a single deprecated compiled contract class which is stored in the Starknet state.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeprecatedCompiledClassFact {
    pub contract_definition: GenericDeprecatedCompiledClass,
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
    fn hash(&self) -> Hash {
        // Dump the contract definition to JSON and let Pathfinder hashing code decide
        // what to do with it.

        // Panicking is okay-ish here, for now this code is test-only.
        let contract_dump =
            serde_json::to_vec(&self.contract_definition).expect("JSON serialization failed unexpectedly.");
        let computed_class_hash =
            compute_class_hash(&contract_dump).unwrap_or_else(|e| panic!("Failed to compute class hash: {}", e));

        Hash::from_bytes_be(computed_class_hash.hash().0.to_be_bytes())
    }
}

/// Represents a leaf in the Starknet contract class tree.
#[derive(Deserialize, Clone, Debug, Serialize, PartialEq)]
pub struct ContractClassLeaf {
    pub compiled_class_hash: Felt252,
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
    fn hash(&self) -> Hash {
        if <ContractClassLeaf as LeafFact<S, H>>::is_empty(self) {
            return Hash::empty();
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
pub fn get_ffc_for_contract_class_facts<S, H>(ffc: &FactFetchingContext<S, H>) -> FactFetchingContext<S, PoseidonHash>
where
    S: Storage,
    H: HashFunctionType,
{
    ffc.clone_with_different_hash::<PoseidonHash>()
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;

    use rstest::rstest;
    use starknet_os_types::casm_contract_class::GenericCasmContractClass;

    use crate::crypto::pedersen::PedersenHash;
    use crate::starknet::business_logic::fact_state::contract_class_objects::CompiledClassFact;
    use crate::storage::dict_storage::DictStorage;
    use crate::storage::storage::{DbObject, Fact, FactFetchingContext};

    #[rstest]
    #[tokio::test]
    /// Sanity check to test that serializing/deserializing compiled class facts to storage works.
    async fn serialize_and_deserialize_compiled_class_fact() {
        let mut ffc: FactFetchingContext<DictStorage, PedersenHash> = FactFetchingContext::new(DictStorage::default());

        let casm_bytes = include_bytes!(
            "../../../../../../tests/integration/contracts/blockifier_contracts/feature_contracts/cairo1/compiled/\
             test_contract.casm.json"
        );
        let compiled_class = GenericCasmContractClass::from_bytes(casm_bytes.to_vec());

        let fact = CompiledClassFact { compiled_class };

        let fact_hash = fact.set_fact(&mut ffc).await.unwrap();

        let storage = ffc.acquire_storage().await;
        let deserialized_fact = CompiledClassFact::get(storage.deref(), &fact_hash).await.unwrap();
        assert!(deserialized_fact.is_some());
    }
}

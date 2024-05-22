use std::borrow::Cow;
use std::collections::HashMap;

use cairo_lang_starknet::casm_contract_class::CasmContractClass;
use cairo_lang_starknet::contract_class::{ContractClass, ContractEntryPoint};
use cairo_vm::Felt252;
use num_bigint::BigUint;
use pathfinder_gateway_types::class_hash::{compute_class_hash, compute_sierra_class_hash};
use pathfinder_gateway_types::class_hash::json::SierraContractDefinition;
use pathfinder_gateway_types::request::contract::{EntryPointType, SelectorAndFunctionIndex};
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

        fn felt_buint2pf(i: &BigUint) -> pathfinder_crypto::Felt {
            pathfinder_crypto::Felt::from_be_slice(&i.to_bytes_be()[..]).unwrap()
        }

        fn convert_entry_points(entry_points: &Vec<ContractEntryPoint>) -> Vec<SelectorAndFunctionIndex> {
            entry_points.into_iter().map(|ep| {
                SelectorAndFunctionIndex {
                    selector: pathfinder_common::EntryPoint(felt_buint2pf(&ep.selector)),
                    function_idx: ep.function_idx.try_into().unwrap()
                }
            }).collect()
        }

        let mut entry_points_map = HashMap::new();
        entry_points_map.insert(EntryPointType::External, convert_entry_points(&self.contract_class.entry_points_by_type.external));
        entry_points_map.insert(EntryPointType::L1Handler, convert_entry_points(&self.contract_class.entry_points_by_type.l1_handler));
        entry_points_map.insert(EntryPointType::Constructor, convert_entry_points(&self.contract_class.entry_points_by_type.constructor));

        let sierra_contract_definition = SierraContractDefinition {
            abi: Default::default(),
            sierra_program: self.contract_class.sierra_program.clone().into_iter().map(|b| felt_buint2pf(&b.value)).collect(),
            contract_class_version: Cow::Borrowed(self.contract_class.contract_class_version.as_str()),
            entry_points_by_type: entry_points_map,
        };

        /*
        // Panicking is okay-ish here, for now this code is test-only.
        // let contract_dump = serde_json::to_vec(&self.contract_class).expect("JSON serialization failed unexpectedly.");
        let contract_dump = serde_json::to_vec(&sierra_contract_definition).expect("JSON serialization failed unexpectedly.");
        let computed_class_hash =
            compute_class_hash(&contract_dump).unwrap_or_else(|e| panic!("Failed to compute class hash: {}", e));
        */

        let computed_class_hash =
            compute_sierra_class_hash(sierra_contract_definition).unwrap_or_else(|e| panic!("Failed to compute class hash: {}", e));

        computed_class_hash.0.to_be_bytes().to_vec()
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
pub fn get_ffc_for_contract_class_facts<S, H>(ffc: &FactFetchingContext<S, H>) -> FactFetchingContext<S, PoseidonHash>
where
    S: Storage,
    H: HashFunctionType,
{
    ffc.clone_with_different_hash::<PoseidonHash>()
}

use std::collections::HashMap;
use std::io::Write;
use std::{fs, path};

use cairo_vm::Felt252;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use starknet_os_types::casm_contract_class::GenericCasmContractClass;
use starknet_os_types::deprecated_compiled_class::GenericDeprecatedCompiledClass;

use super::InternalTransaction;
use crate::config::StarknetGeneralConfig;
use crate::error::SnOsError;
use crate::starknet::business_logic::fact_state::contract_state_objects::ContractState;
use crate::starknet::starknet_storage::CommitmentInfo;
use crate::utils::Felt252HexNoPrefix;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StarknetOsInput {
    pub contract_state_commitment_info: CommitmentInfo,
    pub contract_class_commitment_info: CommitmentInfo,
    pub deprecated_compiled_classes: HashMap<Felt252, GenericDeprecatedCompiledClass>,
    pub compiled_classes: HashMap<Felt252, GenericCasmContractClass>,
    pub compiled_class_visited_pcs: HashMap<Felt252, Vec<Felt252>>,
    pub contracts: HashMap<Felt252, ContractState>,
    pub class_hash_to_compiled_class_hash: HashMap<Felt252, Felt252>,
    pub general_config: StarknetGeneralConfig,
    pub transactions: Vec<InternalTransaction>,
    /// A mapping from Cairo 1 declared class hashes to the hashes of the contract class components.
    pub declared_class_hash_to_component_hashes: HashMap<Felt252, Vec<Felt252>>,
    pub new_block_hash: Felt252,
    pub prev_block_hash: Felt252,
    pub full_output: bool,
}

impl StarknetOsInput {
    pub fn load(path: &path::Path) -> Result<Self, SnOsError> {
        let raw_input = fs::read_to_string(path)?;
        let input = serde_json::from_str(&raw_input)?;

        Ok(input)
    }

    pub fn dump(&self, path: &path::Path) -> Result<(), SnOsError> {
        fs::File::create(path)?.write_all(&serde_json::to_vec(&self)?)?;

        Ok(())
    }
}

#[serde_as]
#[derive(Deserialize, Clone, Default, Debug, Serialize, PartialEq)]
pub struct StorageCommitment {
    #[serde_as(as = "Felt252HexNoPrefix")]
    pub root: Felt252,
    pub height: usize,
}

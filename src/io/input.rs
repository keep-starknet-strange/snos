use std::collections::HashMap;
use std::io::Write;
use std::{fs, path};

use cairo_vm::Felt252;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedContractClass;

use super::InternalTransaction;
use crate::config::StarknetGeneralConfig;
use crate::error::SnOsError;
use crate::state::trie::{MerkleTrie, StarkHasher};
use crate::utils::{Felt252HexNoPrefix, Felt252Num, Felt252Str, Felt252StrDec};

#[serde_as]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StarknetOsInput {
    pub contract_state_commitment_info: CommitmentInfo,
    pub contract_class_commitment_info: CommitmentInfo,
    #[serde_as(as = "HashMap<Felt252Str, _>")]
    pub deprecated_compiled_classes: HashMap<Felt252, DeprecatedContractClass>,
    #[serde_as(as = "HashMap<Felt252Str, Felt252Str>")]
    pub compiled_classes: HashMap<Felt252, Felt252>,
    #[serde_as(as = "HashMap<Felt252StrDec, _>")]
    pub contracts: HashMap<Felt252, ContractState>,
    #[serde_as(as = "HashMap<Felt252Str, Felt252Str>")]
    pub class_hash_to_compiled_class_hash: HashMap<Felt252, Felt252>,
    pub general_config: StarknetGeneralConfig,
    pub transactions: Vec<InternalTransaction>,
    #[serde_as(as = "Felt252Num")]
    pub block_hash: Felt252,
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
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct CommitmentInfo {
    #[serde_as(as = "Felt252Num")]
    pub previous_root: Felt252,
    #[serde_as(as = "Felt252Num")]
    pub updated_root: Felt252,
    pub tree_height: usize,
    #[serde_as(as = "HashMap<Felt252Str, Vec<Felt252Str>>")]
    pub commitment_facts: HashMap<Felt252, Vec<Felt252>>,
}
impl CommitmentInfo {
    pub fn create_from_modifications<H>(_previous_tree: MerkleTrie<H, 64>) -> Self
    where
        H: StarkHasher,
    {
        CommitmentInfo::default()
    }
}
#[serde_as]
#[derive(Deserialize, Clone, Debug, Serialize)]
pub struct ContractState {
    #[serde_as(as = "Felt252HexNoPrefix")]
    pub contract_hash: Felt252,
    pub storage_commitment_tree: StorageCommitment,
    #[serde_as(as = "Felt252Str")]
    pub nonce: Felt252,
}

#[serde_as]
#[derive(Deserialize, Clone, Debug, Serialize)]
pub struct StorageCommitment {
    #[serde_as(as = "Felt252HexNoPrefix")]
    pub root: Felt252,
    pub height: usize,
}

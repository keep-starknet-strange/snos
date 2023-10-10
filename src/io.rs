use std::collections::HashMap;

use cairo_felt::Felt252;
use serde::{Deserialize, Serialize};

use cairo_vm::serde::deserialize_program::deserialize_felt_hex;
use num_traits::Num;
use serde::Deserializer;
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedContractClass;
use starknet_api::transaction::{MessageToL1, MessageToL2};
use std::fs;
use std::path;

use crate::config::StarknetGeneralConfig;

type CommitmentFacts = HashMap<Felt252, Vec<Felt252>>;

#[derive(Debug, Serialize, Deserialize)]
#[allow(unused)]
pub struct StarknetOsInput {
    contract_state_commitment_info: CommitmentInfo,
    contract_class_commitment_info: CommitmentInfo,
    #[serde(deserialize_with = "parse_deprecated_classes")]
    deprecated_compiled_classes: HashMap<Felt252, DeprecatedContractClass>, // TODO: Add contract_class module
    #[serde(deserialize_with = "deserialize_felt_map")]
    compiled_classes: HashMap<Felt252, Felt252>, // TODO: Add contract_class module
    // contracts: HashMap<Felt252, ContractState>,
    #[serde(deserialize_with = "deserialize_felt_map")]
    class_hash_to_compiled_class_hash: HashMap<Felt252, Felt252>,
    general_config: StarknetGeneralConfig,
    // transactions: Vec<InternalTransaction>,
    #[serde(deserialize_with = "deserialize_felt_hex")]
    block_hash: Felt252,
}
impl StarknetOsInput {
    pub fn compiled_classes(&self) -> &HashMap<Felt252, Felt252> {
        &self.compiled_classes
    }
}

impl StarknetOsInput {
    pub fn load(path: &str) -> Self {
        let raw_input = fs::read_to_string(path::PathBuf::from(path)).unwrap();
        serde_json::from_str(&raw_input).unwrap()
    }
}

pub struct StarknetOsOutput {
    /// The state commitment before this block.
    pub prev_state_root: Felt252,
    /// The state commitment after this block.
    pub new_state_root: Felt252,
    /// The number (height) of this block.
    pub block_number: Felt252,
    /// The hash of this block.
    pub block_hash: Felt252,
    /// The Starknet chain config hash
    pub config_hash: Felt252,
    /// List of messages sent to L1 in this block
    pub messages_to_l1: Vec<MessageToL1>,
    /// List of messages from L1 handled in this block
    pub messages_to_l2: Vec<MessageToL2>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CommitmentInfo {
    #[serde(deserialize_with = "deserialize_felt_hex")]
    pub previous_root: Felt252,
    #[serde(deserialize_with = "deserialize_felt_hex")]
    pub updated_root: Felt252,
    pub(crate) tree_height: usize,
    #[serde(deserialize_with = "deserialize_felt_facts")]
    pub(crate) commitment_facts: CommitmentFacts,
}

pub fn deserialize_felt_facts<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<CommitmentFacts, D::Error> {
    let mut ret_map = CommitmentFacts::new();
    let buf_map: HashMap<String, Vec<String>> = HashMap::deserialize(deserializer)?;
    for (fact, commitments) in buf_map.into_iter() {
        let fact = fact.strip_prefix("0x").unwrap();
        ret_map.insert(
            Felt252::from_str_radix(fact, 16).unwrap(),
            commitments
                .into_iter()
                .map(|commit| {
                    Felt252::from_str_radix(commit.strip_prefix("0x").unwrap(), 16).unwrap()
                })
                .collect(),
        );
    }

    Ok(ret_map)
}

pub fn parse_deprecated_classes<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<HashMap<Felt252, DeprecatedContractClass>, D::Error> {
    let mut ret_map: HashMap<Felt252, DeprecatedContractClass> = HashMap::new();
    let buf: HashMap<String, String> = HashMap::deserialize(deserializer)?;
    for (k, v) in buf.into_iter() {
        let class_hash = Felt252::from_str_radix(k.strip_prefix("0x").unwrap(), 16).unwrap();
        let raw_class = fs::read_to_string(path::PathBuf::from(v)).unwrap();
        let class = serde_json::from_str(&raw_class).unwrap();
        ret_map.insert(class_hash, class);
    }

    Ok(ret_map)
}

pub fn deserialize_felt_map<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<HashMap<Felt252, Felt252>, D::Error> {
    let mut ret_map = HashMap::new();
    let buf_map: HashMap<String, String> = HashMap::deserialize(deserializer)?;
    for (k, v) in buf_map.into_iter() {
        let k = k.strip_prefix("0x").unwrap();
        let v = v.strip_prefix("0x").unwrap();
        ret_map.insert(
            Felt252::from_str_radix(k, 16).unwrap(),
            Felt252::from_str_radix(v, 16).unwrap(),
        );
    }

    Ok(ret_map)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const TESTING_BLOCK_HASH: &str =
        "59b01ba262c999f2617412ffbba780f80b0103d928cbce1aecbaa50de90abda";

    #[test]
    fn parse_os_input() {
        let input = StarknetOsInput::load("tests/common/os_input.json");
        assert_eq!(
            Felt252::from_str_radix(TESTING_BLOCK_HASH, 16).unwrap(),
            input.block_hash
        );
        assert_eq!(
            Felt252::from_str_radix(
                "473010ec333f16b84334f9924912d7a13ce8296b0809c2091563ddfb63011d",
                16
            )
            .unwrap(),
            input.contract_state_commitment_info.previous_root
        );
        assert_eq!(
            Felt252::from_str_radix(
                "482c9ce8a99afddc9777ff048520fcbfab6c0389f51584016c80a2e94ab8ca7",
                16
            )
            .unwrap(),
            input.contract_state_commitment_info.updated_root
        );
    }
}

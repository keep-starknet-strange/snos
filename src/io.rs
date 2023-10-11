use std::collections::HashMap;

use cairo_felt::Felt252;
use serde::Deserialize;
use serde_with::serde_as;
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedContractClass;
use starknet_api::transaction::{MessageToL1, MessageToL2};
use std::fs;
use std::path;

use crate::config::StarknetGeneralConfig;
use crate::utils::{parse_deprecated_classes, Felt252Num, Felt252Str};

#[serde_as]
#[derive(Debug, Deserialize)]
pub struct StarknetOsInput {
    pub contract_state_commitment_info: CommitmentInfo,
    pub contract_class_commitment_info: CommitmentInfo,
    #[serde(deserialize_with = "parse_deprecated_classes")]
    pub deprecated_compiled_classes: HashMap<Felt252, DeprecatedContractClass>,
    #[serde_as(as = "HashMap<Felt252Str, Felt252Str>")]
    pub compiled_classes: HashMap<Felt252, Felt252>,
    #[serde_as(as = "HashMap<Felt252Str, _>")]
    pub contracts: HashMap<Felt252, ContractState>,
    #[serde_as(as = "HashMap<Felt252Str, Felt252Str>")]
    pub class_hash_to_compiled_class_hash: HashMap<Felt252, Felt252>,
    pub general_config: StarknetGeneralConfig,
    pub transactions: Vec<InternalTransaction>,
    #[serde_as(as = "Felt252Num")]
    pub block_hash: Felt252,
}

#[serde_as]
#[derive(Debug, Default, Deserialize)]
pub struct CommitmentInfo {
    #[serde_as(as = "Felt252Num")]
    pub previous_root: Felt252,
    #[serde_as(as = "Felt252Num")]
    pub updated_root: Felt252,
    pub tree_height: usize,
    #[serde_as(as = "HashMap<Felt252Str, Vec<Felt252Str>>")]
    pub commitment_facts: HashMap<Felt252, Vec<Felt252>>,
}
#[serde_as]
#[derive(Deserialize, Debug)]
pub struct ContractState {
    #[serde_as(as = "Felt252Str")]
    pub contract_hash: Felt252,
    pub storage_commitment_tree: StorageCommitment,
    #[serde_as(as = "Felt252Str")]
    pub nonce: Felt252,
}

#[serde_as]
#[derive(Deserialize, Debug)]
pub struct StorageCommitment {
    #[serde_as(as = "Felt252Str")]
    pub root: Felt252,
    pub height: usize,
}

#[serde_as]
#[derive(Deserialize, Debug)]
pub struct InternalTransaction {
    #[serde_as(as = "Felt252Str")]
    pub hash_value: Felt252,
    #[serde_as(as = "Option<Felt252Str>")]
    pub version: Option<Felt252>,
    #[serde_as(as = "Option<Felt252Str>")]
    pub contract_address: Option<Felt252>,
    #[serde_as(as = "Option<Felt252Str>")]
    pub contract_address_salt: Option<Felt252>,
    #[serde_as(as = "Option<Vec<Felt252Str>>")]
    pub constructor_calldata: Option<Vec<Felt252>>,
    #[serde_as(as = "Option<Felt252Str>")]
    pub nonce: Option<Felt252>,
    #[serde_as(as = "Option<Felt252Str>")]
    pub sender_address: Option<Felt252>,
    #[serde_as(as = "Option<Felt252Str>")]
    pub entry_point_selector: Option<Felt252>,
    pub entry_point_type: Option<String>,
    #[serde_as(as = "Option<Vec<Felt252Str>>")]
    pub signature: Option<Vec<Felt252>>,
    #[serde_as(as = "Option<Felt252Str>")]
    pub class_hash: Option<Felt252>,
    #[serde_as(as = "Option<Vec<Felt252Str>>")]
    pub calldata: Option<Vec<Felt252>>,
    pub paid_on_l1: Option<bool>,
    pub r#type: String,
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

#[cfg(test)]
mod tests {
    use super::*;

    use cairo_felt::{felt_str, Felt252};

    pub const TESTING_BLOCK_HASH: &str =
        "59b01ba262c999f2617412ffbba780f80b0103d928cbce1aecbaa50de90abda";
    pub const EXPECTED_PREV_ROOT: &str =
        "473010ec333f16b84334f9924912d7a13ce8296b0809c2091563ddfb63011d";
    pub const EXPECTED_UPDATED_ROOT: &str =
        "482c9ce8a99afddc9777ff048520fcbfab6c0389f51584016c80a2e94ab8ca7";

    #[test]
    fn parse_os_input() {
        let input = StarknetOsInput::load("tests/common/os_input.json");
        assert_eq!(felt_str!(TESTING_BLOCK_HASH, 16), input.block_hash);
        assert_eq!(
            felt_str!(EXPECTED_PREV_ROOT, 16),
            input.contract_state_commitment_info.previous_root
        );
        assert_eq!(
            felt_str!(EXPECTED_UPDATED_ROOT, 16),
            input.contract_state_commitment_info.updated_root
        );
        assert!(input.contracts.get(&Felt252::from(0)).is_some());
        assert!(input.transactions.len() > 0);
    }
}

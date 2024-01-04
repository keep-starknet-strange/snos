use std::collections::HashMap;
use std::fs;
use std::io::Write;

use cairo_vm::felt::Felt252;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{serde_as, DeserializeAs, SerializeAs};
use snos::config::StarknetGeneralConfig;
use snos::error::SnOsError;
use snos::io::input::{CommitmentInfo, ContractState};
use snos::io::InternalTransaction;
use snos::utils::{Felt252Num, Felt252Str, Felt252StrDec};
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedContractClass;

pub struct DeprecatedContractClassStr;

impl<'de> DeserializeAs<'de, DeprecatedContractClass> for DeprecatedContractClassStr {
    fn deserialize_as<D>(deserializer: D) -> Result<DeprecatedContractClass, D::Error>
    where
        D: Deserializer<'de>,
    {
        let deprecated_class = String::deserialize(deserializer)?;
        let raw_class = fs::read_to_string(deprecated_class.trim_start_matches("0x")).map_err(de::Error::custom)?;

        serde_json::from_str(&raw_class).map_err(de::Error::custom)
    }
}

impl SerializeAs<DeprecatedContractClass> for DeprecatedContractClassStr {
    fn serialize_as<S>(deprecated_class: &DeprecatedContractClass, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        deprecated_class.serialize(serializer)
    }
}

#[serde_as]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StarknetOsInputUtil {
    pub contract_state_commitment_info: CommitmentInfo,
    pub contract_class_commitment_info: CommitmentInfo,
    #[serde_as(as = "HashMap<Felt252Str, DeprecatedContractClassStr>")]
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

impl StarknetOsInputUtil {
    pub fn load(path: &str) -> Self {
        let raw_input = fs::read_to_string(path).unwrap();
        serde_json::from_str(&raw_input).unwrap()
    }
    pub fn dump(&self, path: &str) -> Result<(), SnOsError> {
        fs::File::create(path)
            .unwrap()
            .write_all(&serde_json::to_vec(&self).unwrap())
            .map_err(|e| SnOsError::CatchAll(format!("{e}")))
    }
}

#[serde_as]
#[derive(Debug, Deserialize)]
pub struct RawOsOutput(#[serde_as(as = "Vec<Felt252Num>")] pub Vec<Felt252>);

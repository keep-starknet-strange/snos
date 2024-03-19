use std::fs;

use cairo_vm::Felt252;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{serde_as, DeserializeAs, SerializeAs};
use snos::utils::Felt252Num;
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
#[derive(Debug, Deserialize)]
pub struct RawOsOutput(#[serde_as(as = "Vec<Felt252Num>")] pub Vec<Felt252>);

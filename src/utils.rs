use anyhow::anyhow;
use bitvec::{prelude::BitSlice, prelude::BitVec, prelude::Msb0, view::BitView};
use blockifier::execution::contract_class::ContractClassV0;

use cairo_felt::Felt252;
use cairo_vm_blockifier::types::program::Program;

use std::collections::HashMap;
use std::fs;
use std::path;

use crate::config::DEFAULT_COMPILER_VERSION;

use starknet_api::core::{ClassHash, Nonce, PatriciaKey};
use starknet_api::deprecated_contract_class::{
    ContractClass as DeprecatedContractClass, Program as DeprecatedProgram,
};
use starknet_api::hash::{pedersen_hash, StarkFelt, StarkHash};

use serde::Deserialize;

use num_traits::Num;
use serde::{de, ser, Deserializer, Serializer};
use serde_json::Number;
use serde_with::{DeserializeAs, SerializeAs};

pub const REPLACE_KEY: &str = "replace:";

/// Calculates the contract state hash from its preimage.
pub fn calculate_contract_state_hash(
    class_hash: ClassHash,
    contract_root: PatriciaKey,
    nonce: Nonce,
) -> StarkHash {
    const CONTRACT_STATE_HASH_VERSION: StarkFelt = StarkFelt::ZERO;

    // The contract state hash is defined as H(H(H(hash, root), nonce), CONTRACT_STATE_HASH_VERSION)
    let hash = pedersen_hash(&class_hash.0, contract_root.key());
    let hash = pedersen_hash(&hash, &nonce.0);
    pedersen_hash(&hash, &CONTRACT_STATE_HASH_VERSION)
}

pub fn felt_from_bits(bits: &BitSlice<u8, Msb0>) -> anyhow::Result<StarkFelt> {
    if bits.len() > 251 {
        return Err(anyhow!("overflow: > 251 bits"));
    }

    let mut bytes = [0u8; 32];
    bytes.view_bits_mut::<Msb0>()[256 - bits.len()..].copy_from_bitslice(bits);

    StarkFelt::new(bytes).map_err(|e| anyhow!(format!("{e}")))
}

pub fn bits_from_felt(felt: StarkFelt) -> BitVec<u8, Msb0> {
    felt.bytes().view_bits::<Msb0>()[5..].to_bitvec()
}

pub fn vm_class_to_api_v0(class: ContractClassV0) -> DeprecatedContractClass {
    DeprecatedContractClass {
        abi: None,
        program: vm_program_to_api_v0(&class.program),
        entry_points_by_type: class.entry_points_by_type.clone(),
    }
}

pub fn felt_from_hex_unchecked(hex_str: &str) -> Felt252 {
    Felt252::from_str_radix(hex_str.trim_start_matches("0x"), 16).unwrap()
}

pub fn vm_program_to_api_v0(program: &Program) -> DeprecatedProgram {
    let builtins = program.iter_builtins().cloned().collect::<Vec<_>>();
    let data = program.iter_data().cloned().collect::<Vec<_>>();
    let identifiers: HashMap<_, _> = program
        .iter_identifiers()
        .map(|(cairo_type, identifier)| (cairo_type.to_string(), identifier.clone()))
        .collect();

    // TODO: parse references
    DeprecatedProgram {
        builtins: serde_json::to_value(builtins).unwrap(),
        compiler_version: serde_json::to_value(DEFAULT_COMPILER_VERSION).unwrap(),
        data: serde_json::to_value(data).unwrap(),
        identifiers: serde_json::to_value(identifiers).unwrap(),
        prime: serde_json::to_value(program.prime()).unwrap(),
        ..DeprecatedProgram::default()
    }
}

pub struct Felt252Str;

impl<'de> DeserializeAs<'de, Felt252> for Felt252Str {
    fn deserialize_as<D>(deserializer: D) -> Result<Felt252, D::Error>
    where
        D: Deserializer<'de>,
    {
        let felt_str = String::deserialize(deserializer)?;
        match felt_str.strip_prefix("0x") {
            Some(felt_hex) => match Felt252::from_str_radix(felt_hex, 16) {
                Ok(x) => Ok(x),
                Err(e) => Err(de::Error::custom(format!("{e}"))),
            },
            None => match Felt252::from_str_radix(&felt_str, 10) {
                Ok(x) => Ok(x),
                Err(e) => Err(de::Error::custom(format!("{e}"))),
            },
        }
    }
}

impl SerializeAs<Felt252> for Felt252Str {
    fn serialize_as<S>(value: &Felt252, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{}", value.to_str_radix(16)))
    }
}

pub struct Felt252Num;

impl<'de> DeserializeAs<'de, Felt252> for Felt252Num {
    fn deserialize_as<D>(deserializer: D) -> Result<Felt252, D::Error>
    where
        D: Deserializer<'de>,
    {
        let felt_num = Number::deserialize(deserializer)?;
        match Felt252::parse_bytes(felt_num.to_string().as_bytes(), 10) {
            Some(x) => Ok(x),
            None => Err(de::Error::custom(String::from(
                "felt_from_number parse error",
            ))),
        }
    }
}

impl SerializeAs<Felt252> for Felt252Num {
    fn serialize_as<S>(value: &Felt252, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{}", value.to_bigint()))
    }
}
pub struct DeprecatedContractClassStr;

impl<'de> DeserializeAs<'de, DeprecatedContractClass> for DeprecatedContractClassStr {
    fn deserialize_as<D>(deserializer: D) -> Result<DeprecatedContractClass, D::Error>
    where
        D: Deserializer<'de>,
    {
        let deprecated_class = String::deserialize(deserializer)?;
        let path_prefix = (deprecated_class[..8]).to_string();
        let raw_class = if path_prefix != REPLACE_KEY {
            deprecated_class
        } else {
            fs::read_to_string(path::PathBuf::from(
                deprecated_class.trim_start_matches(REPLACE_KEY),
            ))
            .map_err(|e| de::Error::custom(format!("{e}")))?
        };

        serde_json::from_str(&raw_class).map_err(|e| de::Error::custom(format!("{e}")))
    }
}

impl SerializeAs<DeprecatedContractClass> for DeprecatedContractClassStr {
    fn serialize_as<S>(
        deprecated_class: &DeprecatedContractClass,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(
            &serde_json::to_string(deprecated_class)
                .map_err(|e| ser::Error::custom(format!("{e}")))?,
        )
    }
}

use std::collections::HashMap;

use anyhow::anyhow;
use bitvec::prelude::{BitSlice, BitVec, Msb0};
use bitvec::view::BitView;
use blockifier::execution::contract_class::ContractClassV0;
use cairo_vm::felt::{felt_str, Felt252};
use cairo_vm_blockifier::types::program::Program;
use lazy_static::lazy_static;
use num_traits::Num;
use regex::Regex;
use serde::{de, ser, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Number;
use serde_with::{DeserializeAs, SerializeAs};
use starknet_api::core::{ChainId, ClassHash, Nonce, PatriciaKey};
use starknet_api::deprecated_contract_class::{ContractClass as DeprecatedContractClass, Program as DeprecatedProgram};
use starknet_api::hash::{pedersen_hash, StarkFelt, StarkHash};
use starknet_api::stark_felt;

use crate::config::DEFAULT_COMPILER_VERSION;
use crate::error::SnOsError;

lazy_static! {
    static ref RE: Regex = Regex::new(r"^[A-Fa-f0-9]+$").unwrap();
}

/// Calculates the contract state hash from its preimage.
pub fn calculate_contract_state_hash(class_hash: ClassHash, contract_root: PatriciaKey, nonce: Nonce) -> StarkHash {
    const CONTRACT_STATE_HASH_VERSION: StarkFelt = StarkFelt::ZERO;

    // The contract state hash is defined as H(H(H(hash, root), nonce), CONTRACT_STATE_HASH_VERSION)
    let hash = pedersen_hash(&class_hash.0, contract_root.key());
    let hash = pedersen_hash(&hash, &nonce.0);
    pedersen_hash(&hash, &CONTRACT_STATE_HASH_VERSION)
}

pub fn felt_from_bits_api(bits: &BitSlice<u8, Msb0>) -> anyhow::Result<StarkFelt> {
    if bits.len() > 251 {
        return Err(anyhow!("overflow: > 251 bits"));
    }

    let mut bytes = [0u8; 32];
    bytes.view_bits_mut::<Msb0>()[256 - bits.len()..].copy_from_bitslice(bits);

    StarkFelt::new(bytes).map_err(|e| anyhow!(format!("{e}")))
}

pub fn felt_to_bits_api(felt: StarkFelt) -> BitVec<u8, Msb0> {
    felt.bytes().view_bits::<Msb0>()[5..].to_bitvec()
}

pub fn felt_from_hex_unchecked(hex_str: &str) -> Felt252 {
    Felt252::from_str_radix(hex_str.trim_start_matches("0x"), 16).unwrap()
}

pub fn felt_vm2api(felt: Felt252) -> StarkFelt {
    stark_felt!(felt.to_str_radix(16).as_str())
}

pub fn felt_api2vm(felt: StarkFelt) -> Felt252 {
    felt_str!(felt.to_string().trim_start_matches("0x"), 16)
}

pub fn felt_vm2usize(felt_op: Option<&Felt252>) -> Result<usize, SnOsError> {
    match felt_op {
        Some(felt) => {
            let big_num: u16 = felt.to_bigint().try_into().map_err(|e| SnOsError::Output(format!("{e}")))?;

            Ok(big_num.into())
        }
        None => Err(SnOsError::CatchAll("no length available".to_string())),
    }
}

pub fn deprecated_class_vm2api(class: ContractClassV0) -> DeprecatedContractClass {
    DeprecatedContractClass {
        abi: None,
        program: deprecated_program_vm2api(&class.program),
        entry_points_by_type: class.entry_points_by_type.clone(),
    }
}

pub fn deprecated_program_vm2api(program: &Program) -> DeprecatedProgram {
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
        let felt_str = felt_str.trim_start_matches("0x");

        Felt252::from_str_radix(felt_str, 16).map_err(de::Error::custom)
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

pub struct Felt252StrDec;

impl<'de> DeserializeAs<'de, Felt252> for Felt252StrDec {
    fn deserialize_as<D>(deserializer: D) -> Result<Felt252, D::Error>
    where
        D: Deserializer<'de>,
    {
        let felt_str = String::deserialize(deserializer)?;
        let felt_str = felt_str.trim_start_matches("0x");

        Felt252::from_str_radix(felt_str, 10).map_err(de::Error::custom)
    }
}

impl SerializeAs<Felt252> for Felt252StrDec {
    fn serialize_as<S>(value: &Felt252, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_str_radix(10))
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
            None => Err(de::Error::custom(String::from("felt_from_number parse error"))),
        }
    }
}

impl SerializeAs<Felt252> for Felt252Num {
    fn serialize_as<S>(value: &Felt252, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let num = Number::from_string_unchecked(value.to_str_radix(10));
        num.serialize(serializer)
    }
}

pub struct Felt252HexNoPrefix;

impl<'de> DeserializeAs<'de, Felt252> for Felt252HexNoPrefix {
    fn deserialize_as<D>(deserializer: D) -> Result<Felt252, D::Error>
    where
        D: Deserializer<'de>,
    {
        let felt_str = String::deserialize(deserializer)?;
        Felt252::from_str_radix(&felt_str, 16).map_err(de::Error::custom)
    }
}

impl SerializeAs<Felt252> for Felt252HexNoPrefix {
    fn serialize_as<S>(value: &Felt252, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0{}", value.to_str_radix(16)))
    }
}

pub struct ChainIdNum;

impl<'de> DeserializeAs<'de, ChainId> for ChainIdNum {
    fn deserialize_as<D>(deserializer: D) -> Result<ChainId, D::Error>
    where
        D: Deserializer<'de>,
    {
        let felt_num = u128::deserialize(deserializer)?;
        Ok(ChainId(format!("{felt_num:x}")))
    }
}

impl SerializeAs<ChainId> for ChainIdNum {
    fn serialize_as<S>(value: &ChainId, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u128(u128::from_str_radix(&value.0, 16).map_err(ser::Error::custom)?)
    }
}

#[cfg(test)]
mod tests {
    use bitvec::prelude::*;

    use super::*;

    #[test]
    fn felt_conversions() {
        let vm_felt = felt_str!("DEADBEEF", 16);
        let api_felt = stark_felt!("DEADBEEF");

        assert_eq!(vm_felt, felt_api2vm(api_felt));
        assert_eq!(api_felt, felt_vm2api(vm_felt.clone()));

        let raw = "0xDEADBEEF";
        assert_eq!(vm_felt, felt_from_hex_unchecked(raw));

        let raw_prefix = "DEADBEEF";
        assert_eq!(vm_felt, felt_from_hex_unchecked(raw_prefix));

        let mut bv = bitvec![u8, Msb0; 0; 219];
        bv.extend_from_bitslice(0xDEADBEEF_u32.view_bits::<Msb0>());

        assert_eq!(bv, felt_to_bits_api(api_felt));
        assert_eq!(api_felt, felt_from_bits_api(&bv).unwrap());
    }
}

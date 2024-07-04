use std::collections::HashMap;

use anyhow::anyhow;
use bitvec::prelude::{BitSlice, BitVec, Msb0};
use bitvec::view::BitView;
use blockifier::execution::contract_class::ContractClassV0Inner;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::Felt252;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{de, ser, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Number;
use serde_with::{DeserializeAs, SerializeAs};
use starknet_api::core::{ChainId, ClassHash, Nonce, PatriciaKey};
use starknet_api::deprecated_contract_class::{ContractClass as DeprecatedContractClass, Program as DeprecatedProgram};
use starknet_api::hash::{pedersen_hash, StarkFelt, StarkHash};
use starknet_api::stark_felt;
use tokio::task;

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
    Felt252::from_hex(hex_str).unwrap()
}

pub fn felt_vm2api(felt: Felt252) -> StarkFelt {
    stark_felt!(felt.to_hex_string().as_str())
}

pub fn felt_api2vm(felt: StarkFelt) -> Felt252 {
    Felt252::from_hex(&felt.to_string()).expect("Couldn't parse bytes")
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

pub fn deprecated_class_vm2api(class: &ContractClassV0Inner) -> DeprecatedContractClass {
    let builtins = class.program.iter_builtins().cloned().collect::<Vec<_>>();
    let data = class.program.iter_data().cloned().collect::<Vec<_>>();
    let identifiers: HashMap<_, _> = class
        .program
        .iter_identifiers()
        .map(|(cairo_type, identifier)| (cairo_type.to_string(), identifier.clone()))
        .collect();

    let program = DeprecatedProgram {
        builtins: serde_json::to_value(builtins).unwrap(),
        compiler_version: serde_json::to_value(DEFAULT_COMPILER_VERSION).unwrap(),
        data: serde_json::to_value(data).unwrap(),
        identifiers: serde_json::to_value(identifiers).unwrap(),
        prime: serde_json::to_value(class.program.prime()).unwrap(),
        ..DeprecatedProgram::default()
    };

    DeprecatedContractClass { abi: None, program, entry_points_by_type: class.entry_points_by_type.clone() }
}

pub struct Felt252Str;

impl<'de> DeserializeAs<'de, Felt252> for Felt252Str {
    fn deserialize_as<D>(deserializer: D) -> Result<Felt252, D::Error>
    where
        D: Deserializer<'de>,
    {
        let felt_str = String::deserialize(deserializer)?;
        let felt_str = felt_str.trim_start_matches("0x");

        Felt252::from_hex(felt_str).map_err(|e| de::Error::custom(format!("felt from hex str parse error: {e}")))
    }
}

impl SerializeAs<Felt252> for Felt252Str {
    fn serialize_as<S>(value: &Felt252, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_hex_string())
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

        Felt252::from_dec_str(felt_str).map_err(|e| de::Error::custom(format!("felt from dec str parse error: {e}")))
    }
}

impl SerializeAs<Felt252> for Felt252StrDec {
    fn serialize_as<S>(value: &Felt252, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{}", value))
    }
}

pub struct Felt252Num;

impl<'de> DeserializeAs<'de, Felt252> for Felt252Num {
    fn deserialize_as<D>(deserializer: D) -> Result<Felt252, D::Error>
    where
        D: Deserializer<'de>,
    {
        let felt_num = Number::deserialize(deserializer)?;

        match Felt252::from_dec_str(&felt_num.to_string()) {
            Ok(x) => Ok(x),
            Err(e) => Err(de::Error::custom(format!("felt_from_number parse error: {e}"))),
        }
    }
}

impl SerializeAs<Felt252> for Felt252Num {
    fn serialize_as<S>(value: &Felt252, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let num = Number::from_string_unchecked(format!("{}", value));
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
        Felt252::from_hex(&format!("0x{felt_str}")).map_err(de::Error::custom)
    }
}

impl SerializeAs<Felt252> for Felt252HexNoPrefix {
    fn serialize_as<S>(value: &Felt252, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0{}", value.to_hex_string().trim_start_matches("0x")))
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

pub fn u64_from_byte_slice_le(bytes: &[u8]) -> u64 {
    let mut x: u64 = 0;
    for (i, byte) in bytes.iter().enumerate() {
        x += (*byte as u64) << (i * 8);
    }
    x
}

pub fn u64_from_byte_slice_be(bytes: &[u8]) -> u64 {
    let mut x: u64 = 0;
    for (i, byte) in bytes.iter().enumerate() {
        if *byte != 0 {
            let offset = 8 * (bytes.len() - i - 1);
            x += (*byte as u64) << offset;
        }
    }
    x
}

pub fn i64_from_byte_slice_le(bytes: &[u8]) -> i64 {
    u64_from_byte_slice_le(bytes) as i64
}

pub fn i64_from_byte_slice_be(bytes: &[u8]) -> i64 {
    u64_from_byte_slice_be(bytes) as i64
}

/// Retrieves a constant from the `constants` hashmap or returns an error.
///
/// We should not use `get_constant_from_var_name` if possible as it performs an O(N)
/// lookup to look for an entry that matches a variable name, without the path prefix.
pub fn get_constant<'a>(
    identifier: &'static str,
    constants: &'a HashMap<String, Felt252>,
) -> Result<&'a Felt252, HintError> {
    constants.get(identifier).ok_or(HintError::MissingConstant(Box::new(identifier)))
}

/// Gets the current Tokio runtime or fails gracefully with a HintError.
fn get_tokio_runtime_handle() -> Result<tokio::runtime::Handle, HintError> {
    tokio::runtime::Handle::try_current()
        .map_err(|e| HintError::CustomHint(format!("Tokio runtime not found: {e}").into_boxed_str()))
}

/// Executes a coroutine from a synchronous context.
/// Fails if no Tokio runtime is present.
pub fn execute_coroutine<F, T>(coroutine: F) -> Result<T, HintError>
where
    F: std::future::Future<Output = T>,
{
    let tokio_runtime_handle = get_tokio_runtime_handle()?;
    Ok(task::block_in_place(|| tokio_runtime_handle.block_on(coroutine)))
}

/// Retrieve a variable from the root execution scope.
///
/// Some global variables are stored in the root execution scope on startup. We sometimes
/// need access to these variables from a hint where we are already in a nested scope.
/// This function retrieves the variable from the root scope regardless of the current scope.
pub fn get_variable_from_root_exec_scope<T>(exec_scopes: &ExecutionScopes, name: &str) -> Result<T, HintError>
where
    T: Clone + 'static,
{
    exec_scopes.data[0]
        .get(name)
        .and_then(|var| var.downcast_ref::<T>().cloned())
        .ok_or(HintError::VariableNotInScopeError(name.to_string().into_boxed_str()))
}

/// Builds a custom hint error
pub fn custom_hint_error(error: &str) -> HintError {
    HintError::CustomHint(error.to_string().into_boxed_str())
}

#[cfg(test)]
mod tests {
    use bitvec::prelude::*;
    use serde_with::serde_as;

    use super::*;

    #[serde_as]
    #[derive(Serialize)]
    struct ChainIdOnly {
        #[serde_as(as = "ChainIdNum")]
        chain_id: ChainId,
    }

    #[test]
    fn felt_conversions() {
        let vm_felt = Felt252::from_hex("0xDEADBEEF").unwrap();
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

    #[test]
    fn chain_id_num_ok() {
        let c = ChainIdOnly { chain_id: ChainId("534e5f474f45524c49".to_string()) };

        serde_json::to_string(&c).unwrap();
    }

    #[test]
    #[should_panic]
    fn chain_id_num_fail() {
        let c = ChainIdOnly { chain_id: ChainId("SN_GOERLI".to_string()) };

        serde_json::to_string(&c).unwrap();
    }
}

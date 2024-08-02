use std::collections::HashMap;

use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::Felt252;
use serde::{de, ser, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Number;
use serde_with::{DeserializeAs, SerializeAs};
use starknet_api::core::ChainId;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use tokio::task;

pub fn felt_vm2api(felt: Felt252) -> StarkFelt {
    stark_felt!(felt.to_hex_string().as_str())
}

pub fn felt_api2vm(felt: StarkFelt) -> Felt252 {
    Felt252::from_hex(&felt.to_string()).expect("Couldn't parse bytes")
}

pub(crate) struct Felt252Str;

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

pub(crate) struct Felt252Num;

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

pub(crate) struct Felt252HexNoPrefix;

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

pub(crate) struct ChainIdNum;

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

/// Retrieves a constant from the `constants` hashmap or returns an error.
///
/// We should not use `get_constant_from_var_name` if possible as it performs an O(N)
/// lookup to look for an entry that matches a variable name, without the path prefix.
pub(crate) fn get_constant<'a>(
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
pub(crate) fn execute_coroutine<F, T>(coroutine: F) -> Result<T, HintError>
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
pub(crate) fn get_variable_from_root_exec_scope<T>(exec_scopes: &ExecutionScopes, name: &str) -> Result<T, HintError>
where
    T: Clone + 'static,
{
    exec_scopes.data[0]
        .get(name)
        .and_then(|var| var.downcast_ref::<T>().cloned())
        .ok_or(HintError::VariableNotInScopeError(name.to_string().into_boxed_str()))
}

/// Builds a custom hint error
pub(crate) fn custom_hint_error<S: Into<String>>(error: S) -> HintError {
    HintError::CustomHint(error.into().into_boxed_str())
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
        assert_eq!(api_felt, felt_vm2api(vm_felt));

        let mut bv = bitvec![u8, Msb0; 0; 219];
        bv.extend_from_bitslice(0xDEADBEEF_u32.view_bits::<Msb0>());
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

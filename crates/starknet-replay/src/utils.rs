use blockifier::execution::contract_class::{ContractClassV0, ContractClassV1};
use blockifier::state::errors::StateError;
use cairo_lang_starknet_classes::casm_contract_class::CasmContractClass;
use serde::de::DeserializeOwned;
use serde::Serialize;
use starknet::core::types::Felt;
use starknet_api::hash::StarkFelt;

/// Executes a coroutine from a synchronous context.
/// Fails if no Tokio runtime is present.
pub(crate) fn execute_coroutine<F, T>(coroutine: F) -> Result<T, tokio::runtime::TryCurrentError>
where
    F: std::future::Future<Output = T>,
{
    let tokio_runtime_handle = tokio::runtime::Handle::try_current()?;
    Ok(tokio::task::block_in_place(|| tokio_runtime_handle.block_on(coroutine)))
}

pub fn felt_api2vm(felt: StarkFelt) -> Felt {
    Felt::from_bytes_be_slice(felt.bytes())
}

pub fn felt_vm2api(felt: Felt) -> StarkFelt {
    StarkFelt::new_unchecked(felt.to_bytes_be())
}

fn serialize_then_deserialize<I: Serialize, O: DeserializeOwned>(input: &I) -> Result<O, StateError> {
    let serialized = serde_json::to_string(input).map_err(|e| StateError::StateReadError(e.to_string()))?;
    serde_json::from_str(&serialized).map_err(|e| StateError::StateReadError(e.to_string()))
}

pub fn contract_class_api2vm(
    contract_class: starknet::core::types::ContractClass,
) -> Result<blockifier::execution::contract_class::ContractClass, StateError> {
    let contract_class = match contract_class {
        starknet::core::types::ContractClass::Sierra(sierra_class) => {
            let casm_contract_class: CasmContractClass = serialize_then_deserialize(&sierra_class)?;
            let contract_class_v1 = ContractClassV1::try_from(casm_contract_class).map_err(StateError::ProgramError)?;
            contract_class_v1.into()
        }
        starknet::core::types::ContractClass::Legacy(legacy_class) => {
            let contract_class_v0: ContractClassV0 = serialize_then_deserialize(&legacy_class)?;
            contract_class_v0.into()
        }
    };

    Ok(contract_class)
}

use blockifier::execution::contract_class::{CompiledClassV0, CompiledClassV1, RunnableCompiledClass};
use blockifier::state::errors::StateError;
use blockifier::state::state_api::{StateReader, StateResult};
use cairo_lang_starknet_classes::contract_class::version_id_from_serialized_sierra_program;
use log::{debug, error};
use starknet::core::types::{BlockId, Felt, StarknetError};
use starknet::providers::{Provider, ProviderError};
use starknet_api::contract_class::SierraVersion;
use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::state::StorageKey;
use starknet_os_types::deprecated_compiled_class::GenericDeprecatedCompiledClass;
use starknet_os_types::sierra_contract_class::GenericSierraContractClass;
use starknet_os_types::starknet_core_addons::decompress_starknet_core_contract_class;

use crate::client::RpcClient;
use crate::utils::execute_coroutine;

#[cfg(test)]
pub mod tests;

#[derive(Clone)]
pub struct AsyncRpcStateReader {
    rpc_client: RpcClient,
    block_id: BlockId,
}

impl AsyncRpcStateReader {
    pub fn new(rpc_client: RpcClient, block_id: BlockId) -> Self {
        Self { rpc_client, block_id }
    }
}

// Helper function to convert provider error to state error
fn provider_error_to_state_error(provider_error: ProviderError) -> StateError {
    StateError::StateReadError(provider_error.to_string())
}

fn to_state_err<E: ToString>(e: E) -> StateError {
    StateError::StateReadError(e.to_string())
}

impl AsyncRpcStateReader {
    pub async fn get_storage_at_async(&self, contract_address: ContractAddress, key: StorageKey) -> StateResult<Felt> {
        let storage_value = match self
            .rpc_client
            .starknet_rpc()
            .get_storage_at(*contract_address.key(), *key.0.key(), self.block_id)
            .await
        {
            Ok(value) => Ok(value),
            Err(ProviderError::StarknetError(StarknetError::ContractNotFound)) => Ok(Felt::ZERO),
            Err(e) => Err(provider_error_to_state_error(e)),
        }?;

        Ok(storage_value)
    }

    pub async fn get_nonce_at_async(&self, contract_address: ContractAddress) -> StateResult<Nonce> {
        debug!("got a request of get_nonce_at with parameters the contract address: {:?}", contract_address);
        let res = self.rpc_client.starknet_rpc().get_nonce(self.block_id, *contract_address.key()).await;
        let nonce = match res {
            Ok(value) => Ok(value),
            Err(ProviderError::StarknetError(StarknetError::ContractNotFound)) => Ok(Felt::ZERO),
            Err(e) => Err(provider_error_to_state_error(e)),
        }?;
        Ok(Nonce(nonce))
    }

    pub async fn get_class_hash_at_async(&self, contract_address: ContractAddress) -> StateResult<ClassHash> {
        debug!("got a request of get_class_hash_at with parameters the contract address: {:?}", contract_address);
        let class_hash =
            match self.rpc_client.starknet_rpc().get_class_hash_at(self.block_id, *contract_address.key()).await {
                Ok(class_hash) => Ok(class_hash),
                Err(ProviderError::StarknetError(StarknetError::ContractNotFound)) => Ok(ClassHash::default().0),
                Err(e) => Err(provider_error_to_state_error(e)),
            }?;

        Ok(ClassHash(class_hash))
    }

    pub async fn get_compiled_class_async(&self, class_hash: ClassHash) -> StateResult<RunnableCompiledClass> {
        debug!("got a request of get_compiled_class with parameters the class hash: {:?}", class_hash);
        let contract_class = match self.rpc_client.starknet_rpc().get_class(self.block_id, class_hash.0).await {
            Ok(contract_class) => Ok(contract_class),
            // If the ContractClass is declared in the current block,
            // might trigger this error when trying to get it on the previous block.
            // Returning an `UndeclaredClassHash` allows blockifier to continue execution
            // Reference: https://github.com/starkware-libs/sequencer/blob/1ade15c645882e3a0bd70ef8f79b23fc66a517e0/crates/blockifier/src/state/cached_state.rs#L178-L200
            Err(ProviderError::StarknetError(StarknetError::ClassHashNotFound)) => {
                Err(StateError::UndeclaredClassHash(ClassHash(class_hash.0)))
            }
            Err(e) => Err(provider_error_to_state_error(e)),
        }?;

        let runnable_contract_class: RunnableCompiledClass = match contract_class {
            starknet::core::types::ContractClass::Sierra(sierra_class) => {
                // Serialize the sierra class to JSON
                let sierra_json = serde_json::to_string(&sierra_class).map_err(to_state_err)?;

                // Parse the JSON to fix the ABI field
                let mut sierra_value: serde_json::Value = serde_json::from_str(&sierra_json).map_err(to_state_err)?;

                // The ABI field is a JSON string, but GenericSierraContractClass expects it to be parseable.
                // Let's check if the ABI field needs to be converted from string to JSON
                if let Some(abi_field) = sierra_value.get_mut("abi") {
                    if let Some(abi_str) = abi_field.as_str() {
                        // Try to parse the ABI string as JSON
                        match serde_json::from_str::<serde_json::Value>(abi_str) {
                            Ok(abi_json) => {
                                debug!("✅ Successfully parsed ABI string as JSON");
                                *abi_field = abi_json;
                            }
                            Err(e) => {
                                error!("⚠️  ABI is not valid JSON string: {}", e);
                                // Keep the ABI as-is if it's not a JSON string
                            }
                        }
                    }
                }

                // Re-serialize the fixed JSON
                let fixed_sierra_json = serde_json::to_string(&sierra_value).map_err(to_state_err)?;

                // Parse as GenericSierraContractClass
                let generic_sierra = GenericSierraContractClass::from_bytes(fixed_sierra_json.into_bytes());

                let generic_cairo_lang_class = generic_sierra
                    .get_cairo_lang_contract_class()
                    .map_err(|e| StateError::StateReadError(e.to_string()))?;
                let (version_id, _) =
                    version_id_from_serialized_sierra_program(&generic_cairo_lang_class.sierra_program)
                        .map_err(|e| StateError::StateReadError(e.to_string()))?;
                let sierra_version =
                    SierraVersion::new(version_id.major as u64, version_id.minor as u64, version_id.patch as u64);

                // Try compilation
                match generic_sierra.compile() {
                    Ok(compiled_class) => {
                        debug!("✅ Sierra compilation succeeded!");
                        let versioned_casm =
                            compiled_class.to_blockifier_contract_class(sierra_version).map_err(to_state_err)?;

                        // Convert VersionedCasm to CompiledClassV1 using TryFrom
                        let compiled_class_v1 = CompiledClassV1::try_from(versioned_casm).map_err(|e| {
                            StateError::StateReadError(format!(
                                "Failed to convert VersionedCasm to CompiledClassV1: {}",
                                e
                            ))
                        })?;

                        RunnableCompiledClass::V1(compiled_class_v1)
                    }
                    Err(e) => {
                        error!("⚠️  Sierra compilation failed: {}", e);
                        return Err(StateError::StateReadError(format!("Sierra compilation failed: {}", e)));
                    }
                }
            }
            starknet::core::types::ContractClass::Legacy(legacy_class) => {
                // Convert between starknet crate types via serialization
                let legacy_json = serde_json::to_string(&legacy_class).map_err(to_state_err)?;
                let starknet_core_legacy_class: starknet_core::types::CompressedLegacyContractClass =
                    serde_json::from_str(&legacy_json).map_err(to_state_err)?;

                // Now use the decompression function from starknet_core_addons
                let decompressed_legacy_class = decompress_starknet_core_contract_class(starknet_core_legacy_class)
                    .map_err(|e| {
                        StateError::StateReadError(format!("Failed to decompress legacy contract class: {}", e))
                    })?;

                // Convert the decompressed LegacyContractClass to GenericDeprecatedCompiledClass
                let generic_deprecated = GenericDeprecatedCompiledClass::from(decompressed_legacy_class);
                let deprecated_contract_class =
                    generic_deprecated.to_blockifier_contract_class().map_err(to_state_err)?;

                // Convert DeprecatedContractClass to CompiledClassV0 using TryFrom
                let compiled_class_v0 = CompiledClassV0::try_from(deprecated_contract_class).map_err(|e| {
                    StateError::StateReadError(format!(
                        "Failed to convert DeprecatedContractClass to CompiledClassV0: {}",
                        e
                    ))
                })?;

                RunnableCompiledClass::V0(compiled_class_v0)
            }
        };

        Ok(runnable_contract_class)
    }

    pub async fn get_compiled_class_hash_async(&self, class_hash: ClassHash) -> StateResult<CompiledClassHash> {
        debug!("got a request of get_compiled_class_hash with parameters the class hash: {:?}", class_hash);
        let contract_class = self
            .rpc_client
            .starknet_rpc()
            .get_class(self.block_id, class_hash.0)
            .await
            .map_err(provider_error_to_state_error)?;

        let class_hash = match contract_class {
            starknet::core::types::ContractClass::Sierra(sierra_class) => {
                // Apply the same ABI fix as in get_compiled_class_async
                let sierra_json = serde_json::to_string(&sierra_class).map_err(to_state_err)?;
                let mut sierra_value: serde_json::Value = serde_json::from_str(&sierra_json).map_err(to_state_err)?;

                // Fix the ABI field if it's a JSON string
                if let Some(abi_field) = sierra_value.get_mut("abi") {
                    if let Some(abi_str) = abi_field.as_str() {
                        if let Ok(abi_json) = serde_json::from_str::<serde_json::Value>(abi_str) {
                            *abi_field = abi_json;
                        }
                    }
                }

                let fixed_sierra_json = serde_json::to_string(&sierra_value).map_err(to_state_err)?;
                let generic_sierra = GenericSierraContractClass::from_bytes(fixed_sierra_json.into_bytes());
                let compiled_class = generic_sierra.compile().map_err(to_state_err)?;
                compiled_class.class_hash().map_err(to_state_err)?
            }
            starknet::core::types::ContractClass::Legacy(legacy_class) => {
                // Convert between starknet crate types via serialization
                let legacy_json = serde_json::to_string(&legacy_class).map_err(to_state_err)?;
                let starknet_core_legacy_class: starknet_core::types::CompressedLegacyContractClass =
                    serde_json::from_str(&legacy_json).map_err(to_state_err)?;

                // Use the decompression function from starknet_core_addons
                let decompressed_legacy_class = decompress_starknet_core_contract_class(starknet_core_legacy_class)
                    .map_err(|e| {
                        StateError::StateReadError(format!("Failed to decompress legacy contract class: {}", e))
                    })?;

                // Convert the decompressed LegacyContractClass to GenericDeprecatedCompiledClass
                let generic_deprecated = GenericDeprecatedCompiledClass::from(decompressed_legacy_class);
                generic_deprecated.class_hash().map_err(to_state_err)?
            }
        };

        Ok(class_hash.into())
    }
}

// Implementing StateReader for AsyncRpcStateReader using coroutines
impl StateReader for AsyncRpcStateReader {
    fn get_storage_at(&self, contract_address: ContractAddress, key: StorageKey) -> StateResult<Felt> {
        execute_coroutine(self.get_storage_at_async(contract_address, key))
            .map_err(|e| StateError::StateReadError(e.to_string()))?
    }

    fn get_nonce_at(&self, contract_address: ContractAddress) -> StateResult<Nonce> {
        execute_coroutine(self.get_nonce_at_async(contract_address))
            .map_err(|e| StateError::StateReadError(e.to_string()))?
    }

    fn get_class_hash_at(&self, contract_address: ContractAddress) -> StateResult<ClassHash> {
        execute_coroutine(self.get_class_hash_at_async(contract_address))
            .map_err(|e| StateError::StateReadError(e.to_string()))?
    }

    fn get_compiled_class(&self, class_hash: ClassHash) -> StateResult<RunnableCompiledClass> {
        execute_coroutine(self.get_compiled_class_async(class_hash))
            .map_err(|e| StateError::StateReadError(e.to_string()))?
    }

    fn get_compiled_class_hash(&self, class_hash: ClassHash) -> StateResult<CompiledClassHash> {
        execute_coroutine(self.get_compiled_class_hash_async(class_hash))
            .map_err(|e| StateError::StateReadError(e.to_string()))?
    }
}

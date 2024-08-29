use blockifier::execution::contract_class::ContractClass;
use blockifier::state::errors::StateError;
use blockifier::state::state_api::{StateReader, StateResult};
use starknet::core::types::{BlockId, Felt};
use starknet::providers::jsonrpc::JsonRpcTransport;
use starknet::providers::{JsonRpcClient, Provider, ProviderError};
use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::state::StorageKey;
use starknet_os_types::deprecated_compiled_class::GenericDeprecatedCompiledClass;
use starknet_os_types::hash::GenericClassHash;
use starknet_os_types::sierra_contract_class::GenericSierraContractClass;

use crate::utils::execute_coroutine;

pub struct AsyncRpcStateReader<T>
where
    T: JsonRpcTransport,
{
    provider: JsonRpcClient<T>,
    block_id: BlockId,
}

impl<T> AsyncRpcStateReader<T>
where
    T: JsonRpcTransport,
{
    pub fn new(provider: JsonRpcClient<T>, block_id: BlockId) -> Self {
        Self { provider, block_id }
    }
}

fn provider_error_to_state_error(provider_error: ProviderError) -> StateError {
    StateError::StateReadError(provider_error.to_string())
}

fn to_state_err<E: ToString>(e: E) -> StateError {
    StateError::StateReadError(e.to_string())
}

impl<T> AsyncRpcStateReader<T>
where
    T: JsonRpcTransport + Sync + Send + 'static,
{
    pub async fn get_storage_at_async(&self, contract_address: ContractAddress, key: StorageKey) -> StateResult<Felt> {
        let storage_value = self
            .provider
            .get_storage_at(*contract_address.key(), *key.0.key(), self.block_id)
            .await
            .map_err(provider_error_to_state_error)?;

        Ok(storage_value)
    }

    pub async fn get_nonce_at_async(&self, contract_address: ContractAddress) -> StateResult<Nonce> {
        let nonce = self
            .provider
            .get_nonce(self.block_id, *contract_address.key())
            .await
            .map_err(provider_error_to_state_error)?;

        Ok(Nonce(nonce))
    }

    pub async fn get_class_hash_at_async(&self, contract_address: ContractAddress) -> StateResult<ClassHash> {
        let nonce = self
            .provider
            .get_class_hash_at(self.block_id, *contract_address.key())
            .await
            .map_err(provider_error_to_state_error)?;

        Ok(ClassHash(nonce))
    }

    pub async fn get_compiled_contract_class_async(&self, class_hash: ClassHash) -> StateResult<ContractClass> {
        let contract_class =
            self.provider.get_class(self.block_id, class_hash.0).await.map_err(provider_error_to_state_error)?;

        let contract_class: ContractClass = match contract_class {
            starknet::core::types::ContractClass::Sierra(sierra_class) => {
                let contract_class = GenericSierraContractClass::from(sierra_class);
                let compiled_class = contract_class.compile().map_err(to_state_err)?;
                compiled_class.to_blockifier_contract_class().map(Into::into).map_err(to_state_err)?
            }
            starknet::core::types::ContractClass::Legacy(legacy_class) => {
                let contract_class = GenericDeprecatedCompiledClass::try_from(legacy_class).map_err(to_state_err)?;
                contract_class.to_blockifier_contract_class().map(Into::into).map_err(to_state_err)?
            }
        };

        Ok(contract_class)
    }

    pub async fn get_compiled_class_hash_async(&self, class_hash: ClassHash) -> StateResult<CompiledClassHash> {
        let contract_class =
            self.provider.get_class(self.block_id, class_hash.0).await.map_err(provider_error_to_state_error)?;

        let class_hash: GenericClassHash = match contract_class {
            starknet::core::types::ContractClass::Sierra(sierra_class) => {
                let contract_class = GenericSierraContractClass::from(sierra_class);
                let compiled_class = contract_class.compile().map_err(to_state_err)?;
                compiled_class.class_hash().map_err(to_state_err)?
            }
            starknet::core::types::ContractClass::Legacy(legacy_class) => {
                let contract_class = GenericDeprecatedCompiledClass::try_from(legacy_class).map_err(to_state_err)?;
                contract_class.class_hash().map_err(to_state_err)?
            }
        };

        Ok(class_hash.into())
    }
}

impl<T> StateReader for AsyncRpcStateReader<T>
where
    T: JsonRpcTransport + Sync + Send + 'static,
{
    fn get_storage_at(&self, contract_address: ContractAddress, key: StorageKey) -> StateResult<Felt> {
        execute_coroutine(self.get_storage_at_async(contract_address, key)).map_err(to_state_err)?
    }

    fn get_nonce_at(&self, contract_address: ContractAddress) -> StateResult<Nonce> {
        execute_coroutine(self.get_nonce_at_async(contract_address)).map_err(to_state_err)?
    }

    fn get_class_hash_at(&self, contract_address: ContractAddress) -> StateResult<ClassHash> {
        execute_coroutine(self.get_class_hash_at_async(contract_address))
            .map_err(|e| StateError::StateReadError(e.to_string()))?
    }

    fn get_compiled_contract_class(&self, class_hash: ClassHash) -> StateResult<ContractClass> {
        execute_coroutine(self.get_compiled_contract_class_async(class_hash)).map_err(to_state_err)?
    }

    fn get_compiled_class_hash(&self, class_hash: ClassHash) -> StateResult<CompiledClassHash> {
        execute_coroutine(self.get_compiled_class_hash_async(class_hash)).map_err(to_state_err)?
    }
}

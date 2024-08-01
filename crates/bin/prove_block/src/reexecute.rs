use std::error::Error;

use blockifier::{context::BlockContext, state::{cached_state::CachedState, errors::StateError, state_api::{StateReader, StateResult}}, test_utils::dict_state_reader::DictStateReader, transaction::{objects::TransactionExecutionInfo, transaction_execution::Transaction, transactions::ExecutableTransaction as _}};
use starknet::{core::types::BlockId, providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider as _}};
use starknet_os::utils::{execute_coroutine, felt_api2vm, felt_vm2api};
use starknet_api::{core::{ClassHash, CompiledClassHash, Nonce, PatriciaKey}, hash::StarkFelt, state::StorageKey};

/// A StateReader impl which is backed by RPC
pub(crate) struct RpcStateReader {
    pub block_id: BlockId,
    pub rpc_client: JsonRpcClient<HttpTransport>, 
}

impl StateReader for RpcStateReader {
    fn get_storage_at(
        &mut self,
        contract_address: starknet_api::core::ContractAddress,
        key: StorageKey,
    ) -> StateResult<StarkFelt> {
        log::debug!("RpcStateReader::get_storage_at()");
        let value = execute_coroutine(self.rpc_client.get_storage_at(
            felt_api2vm(*contract_address.0.key()),
            felt_api2vm(*key.0.key()),
            self.block_id)
        ).map_err(|_| StateError::StateReadError("Error executing coroutine".to_string()))?
        .map_err(|rpc_error| StateError::StateReadError(format!("RPC Provider Error: {}", rpc_error)))?;

        Ok(felt_vm2api(value))
    }

    fn get_nonce_at(&mut self, contract_address: starknet_api::core::ContractAddress) -> StateResult<Nonce> {
        log::debug!("RpcStateReader::get_nonce_at()");
        let nonce = execute_coroutine(self.rpc_client.get_nonce(
            self.block_id,
            felt_api2vm(*contract_address.0.key()))
        ).map_err(|_| StateError::StateReadError("Error executing coroutine".to_string()))?
        .map_err(|rpc_error| StateError::StateReadError(format!("RPC Provider Error: {}", rpc_error)))?;

        Ok(Nonce(felt_vm2api(nonce)))
    }

    fn get_compiled_contract_class(&mut self, class_hash: ClassHash) -> StateResult<blockifier::execution::contract_class::ContractClass> {
        log::debug!("RpcStateReader::get_compiled_contract_class()");
        let contract_class = execute_coroutine(self.rpc_client.get_class(
            self.block_id,
            felt_api2vm(class_hash.0))
        ).map_err(|_| StateError::StateReadError("Error executing coroutine".to_string()))?
        .map_err(|rpc_error| StateError::StateReadError(format!("RPC Provider Error: {}", rpc_error)))?;

        match contract_class {
            starknet::core::types::ContractClass::Sierra(flattened_sierra_cc) => {
                let middle_sierra: crate::types::MiddleSierraContractClass = {
                    let v = serde_json::to_value(flattened_sierra_cc).unwrap();
                    serde_json::from_value(v).unwrap()
                };
                let sierra_cc = cairo_lang_starknet_classes::contract_class::ContractClass {
                    sierra_program: middle_sierra.sierra_program,
                    contract_class_version: middle_sierra.contract_class_version,
                    entry_points_by_type: middle_sierra.entry_points_by_type,
                    sierra_program_debug_info: None,
                    abi: None,
                };

                let casm_cc =
                    cairo_lang_starknet_classes::casm_contract_class::CasmContractClass::from_contract_class(sierra_cc.clone(), false, usize::MAX).unwrap();

                Ok(blockifier::execution::contract_class::ContractClass::V1(casm_cc.try_into().unwrap()))
            },
            starknet::core::types::ContractClass::Legacy(_compressed_logacy_contract_class) => {
                panic!("legacy class (TODO)");
            }
        }
    }

    fn get_class_hash_at(&mut self, contract_address: starknet_api::core::ContractAddress) -> StateResult<ClassHash> {
        log::debug!("RpcStateReader::get_class_hash_at()");
        let hash = execute_coroutine(self.rpc_client.get_class_hash_at(
            self.block_id,
            felt_api2vm(*contract_address.0.key()))
        ).map_err(|_| StateError::StateReadError("Error executing coroutine".to_string()))?
        .map_err(|rpc_error| StateError::StateReadError(format!("RPC Provider Error: {}", rpc_error)))?;

        Ok(ClassHash(felt_vm2api(hash)))
    }

    fn get_compiled_class_hash(
        &mut self,
        class_hash: ClassHash,
    ) -> StateResult<starknet_api::core::CompiledClassHash> {
        log::debug!("RpcStateReader::get_compiled_class_hash()");
        // TODO: review, this seems to be what starknet_replay does...
        let contract_address = starknet_api::core::ContractAddress(PatriciaKey::try_from(class_hash.0).unwrap());
        let hash = self.get_class_hash_at(contract_address)?;
        Ok(CompiledClassHash(*hash))
    }
}


/// A DictStateReader which uses RPC for missing values.
///
/// Note that the underlying implementation feeds default values when its hash map doesn't contain
/// a value for a given key in some cases, so we sometimes bypass its StateReader impl and use the
/// hash maps directly so we can differentiate between a missing value and a default one.
pub(crate) struct DictStateWithRpc {
    pub dict_state: DictStateReader,
    pub rpc: RpcStateReader, 
}

impl StateReader for DictStateWithRpc {
    fn get_storage_at(
        &mut self,
        contract_address: starknet_api::core::ContractAddress,
        key: StorageKey,
    ) -> StateResult<StarkFelt> {
        log::debug!("DictStateWithRpc::get_storage_at()");

        let contract_storage_key = (contract_address, key);

        match self.dict_state.storage_view.get(&contract_storage_key) {
            Some(nonce) => Ok(*nonce),
            None => {
                // TODO: cache resulin self.dict_state
                self.rpc.get_storage_at(contract_address, key)
            }
        }
    }

    fn get_nonce_at(&mut self, contract_address: starknet_api::core::ContractAddress) -> StateResult<Nonce> {
        log::debug!("DictStateWithRpc::get_nonce_at()");

        match self.dict_state.address_to_nonce.get(&contract_address) {
            Some(nonce) => Ok(*nonce),
            None => {
                // TODO: cache resulin self.dict_state
                self.rpc.get_nonce_at(contract_address)
            }
        }
    }

    fn get_compiled_contract_class(&mut self, class_hash: ClassHash) -> StateResult<blockifier::execution::contract_class::ContractClass> {
        log::debug!("DictStateWithRpc::get_compiled_contract_class()");
        self.dict_state.get_compiled_contract_class(class_hash)
            .or_else(|_| {
                // TODO: cache resulin self.dict_state
                self.rpc.get_compiled_contract_class(class_hash)
            })
    }

    fn get_class_hash_at(&mut self, contract_address: starknet_api::core::ContractAddress) -> StateResult<ClassHash> {
        log::debug!("DictStateWithRpc::get_class_hash_at()");

        match self.dict_state.address_to_class_hash.get(&contract_address) {
            Some(nonce) => Ok(*nonce),
            None => {
                // TODO: cache resulin self.dict_state
                self.rpc.get_class_hash_at(contract_address)
            }
        }
    }

    fn get_compiled_class_hash(
        &mut self,
        class_hash: ClassHash,
    ) -> StateResult<starknet_api::core::CompiledClassHash> {
        log::debug!("DictStateWithRpc::get_compiled_class_hash()");
        self.dict_state.get_compiled_class_hash(class_hash)
            .or_else(|_| {
                // TODO: cache resulin self.dict_state
                self.rpc.get_compiled_class_hash(class_hash)
            })
    }
}


/// Reexecute the given transactions through Blockifier
pub fn reexecute_transactions_with_blockifier(
    mut state: CachedState<DictStateWithRpc>,
    block_context: &BlockContext,
    txs: Vec<Transaction>,
) -> Result<Vec<TransactionExecutionInfo>, Box<dyn Error>> {

    let tx_execution_infos = txs
        .into_iter()
        .map(|tx| {
            let tx_result = tx.execute(&mut state, block_context, true, true);
            return match tx_result {
                Err(e) => {
                    panic!("Transaction failed in blockifier: {}", e);
                }
                Ok(info) => {
                    if info.is_reverted() {
                        log::error!("Transaction reverted: {:?}", info.revert_error);
                        log::warn!("TransactionExecutionInfo: {:?}", info);
                        panic!("A transaction reverted during execution: {:?}", info);
                    }
                    info
                }
            };
        })
        .collect();

    Ok(tx_execution_infos)
}

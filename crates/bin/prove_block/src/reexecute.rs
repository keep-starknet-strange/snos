use std::error::Error;

use blockifier::context::BlockContext;
use blockifier::state::cached_state::CachedState;
use blockifier::state::errors::StateError;
use blockifier::state::state_api::{StateReader, StateResult};
use blockifier::transaction::objects::TransactionExecutionInfo;
use blockifier::transaction::transaction_execution::Transaction;
use blockifier::transaction::transactions::ExecutableTransaction as _;
use starknet::core::types::BlockId;
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Provider as _};
use starknet_api::core::{ClassHash, CompiledClassHash, Nonce, PatriciaKey};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;
use starknet_os::utils::{execute_coroutine, felt_api2vm, felt_vm2api};

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
            self.block_id,
        ))
        .map_err(|_| StateError::StateReadError("Error executing coroutine".to_string()))?
        .map_err(|rpc_error| StateError::StateReadError(format!("RPC Provider Error: {}", rpc_error)))?;

        Ok(felt_vm2api(value))
    }

    fn get_nonce_at(&mut self, contract_address: starknet_api::core::ContractAddress) -> StateResult<Nonce> {
        log::debug!("RpcStateReader::get_nonce_at()");
        let nonce = execute_coroutine(self.rpc_client.get_nonce(self.block_id, felt_api2vm(*contract_address.0.key())))
            .map_err(|_| StateError::StateReadError("Error executing coroutine".to_string()))?
            .map_err(|rpc_error| StateError::StateReadError(format!("RPC Provider Error: {}", rpc_error)))?;

        Ok(Nonce(felt_vm2api(nonce)))
    }

    fn get_compiled_contract_class(
        &mut self,
        class_hash: ClassHash,
    ) -> StateResult<blockifier::execution::contract_class::ContractClass> {
        log::debug!("RpcStateReader::get_compiled_contract_class()");
        let contract_class = execute_coroutine(self.rpc_client.get_class(self.block_id, felt_api2vm(class_hash.0)))
            .map_err(|_| StateError::StateReadError("Error executing coroutine".to_string()))?
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

                let casm_cc = cairo_lang_starknet_classes::casm_contract_class::CasmContractClass::from_contract_class(
                    sierra_cc.clone(),
                    false,
                    usize::MAX,
                )
                .unwrap();

                Ok(blockifier::execution::contract_class::ContractClass::V1(casm_cc.try_into().unwrap()))
            }
            starknet::core::types::ContractClass::Legacy(_compressed_logacy_contract_class) => {
                panic!("legacy class (TODO)");
            }
        }
    }

    fn get_class_hash_at(&mut self, contract_address: starknet_api::core::ContractAddress) -> StateResult<ClassHash> {
        log::debug!("RpcStateReader::get_class_hash_at()");
        let hash =
            execute_coroutine(self.rpc_client.get_class_hash_at(self.block_id, felt_api2vm(*contract_address.0.key())))
                .map_err(|_| StateError::StateReadError("Error executing coroutine".to_string()))?
                .map_err(|rpc_error| StateError::StateReadError(format!("RPC Provider Error: {}", rpc_error)))?;

        Ok(ClassHash(felt_vm2api(hash)))
    }

    fn get_compiled_class_hash(&mut self, class_hash: ClassHash) -> StateResult<starknet_api::core::CompiledClassHash> {
        log::debug!("RpcStateReader::get_compiled_class_hash()");
        // TODO: review, this seems to be what starknet_replay does...
        let contract_address = starknet_api::core::ContractAddress(PatriciaKey::try_from(class_hash.0).unwrap());
        let hash = self.get_class_hash_at(contract_address)?;
        Ok(CompiledClassHash(*hash))
    }
}

/// Reexecute the given transactions through Blockifier
pub fn reexecute_transactions_with_blockifier(
    mut state: CachedState<RpcStateReader>,
    block_context: &BlockContext,
    txs: Vec<Transaction>,
) -> Result<Vec<TransactionExecutionInfo>, Box<dyn Error>> {
    let tx_execution_infos = txs
        .into_iter()
        .map(|tx| {
            let tx_result = tx.execute(&mut state, block_context, true, true);
            match tx_result {
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
            }
        })
        .collect();

    Ok(tx_execution_infos)
}

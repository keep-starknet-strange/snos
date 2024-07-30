use std::collections::HashMap;
use std::error::Error;

use blockifier::{context::BlockContext, state::cached_state::CachedState, transaction::{account_transaction::AccountTransaction, objects::TransactionExecutionInfo, transaction_execution::Transaction, transactions::ExecutableTransaction as _}};
use cairo_lang_starknet_classes::casm_contract_class::CasmContractClass;
use starknet_os::{crypto::pedersen::PedersenHash, io::InternalTransaction, starknet::business_logic::fact_state::state::SharedState};
use starknet_api::{core::ClassHash, deprecated_contract_class::ContractClass as DeprecatedCompiledClass, transaction::Transaction as SNTransaction};

use crate::CachedRpcStorage;

/// Reexecute the given transactions through Blockifier
pub fn reexecute_transactions_with_blockifier(
    mut state: CachedState<SharedState<CachedRpcStorage, PedersenHash>>,
    block_context: &BlockContext,
    txs: Vec<Transaction>,
    deprecated_contract_classes: HashMap<ClassHash, DeprecatedCompiledClass>,
    contract_classes: HashMap<ClassHash, CasmContractClass>,
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

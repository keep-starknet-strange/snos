use std::error::Error;

use blockifier::context::BlockContext;
use blockifier::state::cached_state::CachedState;
use blockifier::state::state_api::StateReader;
use blockifier::transaction::objects::TransactionExecutionInfo;
use blockifier::transaction::transaction_execution::Transaction;
use blockifier::transaction::transactions::ExecutableTransaction;

/// Reexecute the given transactions through Blockifier
pub fn reexecute_transactions_with_blockifier<S: StateReader>(
    mut state: CachedState<S>,
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

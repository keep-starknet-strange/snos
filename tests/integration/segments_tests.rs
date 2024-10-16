use blockifier::context::BlockContext;
use blockifier::invoke_tx_args;
use blockifier::test_utils::{create_calldata, NonceManager};
use blockifier::transaction::test_utils;
use blockifier::transaction::test_utils::max_fee;
use blockifier::transaction::transaction_execution::Transaction;
use rstest::rstest;
use starknet_api::transaction::{Fee, TransactionVersion};

use crate::common::block_context;
use crate::common::state::{initial_state_syscalls, StarknetTestState};
use crate::common::transaction_utils::execute_txs_and_run_os;

#[rstest(
    tx_version => [TransactionVersion::ONE, TransactionVersion::THREE]
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_segment_arena(
    #[future] initial_state_syscalls: StarknetTestState,
    block_context: BlockContext,
    max_fee: Fee,
    tx_version: TransactionVersion,
) {
    use std::collections::HashMap;

    let initial_state = initial_state_syscalls.await;

    let mut nonce_manager = NonceManager::default();

    let sender_address = initial_state.deployed_cairo1_contracts.get("account_with_dummy_validate").unwrap().address;
    let test_contract = initial_state.deployed_cairo1_contracts.get("test_contract").unwrap();

    let contract_address = test_contract.address;

    let tx = test_utils::account_invoke_tx(invoke_tx_args! {
        max_fee,
        sender_address: sender_address,
        calldata: create_calldata(contract_address, "test_segment_arena", &[]),
        version: tx_version,
        nonce: nonce_manager.next(sender_address),
    });

    let txs = vec![Transaction::AccountTransaction(tx)];

    let (_pie, _os_output) = execute_txs_and_run_os(
        crate::common::DEFAULT_COMPILED_OS,
        initial_state.cached_state,
        block_context,
        txs,
        initial_state.cairo0_compiled_classes,
        initial_state.cairo1_compiled_classes,
        HashMap::default(),
    )
    .await
    .expect("OS run failed");
}

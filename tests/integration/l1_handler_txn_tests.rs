use std::sync::Arc;

use blockifier::abi::abi_utils::selector_from_name;
use blockifier::context::BlockContext;
use blockifier::transaction::test_utils::{block_context, max_fee};
use blockifier::transaction::transactions::L1HandlerTransaction;
use futures::Future;
use rstest::{fixture, rstest};
use starknet_api::core::{ContractAddress, EntryPointSelector};
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use starknet_api::transaction::{Calldata, Fee, TransactionVersion};

use crate::common::state::{init_logging, initial_state_cairo0, initial_state_syscalls, StarknetTestState};
use crate::common::transaction_utils::execute_txs_and_run_os;

#[fixture]
async fn l1_initial_state_cairo1(
    block_context: BlockContext,
    #[from(init_logging)] _logging: (),
) -> (StarknetTestState, ContractAddress) {
    let state = initial_state_syscalls(block_context, ()).await;
    let contract_address = state.deployed_cairo1_contracts.get("test_contract").unwrap().address;
    (state, contract_address)
}

#[fixture]
async fn l1_initial_state_cairo0(
    block_context: BlockContext,
    #[from(init_logging)] _logging: (),
) -> (StarknetTestState, ContractAddress) {
    let state = initial_state_cairo0(block_context, ()).await;
    let contract_address = state.deployed_cairo0_contracts.get("test_contract").unwrap().address;
    (state, contract_address)
}

#[rstest(
    initial_state => [l1_initial_state_cairo0, l1_initial_state_cairo1]
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn l1_handler<F>(
    initial_state: fn(blockifier::context::BlockContext, ()) -> F,
    block_context: BlockContext,
    max_fee: Fee,
) where
    F: Future<Output = (StarknetTestState, ContractAddress)>,
{
    let (initial_state, contract_address) = initial_state(block_context.clone(), ()).await;

    let tx_version = TransactionVersion::ZERO;

    let calldata_args = vec![stark_felt!(1234_u16), stark_felt!(42_u16)];
    let l1_tx = L1HandlerTransaction {
        paid_fee_on_l1: max_fee,
        tx: starknet_api::transaction::L1HandlerTransaction {
            contract_address,
            version: tx_version,
            entry_point_selector: EntryPointSelector(selector_from_name("l1_handle").0),
            calldata: Calldata(Arc::new(calldata_args)),
            ..Default::default()
        },
        tx_hash: Default::default(),
    };
    let txs = vec![l1_tx].into_iter().map(Into::into).collect();
    let _result = execute_txs_and_run_os(
        initial_state.cached_state,
        block_context,
        txs,
        initial_state.cairo0_compiled_classes,
        initial_state.cairo1_compiled_classes,
    )
    .await
    .expect("OS run failed");
}

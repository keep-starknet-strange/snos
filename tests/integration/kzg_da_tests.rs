use std::sync::Arc;

use blockifier::abi::abi_utils::selector_from_name;
use blockifier::context::BlockContext;
use blockifier::transaction::test_utils::max_fee;
use blockifier::transaction::transactions::L1HandlerTransaction;
use cairo_vm::Felt252;
use rstest::rstest;
use starknet_api::core::EntryPointSelector;
use starknet_api::transaction::{Calldata, Fee, TransactionVersion};

use crate::common::state::{initial_state_cairo0, initial_state_cairo1, StarknetTestState};
use crate::common::transaction_utils::execute_txs_and_run_os;

#[rstest]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_kzg_da_cairo_1(#[future] initial_state_cairo1: StarknetTestState, max_fee: Fee) {
    let initial_state = initial_state_cairo1.await;
    let tx_version = TransactionVersion::ZERO;
    let contract_address = initial_state.deployed_cairo0_contracts.get("test_contract").unwrap().address;
    let calldata_args = vec![Felt252::from(1234_u16), Felt252::from(42_u16)];
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
    let (_, output) = execute_txs_and_run_os(
        initial_state.cached_state,
        BlockContext::create_for_account_testing_with_kzg(true),
        txs,
        initial_state.cairo0_compiled_classes,
        initial_state.cairo1_compiled_classes,
    )
    .await
    .expect("OS run failed");
    assert!(output.use_kzg_da == Felt252::ONE);
}

#[rstest]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_kzg_da_cairo_0(#[future] initial_state_cairo0: StarknetTestState, max_fee: Fee) {
    let initial_state = initial_state_cairo0.await;
    let tx_version = TransactionVersion::ZERO;
    let contract_address = initial_state.deployed_cairo0_contracts.get("test_contract").unwrap().address;
    let calldata_args = vec![Felt252::from(1234_u16), Felt252::from(42_u16)];
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
    let (_, output) = execute_txs_and_run_os(
        initial_state.cached_state,
        BlockContext::create_for_account_testing_with_kzg(true),
        txs,
        initial_state.cairo0_compiled_classes,
        initial_state.cairo1_compiled_classes,
    )
    .await
    .expect("OS run failed");
    assert!(output.use_kzg_da == Felt252::ONE);
}

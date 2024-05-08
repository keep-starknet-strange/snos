use blockifier::block_context::BlockContext;
use blockifier::invoke_tx_args;
use blockifier::test_utils::contracts::FeatureContract;
use blockifier::test_utils::{create_calldata, CairoVersion, NonceManager};
use blockifier::transaction::test_utils;
use blockifier::transaction::test_utils::max_fee;
use rstest::rstest;
use snos::config::STORED_BLOCK_HASH_BUFFER;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use starknet_api::transaction::{Fee, TransactionVersion};

use crate::common::block_context;
use crate::common::state::{cairo0_initial_state, initial_state, Cairo0InitialState, InitialState};
use crate::common::transaction_utils::execute_txs_and_run_os;

#[rstest]
#[tokio::test]
async fn test_cairo0_state(#[future] cairo0_initial_state: Cairo0InitialState) {
    let cairo0_initial_state = cairo0_initial_state.await;

    println!("{}", serde_json::to_string(&cairo0_initial_state.contracts.test_contract).unwrap());
}

#[rstest]
fn return_result_cairo0_account(block_context: BlockContext, initial_state: InitialState, max_fee: Fee) {
    let tx_version = TransactionVersion::ZERO;
    let mut nonce_manager = NonceManager::default();

    let InitialState {
        state,
        account_without_validations_cairo0_address: sender_address,
        test_contract_cairo0_address: contract_address,
        ..
    } = initial_state;

    let return_result_tx = test_utils::account_invoke_tx(invoke_tx_args! {
        max_fee,
        sender_address,
        calldata: create_calldata(
            contract_address,
            "return_result",
            &[stark_felt!(2_u8)],
        ),
        version: tx_version,
        nonce: nonce_manager.next(sender_address),
    });

    let r = execute_txs_and_run_os(state, block_context, vec![return_result_tx]);

    // temporarily expect test to break in the descent code
    let err_log = format!("{:?}", r);
    assert!(err_log.contains(r#"Could not find commitment info for contract 1073742336"#), "{}", err_log);
}

#[rstest]
fn return_result_cairo1_account(block_context: BlockContext, initial_state: InitialState, max_fee: Fee) {
    let tx_version = TransactionVersion::ZERO;
    let mut nonce_manager = NonceManager::default();

    let InitialState {
        state,
        account_without_validations_cairo1_address: sender_address,
        test_contract_cairo0_address: contract_address,
        ..
    } = initial_state;

    let return_result_tx = test_utils::account_invoke_tx(invoke_tx_args! {
        max_fee,
        sender_address,
        calldata: create_calldata(
            contract_address,
            "return_result",
            &[stark_felt!(2_u8)],
        ),
        version: tx_version,
        nonce: nonce_manager.next(sender_address),
    });

    let r = execute_txs_and_run_os(state, block_context, vec![return_result_tx]);

    // temporarily expect test to break in the descent code
    let err_log = format!("{:?}", r);
    assert!(err_log.contains(r#"Could not find commitment info for contract 1073743616"#), "{}", err_log);
}

#[rstest]
fn syscalls_cairo1(block_context: BlockContext, initial_state: InitialState, max_fee: Fee) {
    let tx_version = TransactionVersion::ZERO;
    let mut nonce_manager = NonceManager::default();

    let InitialState {
        state,
        account_without_validations_cairo1_address: sender_address,
        test_contract_cairo1_address: contract_address,
        ..
    } = initial_state;

    // test_emit_event
    let keys = vec![stark_felt!(2019_u16), stark_felt!(2020_u16)];
    let data = vec![stark_felt!(2021_u16), stark_felt!(2022_u16), stark_felt!(2023_u16)];
    let entrypoint_args = &[
        vec![stark_felt!(u128::try_from(keys.len()).unwrap())],
        keys,
        vec![stark_felt!(u128::try_from(data.len()).unwrap())],
        data,
    ]
    .concat();

    let test_emit_event_tx = test_utils::account_invoke_tx(invoke_tx_args! {
        max_fee,
        sender_address: sender_address,
        calldata: create_calldata(contract_address, "test_emit_event", entrypoint_args),
        version: tx_version,
        nonce: nonce_manager.next(sender_address),
    });

    // test_storage_read_write
    let test_storage_read_write_tx = test_utils::account_invoke_tx(invoke_tx_args! {
        max_fee,
        sender_address: sender_address,
        calldata: create_calldata(contract_address, "test_storage_read_write", &[StarkFelt::TWO, StarkFelt::ONE]),
        version: tx_version,
        nonce: nonce_manager.next(sender_address),
    });

    // test_get_block_hash
    let test_get_block_hash_tx = test_utils::account_invoke_tx(invoke_tx_args! {
        max_fee,
        sender_address: sender_address,
        calldata: create_calldata(contract_address, "test_get_block_hash", &[stark_felt!(block_context.block_number.0 - STORED_BLOCK_HASH_BUFFER)]),
        version: tx_version,
        nonce: nonce_manager.next(sender_address),
    });

    // test_send_message_to_l1
    let to_address = stark_felt!(1234_u16);
    let payload = vec![stark_felt!(2019_u16), stark_felt!(2020_u16), stark_felt!(2021_u16)];
    let entrypoint_args = &[vec![to_address, stark_felt!(payload.len() as u64)], payload].concat();

    let test_send_message_to_l1_tx = test_utils::account_invoke_tx(invoke_tx_args! {
        max_fee,
        sender_address: sender_address,
        calldata: create_calldata(contract_address, "test_send_message_to_l1", entrypoint_args),
        version: tx_version,
        nonce: nonce_manager.next(sender_address),
    });

    // test_deploy
    let test_contract_class_hash = FeatureContract::TestContract(CairoVersion::Cairo1).get_class_hash().0;
    let entrypoint_args = &[
        test_contract_class_hash, // class hash
        stark_felt!(255_u8),      // contract_address_salt
        stark_felt!(2_u8),        // calldata length
        stark_felt!(3_u8),        // calldata: arg1
        stark_felt!(3_u8),        // calldata: arg2
        stark_felt!(0_u8),        // deploy_from_zero
    ];

    let test_deploy_tx = test_utils::account_invoke_tx(invoke_tx_args! {
        max_fee,
        sender_address: sender_address,
        calldata: create_calldata(contract_address, "test_deploy", entrypoint_args),
        version: tx_version,
        nonce: nonce_manager.next(sender_address),
    });

    let txs = vec![
        test_emit_event_tx,
        test_storage_read_write_tx,
        test_get_block_hash_tx,
        test_send_message_to_l1_tx,
        test_deploy_tx,
    ];

    let r = execute_txs_and_run_os(state, block_context, txs);

    // temporarily expect test to break in the descent code
    let err_log = format!("{:?}", r);
    assert!(err_log.contains(r#"Could not find commitment info for contract 3221225984"#), "{}", err_log);
}

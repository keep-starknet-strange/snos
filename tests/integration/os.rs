use blockifier::block_context::BlockContext;
use blockifier::invoke_tx_args;
use blockifier::test_utils::{create_calldata, NonceManager};
use blockifier::transaction::test_utils;
use blockifier::transaction::test_utils::max_fee;
use rstest::rstest;
use snos::config::STORED_BLOCK_HASH_BUFFER;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use starknet_api::transaction::{Fee, TransactionVersion};

use crate::common::block_context;
use crate::common::state::{initial_state, InitialState};
use crate::common::transaction_utils::execute_txs_and_run_os;

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

    // temporarily expect test to break somewhere in the state_update function
    assert!(&format!("{:?}", r).contains(r#"AssertionFailed("Tree height does not match Merkle height")))"#));
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

    // temporarily expect test to break somewhere in the state_update function
    assert!(&format!("{:?}", r).contains(r#"AssertionFailed("Tree height does not match Merkle height")))"#));
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

    let txs = vec![test_emit_event_tx, test_storage_read_write_tx, test_get_block_hash_tx, test_send_message_to_l1_tx];

    let r = execute_txs_and_run_os(state, block_context, txs);

    // temporarily expect test to break somewhere in the state_update function
    assert!(&format!("{:?}", r).contains(r#"CustomHint("Storage not found for contract 3221227264")"#));
}

use blockifier::abi::abi_utils::selector_from_name;
use blockifier::context::BlockContext;
use blockifier::invoke_tx_args;
use blockifier::test_utils::invoke::invoke_tx;
use blockifier::test_utils::{create_calldata, NonceManager};
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::test_utils;
use blockifier::transaction::test_utils::max_fee;
use rstest::rstest;
use snos::config::SN_GOERLI;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use starknet_api::transaction::{Fee, TransactionHash, TransactionVersion};

use crate::common::block_context;
use crate::common::state::{initial_state_cairo1, initial_state_syscalls, StarknetTestState};
use crate::common::transaction_utils::execute_txs_and_run_os;

#[rstest]
// We need to use the multi_thread runtime to use task::block_in_place for sync -> async calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_syscall_library_call_cairo0(
    #[future] initial_state_cairo1: StarknetTestState,
    block_context: BlockContext,
    max_fee: Fee,
) {
    let initial_state = initial_state_cairo1.await;

    let tx_version = TransactionVersion::ZERO;
    let mut nonce_manager = NonceManager::default();

    let sender_address = initial_state.cairo1_contracts.get("account_with_dummy_validate").unwrap().address;
    let test_contract = initial_state.cairo0_contracts.get("test_contract").unwrap();

    let contract_address = test_contract.address;

    // Call the `return_result` method of the test contract class,
    // i.e. the test contract will call its own class.
    let test_contract_class_hash = test_contract.class_hash;
    let selector_felt = selector_from_name("return_result");

    let return_result_calldata = vec![stark_felt!(1u128), stark_felt!(42u128)];

    let entrypoint_args = &[vec![test_contract_class_hash.0], vec![selector_felt.0], return_result_calldata].concat();

    log::debug!("Entrypoint args: {entrypoint_args:?}");

    let tx = test_utils::account_invoke_tx(invoke_tx_args! {
        max_fee,
        sender_address: sender_address,
        calldata: create_calldata(contract_address, "test_library_call", entrypoint_args),
        version: tx_version,
        nonce: nonce_manager.next(sender_address),
    });

    let txs = vec![tx];

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

#[rstest]
// We need to use the multi_thread runtime to use task::block_in_place for sync -> async calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_syscall_library_call_cairo1(
    #[future] initial_state_syscalls: StarknetTestState,
    block_context: BlockContext,
    max_fee: Fee,
) {
    let initial_state = initial_state_syscalls.await;

    let tx_version = TransactionVersion::ZERO;
    let mut nonce_manager = NonceManager::default();

    let sender_address = initial_state.cairo1_contracts.get("account_with_dummy_validate").unwrap().address;
    let test_contract = initial_state.cairo1_contracts.get("test_contract").unwrap();

    let contract_address = test_contract.address;

    // Call the `return_result` method of the test contract class,
    // i.e. the test contract will call its own class.
    let test_contract_class_hash = test_contract.class_hash;
    let selector_felt = selector_from_name("recurse");

    let return_result_calldata = vec![stark_felt!(1u128), stark_felt!(42u128)];

    let entrypoint_args = &[vec![test_contract_class_hash.0], vec![selector_felt.0], return_result_calldata].concat();

    log::debug!("Entrypoint args: {entrypoint_args:?}");

    let tx = test_utils::account_invoke_tx(invoke_tx_args! {
        max_fee,
        sender_address: sender_address,
        calldata: create_calldata(contract_address, "test_library_call", entrypoint_args),
        version: tx_version,
        nonce: nonce_manager.next(sender_address),
    });

    let txs = vec![tx];

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

#[rstest]
// We need to use the multi_thread runtime to use task::block_in_place for sync -> async calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_syscall_get_block_number_cairo0(
    #[future] initial_state_cairo1: StarknetTestState,
    block_context: BlockContext,
    max_fee: Fee,
) {
    let initial_state = initial_state_cairo1.await;

    let sender_address = initial_state.cairo1_contracts.get("account_with_dummy_validate").unwrap().address;
    let contract_address = initial_state.cairo0_contracts.get("test_contract").unwrap().address;

    let expected_block_number = stark_felt!(block_context.block_info().block_number.0);

    let tx_version = TransactionVersion::ZERO;
    let mut nonce_manager = NonceManager::default();
    let tx = test_utils::account_invoke_tx(invoke_tx_args! {
        max_fee,
        sender_address: sender_address,
        calldata: create_calldata(contract_address, "test_get_block_number", &[expected_block_number]),
        version: tx_version,
        nonce: nonce_manager.next(sender_address),
    });

    let txs = vec![tx];

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

#[rstest]
// We need to use the multi_thread runtime to use task::block_in_place for sync -> async calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_syscall_get_block_timestamp_cairo0(
    #[future] initial_state_cairo1: StarknetTestState,
    block_context: BlockContext,
    max_fee: Fee,
) {
    let initial_state = initial_state_cairo1.await;

    let sender_address = initial_state.cairo1_contracts.get("account_with_dummy_validate").unwrap().address;
    let contract_address = initial_state.cairo0_contracts.get("test_contract").unwrap().address;

    let expected_block_timestamp = stark_felt!(block_context.block_info().block_timestamp.0);

    let tx_version = TransactionVersion::ZERO;
    let mut nonce_manager = NonceManager::default();
    let tx = test_utils::account_invoke_tx(invoke_tx_args! {
        max_fee,
        sender_address: sender_address,
        calldata: create_calldata(contract_address, "test_get_block_timestamp", &[expected_block_timestamp]),
        version: tx_version,
        nonce: nonce_manager.next(sender_address),
    });

    let txs = vec![tx];

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

#[rstest]
// We need to use the multi_thread runtime to use task::block_in_place for sync -> async calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_syscall_get_tx_info_cairo0(
    #[future] initial_state_cairo1: StarknetTestState,
    block_context: BlockContext,
    max_fee: Fee,
) {
    let initial_state = initial_state_cairo1.await;

    let sender_address = initial_state.cairo1_contracts.get("account_with_dummy_validate").unwrap().address;
    let contract_address = initial_state.cairo0_contracts.get("test_contract").unwrap().address;

    let tx_version = TransactionVersion::ZERO;

    let expected_chain_id = stark_felt!(SN_GOERLI);

    let mut nonce_manager = NonceManager::default();
    let nonce = nonce_manager.next(sender_address);

    // Note: we use `test_get_tx_info_no_tx_hash_check()` instead of `test_get_tx_info()`
    // because it is pretty much impossible to generate a tx whose hash is equal to the expected
    // hash that must be set in the calldata.
    let tx = {
        let mut invoke_tx = invoke_tx(invoke_tx_args! {
            max_fee,
            sender_address: sender_address,
            calldata: create_calldata(contract_address, "test_get_tx_info_no_tx_hash_check", &[
                tx_version.0, // expected version
                sender_address.0.key().clone(), // expected contract address
                stark_felt!(max_fee.0), // expected max fee
                expected_chain_id, // expected chain ID
                nonce.0, // expected nonce
            ]),
            version: tx_version,
            nonce,
        });
        // Blockifier does not compute tx hashes. Insert the correct tx hash here to make
        // the storage updates match between Blockifier and the OS.
        invoke_tx.tx_hash = TransactionHash(
            StarkFelt::try_from("0x8704f5e69650b81810a420373c21885aa6e75a8c46e34095e12a2a5231815f").unwrap(),
        );
        AccountTransaction::Invoke(invoke_tx)
    };

    let txs = vec![tx];

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

#[rstest]
// We need to use the multi_thread runtime to use task::block_in_place for sync -> async calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_syscall_get_tx_signature_cairo0(
    #[future] initial_state_cairo1: StarknetTestState,
    block_context: BlockContext,
    max_fee: Fee,
) {
    let initial_state = initial_state_cairo1.await;

    let sender_address = initial_state.cairo1_contracts.get("account_with_dummy_validate").unwrap().address;
    let contract_address = initial_state.cairo0_contracts.get("test_contract").unwrap().address;

    let tx_version = TransactionVersion::ZERO;

    let mut nonce_manager = NonceManager::default();

    let tx = test_utils::account_invoke_tx(invoke_tx_args! {
        max_fee,
        sender_address: sender_address,
        calldata: create_calldata(contract_address, "test_get_tx_signature", &[]),
        version: tx_version,
        nonce: nonce_manager.next(sender_address),
    });

    let txs = vec![tx];

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

#[rstest]
// We need to use the multi_thread runtime to use task::block_in_place for sync -> async calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_syscall_replace_class_cairo0(
    #[future] initial_state_cairo1: StarknetTestState,
    block_context: BlockContext,
    max_fee: Fee,
) {
    let initial_state = initial_state_cairo1.await;

    let sender_address = initial_state.cairo1_contracts.get("account_with_dummy_validate").unwrap().address;
    let test_contract = initial_state.cairo0_contracts.get("test_contract").unwrap();
    let contract_address = test_contract.address;

    let tx_version = TransactionVersion::ZERO;

    // We just test that the replace_class syscall goes through. Just use the same class hash.
    let class_hash = test_contract.class_hash;

    let mut nonce_manager = NonceManager::default();
    let tx = test_utils::account_invoke_tx(invoke_tx_args! {
        max_fee,
        sender_address: sender_address,
        calldata: create_calldata(contract_address, "test_replace_class", &[class_hash.0]),
        version: tx_version,
        nonce: nonce_manager.next(sender_address),
    });

    let txs = vec![tx];

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

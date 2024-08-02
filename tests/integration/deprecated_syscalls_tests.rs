//! Tests for syscalls, based on the test contracts (Cairo 0 & 1) from Blockifier.
//! These contracts are built in a way that each entrypoint calls a specific syscall, performs
//! some validation and returns.
//!
//! Each test in this file calls a single entrypoint and returns to test syscalls individually.

use std::collections::HashMap;

use blockifier::abi::abi_utils::selector_from_name;
use blockifier::context::BlockContext;
use blockifier::invoke_tx_args;
use blockifier::test_utils::invoke::invoke_tx;
use blockifier::test_utils::{create_calldata, NonceManager};
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::test_utils;
use blockifier::transaction::test_utils::max_fee;
use blockifier::transaction::transaction_execution::Transaction;
use cairo_vm::Felt252;
use num_traits::ToPrimitive;
use rstest::rstest;
use starknet_api::core::calculate_contract_address;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use starknet_api::transaction::{Calldata, ContractAddressSalt, Fee, TransactionHash, TransactionVersion};
use starknet_os::config::SN_GOERLI;
use starknet_os::utils::felt_api2vm;

use crate::common::block_context;
use crate::common::state::{initial_state_cairo0, StarknetTestState};
use crate::common::transaction_utils::execute_txs_and_run_os;
use crate::common::utils::check_os_output_read_only_syscall;

#[rstest]
// We need to use the multi_thread runtime to use task::block_in_place for sync -> async calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_syscall_library_call_cairo0(
    #[future] initial_state_cairo0: StarknetTestState,
    block_context: BlockContext,
    max_fee: Fee,
) {
    let initial_state = initial_state_cairo0.await;

    let tx_version = TransactionVersion::ZERO;
    let mut nonce_manager = NonceManager::default();

    let sender_address = initial_state.deployed_cairo0_contracts.get("account_with_dummy_validate").unwrap().address;
    let test_contract = initial_state.deployed_cairo0_contracts.get("test_contract").unwrap();

    let contract_address = test_contract.address;

    // Call the `return_result` method of the test contract class,
    // i.e. the test contract will call its own class.
    let test_contract_class_hash = test_contract.declaration.class_hash;
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

    let txs = vec![Transaction::AccountTransaction(tx)];

    let (_pie, os_output) = execute_txs_and_run_os(
        initial_state.cached_state,
        block_context.clone(),
        txs,
        initial_state.cairo0_compiled_classes,
        initial_state.cairo1_compiled_classes,
    )
    .await
    .expect("OS run failed");

    check_os_output_read_only_syscall(os_output, block_context);
}

#[rstest]
// We need to use the multi_thread runtime to use task::block_in_place for sync -> async calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_syscall_get_block_number_cairo0(
    #[future] initial_state_cairo0: StarknetTestState,
    block_context: BlockContext,
    max_fee: Fee,
) {
    let initial_state = initial_state_cairo0.await;

    let sender_address = initial_state.deployed_cairo0_contracts.get("account_with_dummy_validate").unwrap().address;
    let contract_address = initial_state.deployed_cairo0_contracts.get("test_contract").unwrap().address;

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

    let txs = vec![Transaction::AccountTransaction(tx)];

    let (_pie, os_output) = execute_txs_and_run_os(
        initial_state.cached_state,
        block_context.clone(),
        txs,
        initial_state.cairo0_compiled_classes,
        initial_state.cairo1_compiled_classes,
    )
    .await
    .expect("OS run failed");

    check_os_output_read_only_syscall(os_output, block_context);
}

#[rstest]
// We need to use the multi_thread runtime to use task::block_in_place for sync -> async calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_syscall_get_block_timestamp_cairo0(
    #[future] initial_state_cairo0: StarknetTestState,
    block_context: BlockContext,
    max_fee: Fee,
) {
    let initial_state = initial_state_cairo0.await;

    let sender_address = initial_state.deployed_cairo0_contracts.get("account_with_dummy_validate").unwrap().address;
    let contract_address = initial_state.deployed_cairo0_contracts.get("test_contract").unwrap().address;

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

    let txs = vec![Transaction::AccountTransaction(tx)];

    let (_pie, os_output) = execute_txs_and_run_os(
        initial_state.cached_state,
        block_context.clone(),
        txs,
        initial_state.cairo0_compiled_classes,
        initial_state.cairo1_compiled_classes,
    )
    .await
    .expect("OS run failed");

    check_os_output_read_only_syscall(os_output, block_context);
}

#[rstest]
// We need to use the multi_thread runtime to use task::block_in_place for sync -> async calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_syscall_get_tx_info_cairo0(
    #[future] initial_state_cairo0: StarknetTestState,
    block_context: BlockContext,
    max_fee: Fee,
) {
    let initial_state = initial_state_cairo0.await;

    let sender_address = initial_state.deployed_cairo0_contracts.get("account_with_dummy_validate").unwrap().address;
    let contract_address = initial_state.deployed_cairo0_contracts.get("test_contract").unwrap().address;

    let tx_version = TransactionVersion::ZERO;

    let expected_chain_id = stark_felt!(SN_GOERLI);

    let mut nonce_manager = NonceManager::default();
    let nonce = nonce_manager.next(sender_address);

    // Note: we use `test_get_tx_info_no_tx_hash_check()` instead of `test_get_tx_info()`
    // because it is pretty much impossible to generate a tx whose hash is equal to the expected
    // hash that must be set in the calldata.
    let tx_hash = TransactionHash(
        StarkFelt::try_from("0x8704f5e69650b81810a420373c21885aa6e75a8c46e34095e12a2a5231815f").unwrap(),
    );
    let tx = {
        let mut invoke_tx = invoke_tx(invoke_tx_args! {
            max_fee,
            sender_address: sender_address,
            calldata: create_calldata(contract_address, "test_get_tx_info_no_tx_hash_check", &[
                tx_version.0, // expected version
                *sender_address.key(), // expected contract address
                stark_felt!(max_fee.0), // expected max fee
                expected_chain_id, // expected chain ID
                nonce.0, // expected nonce
            ]),
            version: tx_version,
            nonce,
        });
        // Blockifier does not compute tx hashes. Insert the correct tx hash here to make
        // the storage updates match between Blockifier and the OS.
        invoke_tx.tx_hash = tx_hash;
        AccountTransaction::Invoke(invoke_tx)
    };

    let txs = vec![Transaction::AccountTransaction(tx)];

    let (_pie, os_output) = execute_txs_and_run_os(
        initial_state.cached_state,
        block_context.clone(),
        txs,
        initial_state.cairo0_compiled_classes,
        initial_state.cairo1_compiled_classes,
    )
    .await
    .expect("OS run failed");

    // This test causes storage changes in the test contract. Check them.
    let contract_changes_by_address: HashMap<_, _> =
        os_output.contracts.iter().map(|change| (change.addr, change)).collect();
    let test_contract_changes = contract_changes_by_address
        .get(&felt_api2vm(*contract_address.0.key()))
        .expect("The test contract should appear as modified in the OS output");

    // Values based on the code of `test_contract.cairo`.
    // Note that if the nonce is 0 it will not appear as a change, so check for that.
    let expected_storage_changes = {
        let mut changes = HashMap::from([
            (Felt252::from(300), felt_api2vm(tx_hash.0)),
            (Felt252::from(311), felt_api2vm(expected_chain_id)),
        ]);

        if nonce.0 != StarkFelt::ZERO {
            changes.insert(Felt252::from(322), felt_api2vm(nonce.0));
        }
        changes
    };
    assert_eq!(test_contract_changes.storage_changes, expected_storage_changes);
}

#[rstest]
// We need to use the multi_thread runtime to use task::block_in_place for sync -> async calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_syscall_get_tx_signature_cairo0(
    #[future] initial_state_cairo0: StarknetTestState,
    block_context: BlockContext,
    max_fee: Fee,
) {
    let initial_state = initial_state_cairo0.await;

    let sender_address = initial_state.deployed_cairo0_contracts.get("account_with_dummy_validate").unwrap().address;
    let contract_address = initial_state.deployed_cairo0_contracts.get("test_contract").unwrap().address;

    let tx_version = TransactionVersion::ZERO;

    let mut nonce_manager = NonceManager::default();

    let tx = test_utils::account_invoke_tx(invoke_tx_args! {
        max_fee,
        sender_address: sender_address,
        calldata: create_calldata(contract_address, "test_get_tx_signature", &[]),
        version: tx_version,
        nonce: nonce_manager.next(sender_address),
    });

    let txs = vec![Transaction::AccountTransaction(tx)];

    let (_pie, os_output) = execute_txs_and_run_os(
        initial_state.cached_state,
        block_context.clone(),
        txs,
        initial_state.cairo0_compiled_classes,
        initial_state.cairo1_compiled_classes,
    )
    .await
    .expect("OS run failed");

    check_os_output_read_only_syscall(os_output, block_context);
}

#[rstest]
// We need to use the multi_thread runtime to use task::block_in_place for sync -> async calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_syscall_replace_class_cairo0(
    #[future] initial_state_cairo0: StarknetTestState,
    block_context: BlockContext,
    max_fee: Fee,
) {
    let initial_state = initial_state_cairo0.await;

    let sender_address = initial_state.deployed_cairo0_contracts.get("account_with_dummy_validate").unwrap().address;
    let test_contract = initial_state.deployed_cairo0_contracts.get("test_contract").unwrap();
    let contract_address = test_contract.address;

    let tx_version = TransactionVersion::ZERO;

    // We just test that the replace_class syscall goes through. Just use the same class hash.
    let class_hash = test_contract.declaration.class_hash;

    let mut nonce_manager = NonceManager::default();
    let tx = test_utils::account_invoke_tx(invoke_tx_args! {
        max_fee,
        sender_address: sender_address,
        calldata: create_calldata(contract_address, "test_replace_class", &[class_hash.0]),
        version: tx_version,
        nonce: nonce_manager.next(sender_address),
    });

    let txs = vec![Transaction::AccountTransaction(tx)];

    // TODO: use a different class hash and check that it is reflected in the OS output.
    let (_pie, _os_output) = execute_txs_and_run_os(
        initial_state.cached_state,
        block_context.clone(),
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
async fn test_syscall_deploy_cairo0(
    #[future] initial_state_cairo0: StarknetTestState,
    block_context: BlockContext,
    max_fee: Fee,
) {
    let initial_state = initial_state_cairo0.await;

    let sender_address = initial_state.deployed_cairo0_contracts.get("account_with_dummy_validate").unwrap().address;
    let test_contract = initial_state.deployed_cairo0_contracts.get("test_contract").unwrap();
    let contract_address = test_contract.address;

    let tx_version = TransactionVersion::ZERO;

    let class_hash = test_contract.declaration.class_hash;

    let contract_address_salt = ContractAddressSalt::default();
    let constructor_args = vec![StarkFelt::from(100u64), StarkFelt::from(200u64)];
    let test_deploy_args = &[
        vec![class_hash.0, contract_address_salt.0],
        vec![StarkFelt::from(constructor_args.len() as u64)],
        constructor_args.clone(),
        vec![StarkFelt::ZERO],
    ]
    .concat();

    let expected_contract_address = calculate_contract_address(
        contract_address_salt,
        test_contract.declaration.class_hash,
        &Calldata(constructor_args.into()),
        contract_address,
    )
    .unwrap();

    let mut nonce_manager = NonceManager::default();
    let tx = test_utils::account_invoke_tx(invoke_tx_args! {
        max_fee,
        sender_address: sender_address,
        calldata: create_calldata(contract_address, "test_deploy", test_deploy_args),
        version: tx_version,
        nonce: nonce_manager.next(sender_address),
    });

    let txs = vec![Transaction::AccountTransaction(tx)];

    let (_pie, os_output) = execute_txs_and_run_os(
        initial_state.cached_state,
        block_context.clone(),
        txs,
        initial_state.cairo0_compiled_classes,
        initial_state.cairo1_compiled_classes,
    )
    .await
    .expect("OS run failed");

    // Check that the new contract address appears in the OS output
    let contract_changes_by_address: HashMap<_, _> =
        os_output.contracts.iter().map(|change| (change.addr, change)).collect();
    assert!(contract_changes_by_address.contains_key(&felt_api2vm(*expected_contract_address.key())));

    // Check other output fields
    assert_eq!(os_output.block_number.to_u64().unwrap(), block_context.block_info().block_number.0);
    assert!(os_output.classes.is_empty());
    assert!(os_output.messages_to_l1.is_empty());
    assert!(os_output.messages_to_l2.is_empty());
    let use_kzg_da = os_output.use_kzg_da != Felt252::ZERO;
    assert_eq!(use_kzg_da, block_context.block_info().use_kzg_da);
}

#[rstest]
// We need to use the multi_thread runtime to use task::block_in_place for sync -> async calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_syscall_get_sequencer_address_cairo0(
    #[future] initial_state_cairo0: StarknetTestState,
    block_context: BlockContext,
    max_fee: Fee,
) {
    let initial_state = initial_state_cairo0.await;

    let sender_address = initial_state.deployed_cairo0_contracts.get("account_with_dummy_validate").unwrap().address;
    let contract_address = initial_state.deployed_cairo0_contracts.get("test_contract").unwrap().address;

    let tx_version = TransactionVersion::ZERO;
    let expected_sequencer_address = block_context.block_info().sequencer_address;

    let mut nonce_manager = NonceManager::default();
    let tx = test_utils::account_invoke_tx(invoke_tx_args! {
        max_fee,
        sender_address: sender_address,
        calldata: create_calldata(contract_address, "test_get_sequencer_address", &[*expected_sequencer_address.0.key()]),
        version: tx_version,
        nonce: nonce_manager.next(sender_address),
    });

    let txs = vec![Transaction::AccountTransaction(tx)];

    let (_pie, os_output) = execute_txs_and_run_os(
        initial_state.cached_state,
        block_context.clone(),
        txs,
        initial_state.cairo0_compiled_classes,
        initial_state.cairo1_compiled_classes,
    )
    .await
    .expect("OS run failed");

    check_os_output_read_only_syscall(os_output, block_context);
}

#[rstest]
// We need to use the multi_thread runtime to use task::block_in_place for sync -> async calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_syscall_get_contract_address_cairo0(
    #[future] initial_state_cairo0: StarknetTestState,
    block_context: BlockContext,
    max_fee: Fee,
) {
    let initial_state = initial_state_cairo0.await;

    let sender_address = initial_state.deployed_cairo0_contracts.get("account_with_dummy_validate").unwrap().address;
    let test_contract = initial_state.deployed_cairo0_contracts.get("test_contract").unwrap();
    let contract_address = test_contract.address;

    let class_hash = test_contract.declaration.class_hash;

    let contract_address_salt = ContractAddressSalt::default();
    let constructor_args = vec![StarkFelt::from(100u64), StarkFelt::from(200u64)];

    // Build the args required for calling test_contract_address. Check the Cairo code for
    // more details.
    let test_contract_address_args = &[
        vec![contract_address_salt.0, class_hash.0],
        vec![StarkFelt::from(constructor_args.len() as u64)],
        constructor_args.clone(),
        vec![StarkFelt::ZERO], // deployer_address
    ]
    .concat();

    let tx_version = TransactionVersion::ZERO;

    let mut nonce_manager = NonceManager::default();
    let tx = test_utils::account_invoke_tx(invoke_tx_args! {
        max_fee,
        sender_address: sender_address,
        calldata: create_calldata(contract_address, "test_contract_address", test_contract_address_args),
        version: tx_version,
        nonce: nonce_manager.next(sender_address),
    });

    let txs = vec![Transaction::AccountTransaction(tx)];

    let (_pie, os_output) = execute_txs_and_run_os(
        initial_state.cached_state,
        block_context.clone(),
        txs,
        initial_state.cairo0_compiled_classes,
        initial_state.cairo1_compiled_classes,
    )
    .await
    .expect("OS run failed");

    // The way tests are structured, we cannot check the result of the tx directly.
    // We can only verify that the syscall is implemented and goes through.
    check_os_output_read_only_syscall(os_output, block_context);
}

#[rstest]
// We need to use the multi_thread runtime to use task::block_in_place for sync -> async calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_syscall_emit_event_cairo0(
    #[future] initial_state_cairo0: StarknetTestState,
    block_context: BlockContext,
    max_fee: Fee,
) {
    let initial_state = initial_state_cairo0.await;

    let sender_address = initial_state.deployed_cairo0_contracts.get("account_with_dummy_validate").unwrap().address;
    let test_contract = initial_state.deployed_cairo0_contracts.get("test_contract").unwrap();
    let contract_address = test_contract.address;

    let tx_version = TransactionVersion::ZERO;
    let keys = vec![stark_felt!(2019_u16), stark_felt!(2020_u16)];
    let data = vec![stark_felt!(2021_u16), stark_felt!(2022_u16), stark_felt!(2023_u16)];
    let entrypoint_args = &[
        vec![stark_felt!(u128::try_from(keys.len()).unwrap())],
        keys,
        vec![stark_felt!(u128::try_from(data.len()).unwrap())],
        data,
    ]
    .concat();

    let mut nonce_manager = NonceManager::default();
    let tx = test_utils::account_invoke_tx(invoke_tx_args! {
        max_fee,
        sender_address: sender_address,
        calldata: create_calldata(contract_address, "test_emit_event", entrypoint_args),
        version: tx_version,
        nonce: nonce_manager.next(sender_address),
    });

    let txs = vec![Transaction::AccountTransaction(tx)];

    let (_pie, _os_output) = execute_txs_and_run_os(
        initial_state.cached_state,
        block_context.clone(),
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
async fn test_syscall_send_message_to_l1_cairo0(
    #[future] initial_state_cairo0: StarknetTestState,
    block_context: BlockContext,
    max_fee: Fee,
) {
    let initial_state = initial_state_cairo0.await;

    let sender_address = initial_state.deployed_cairo0_contracts.get("account_with_dummy_validate").unwrap().address;
    let test_contract = initial_state.deployed_cairo0_contracts.get("test_contract").unwrap();
    let contract_address = test_contract.address;

    // test constants
    const ADDRESS: u64 = 1298;
    const PAYLOAD_SIZE: u64 = 2;
    const PAYLOAD_1: u64 = 12;
    const PAYLOAD_2: u64 = 34;

    let tx_version = TransactionVersion::ZERO;
    let to_address = stark_felt!(ADDRESS);

    let entrypoint_args = &[vec![to_address]].concat();

    let mut nonce_manager = NonceManager::default();
    let tx = test_utils::account_invoke_tx(invoke_tx_args! {
        max_fee,
        sender_address: sender_address,
        calldata: create_calldata(contract_address, "send_message", entrypoint_args),
        version: tx_version,
        nonce: nonce_manager.next(sender_address),
    });

    let txs = vec![Transaction::AccountTransaction(tx)];
    let (_pie, os_output) = execute_txs_and_run_os(
        initial_state.cached_state,
        block_context.clone(),
        txs,
        initial_state.cairo0_compiled_classes,
        initial_state.cairo1_compiled_classes,
    )
    .await
    .expect("OS run failed");
    let output = os_output.messages_to_l1;

    let expected: [Felt252; 5] = [
        felt_api2vm(*contract_address.0.key()),
        ADDRESS.into(),
        PAYLOAD_SIZE.into(),
        PAYLOAD_1.into(),
        PAYLOAD_2.into(),
    ];
    assert_eq!(&*output, expected);
}

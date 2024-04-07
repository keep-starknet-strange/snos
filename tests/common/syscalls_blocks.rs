use blockifier::block_context::BlockContext;
use blockifier::invoke_tx_args;
use blockifier::test_utils::contracts::FeatureContract;
use blockifier::test_utils::{create_calldata, CairoVersion, NonceManager, BALANCE};
use blockifier::transaction::objects::FeeType;
use blockifier::transaction::test_utils;
use blockifier::transaction::test_utils::max_fee;
use blockifier::transaction::transactions::ExecutableTransaction;
use rstest::fixture;
use snos::execution::helper::ExecutionHelperWrapper;
use snos::io::input::StarknetOsInput;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use starknet_api::transaction::{Fee, TransactionVersion};

use crate::common::block_utils::{copy_state, os_hints, test_state};
use crate::common::blocks::block_context;
use crate::common::transaction_utils::{to_felt252, to_internal_tx};

#[fixture]
pub fn cairo1_syscalls_block(
    block_context: BlockContext,
    max_fee: Fee,
    #[default(TransactionVersion::ZERO)] tx_version: TransactionVersion,
    #[default(false)] only_query: bool,
) -> (StarknetOsInput, ExecutionHelperWrapper) {
    let account = FeatureContract::AccountWithoutValidations(CairoVersion::Cairo1);
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo1);
    let erc20 = FeatureContract::ERC20;

    let mut state = test_state(&block_context, BALANCE, &[(account, 1), (erc20, 1), (test_contract, 1)]);

    let account_address = account.get_instance_address(0);
    let contract_address = test_contract.get_instance_address(0);
    let mut nonce_manager = NonceManager::default();

    println!("contract addresses:");
    println!("\terc20(eth): {}", to_felt252(block_context.fee_token_address(&FeeType::Eth).0.key()));
    println!("\terc20(strk): {}", to_felt252(block_context.fee_token_address(&FeeType::Strk).0.key()));
    println!("\taccount: {}", to_felt252(account_address.0.key()));
    println!("\tcontract: {}", to_felt252(contract_address.0.key()));

    // TODO: use following test methods to test syscalls as soon as they are implemented
    // test_emit_event
    // test_storage_read_write
    // test_call_contract
    // test_get_block_hash
    // test_get_execution_info
    // test_library_call
    // test_nested_library_call
    // test_replace_class
    // test_send_message_to_l1
    // test_deploy
    // test_keccak
    // test_secp256k1
    // get_message_and_secp256k1_signature
    // test_secp256r1
    // get_message_and_secp256r1_signature

    let keys = vec![stark_felt!(2019_u16), stark_felt!(2020_u16)];
    let data = vec![stark_felt!(2021_u16), stark_felt!(2022_u16), stark_felt!(2023_u16)];
    let entrypoint_args = &[
        vec![stark_felt!(u128::try_from(keys.len()).expect("Failed to convert usize to u16."))],
        keys,
        vec![stark_felt!(u128::try_from(data.len()).expect("Failed to convert usize to u16."))],
        data,
    ]
    .concat();

    let test_emit_event_tx = test_utils::account_invoke_tx(invoke_tx_args! {
        max_fee,
        sender_address: account_address,
        calldata: create_calldata(contract_address, "test_emit_event", entrypoint_args),
        version: tx_version,
        nonce: nonce_manager.next(account_address),
        only_query,
    });

    let initial_state = copy_state(&state);

    let test_emit_event_tx_internal = to_internal_tx(&test_emit_event_tx);

    let tx_execution_info = test_emit_event_tx.execute(&mut state, &block_context, true, true).unwrap();

    os_hints(&block_context, initial_state, vec![test_emit_event_tx_internal], vec![tx_execution_info])
}

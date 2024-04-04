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
use starknet_api::block::BlockNumber;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use starknet_api::transaction::{Fee, TransactionVersion};

use crate::common::block_utils::{copy_state, os_hints, test_state};
use crate::common::transaction_utils::{to_felt252, to_internal_tx};

#[fixture]
pub fn block_context() -> BlockContext {
    BlockContext { block_number: BlockNumber(0), ..BlockContext::create_for_account_testing() }
}

#[fixture]
pub fn simple_block(
    block_context: BlockContext,
    max_fee: Fee,
    #[default(CairoVersion::Cairo0)] cairo_version: CairoVersion,
    #[default(TransactionVersion::ZERO)] tx_version: TransactionVersion,
    #[default(false)] only_query: bool,
) -> (StarknetOsInput, ExecutionHelperWrapper) {
    let account = FeatureContract::AccountWithoutValidations(cairo_version);
    let test_contract = FeatureContract::TestContract(cairo_version);
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

    let account_tx = test_utils::account_invoke_tx(invoke_tx_args! {
        max_fee,
        sender_address: account_address,
        calldata: create_calldata(
            contract_address,
            "return_result",
            &[stark_felt!(2_u8)],
        ),
        version: tx_version,
        nonce: nonce_manager.next(account_address),
        only_query,
    });

    let initial_state = copy_state(&state);

    let account_tx_internal = to_internal_tx(&account_tx);

    let tx_execution_info = account_tx.execute(&mut state, &block_context, true, true).unwrap();

    os_hints(&block_context, initial_state, vec![account_tx_internal], vec![tx_execution_info])
}

#[fixture]
pub fn simple_block_cairo1(
    block_context: BlockContext,
    max_fee: Fee,
    #[default(CairoVersion::Cairo0)] cairo_version: CairoVersion,
    #[default(TransactionVersion::ZERO)] tx_version: TransactionVersion,
    #[default(false)] only_query: bool,
) -> (StarknetOsInput, ExecutionHelperWrapper) {
    let account = FeatureContract::AccountWithoutValidations(CairoVersion::Cairo1);
    let test_contract = FeatureContract::TestContract(cairo_version);
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

    let account_tx = test_utils::account_invoke_tx(invoke_tx_args! {
        max_fee,
        sender_address: account_address,
        calldata: create_calldata(
            contract_address,
            "return_result",
            &[stark_felt!(2_u8)],
        ),
        version: tx_version,
        nonce: nonce_manager.next(account_address),
        only_query,
    });

    let initial_state = copy_state(&state);

    let account_tx_intenal = to_internal_tx(&account_tx);

    let tx_execution_info = account_tx.execute(&mut state, &block_context, true, true).unwrap();

    os_hints(&block_context, initial_state, vec![account_tx_intenal], vec![tx_execution_info])
}

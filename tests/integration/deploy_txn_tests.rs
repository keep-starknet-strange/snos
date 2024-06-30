use blockifier::context::BlockContext;
use blockifier::deploy_account_tx_args;
use blockifier::test_utils::deploy_account::deploy_account_tx;
use blockifier::test_utils::{NonceManager, BALANCE};
use blockifier::transaction::test_utils::max_fee;
use rstest::{fixture, rstest};
use starknet_api::core::{ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::transaction::{Calldata, ContractAddressSalt, Fee, TransactionVersion};
use starknet_api::{contract_address, patricia_key, stark_felt};

use crate::common::block_context;
use crate::common::state::{init_logging, load_cairo0_contract, StarknetStateBuilder, StarknetTestState};
use crate::common::transaction_utils::execute_txs_and_run_os;

/// Fixture to create initial test state in which all test contracts are deployed.
#[fixture]
pub async fn initial_state_for_deploy_tests(
    block_context: BlockContext,
    #[from(init_logging)] _logging: (),
) -> (StarknetTestState, ContractAddress) {
    let account_with_dummy_validate = load_cairo0_contract("account_with_dummy_validate");
    let account_with_long_validate = load_cairo0_contract("account_with_long_validate");

    let deployed_contract_address =
        contract_address!("0x07420ca64ed9743f6d277b1b191421f4dd113b11014bb3d36f9c0d781e900867");

    let state = StarknetStateBuilder::new(&block_context)
        .add_cairo0_contract(account_with_dummy_validate.0, account_with_dummy_validate.1)
        .add_cairo0_contract(account_with_long_validate.0, account_with_long_validate.1)
        .fund_account(deployed_contract_address, BALANCE, BALANCE)
        .set_default_balance(BALANCE, BALANCE)
        .build()
        .await;

    (state, deployed_contract_address)
}

#[rstest]
// We need to use the multi_thread runtime to use task::block_in_place for sync -> async calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn deploy_cairo0_account(
    #[future] initial_state_for_deploy_tests: (StarknetTestState, ContractAddress),
    block_context: BlockContext,
    max_fee: Fee,
) {
    let (initial_state, deployed_contract_address) = initial_state_for_deploy_tests.await;

    let tx_version = TransactionVersion::ONE;
    let mut nonce_manager = NonceManager::default();

    let account_with_long_validate = initial_state.cairo0_contracts.get("account_with_long_validate").unwrap();

    let deployed_account_class_hash = account_with_long_validate.class_hash;

    let constructor_address_salt = ContractAddressSalt::default();

    let grind_on_deploy = stark_felt!(0u128);
    let ctor_arg = stark_felt!(101u128);

    let mut deploy_account_tx = deploy_account_tx(
        deploy_account_tx_args! {
            class_hash: deployed_account_class_hash,
            max_fee,
            contract_address_salt: constructor_address_salt,
            version: tx_version,
            constructor_calldata: Calldata(vec![grind_on_deploy, ctor_arg].into())
        },
        &mut nonce_manager,
    );
    println!("class hash: {}", deployed_account_class_hash);
    println!("contract address: {}", deploy_account_tx.contract_address.to_string());
    // deploy_account_tx.contract_address = deployed_contract_address;
    let deploy_account_tx =
        blockifier::transaction::account_transaction::AccountTransaction::DeployAccount(deploy_account_tx);

    let _result = execute_txs_and_run_os(
        initial_state.cached_state,
        block_context,
        vec![deploy_account_tx],
        initial_state.cairo0_compiled_classes,
        initial_state.cairo1_compiled_classes,
    )
    .await
    .expect("OS run failed");
}

use blockifier::context::BlockContext;
use blockifier::deploy_account_tx_args;
use blockifier::test_utils::deploy_account::deploy_account_tx;
use blockifier::test_utils::{NonceManager, BALANCE};
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::test_utils::max_fee;
use rstest::{fixture, rstest};
use starknet_api::core::{calculate_contract_address, ClassHash, ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::transaction::{Calldata, ContractAddressSalt, Fee, TransactionVersion};
use starknet_api::{class_hash, contract_address, patricia_key, stark_felt};

use crate::common::block_context;
use crate::common::blockifier_contracts::{load_cairo0_feature_contract, load_cairo1_feature_contract};
use crate::common::state::{init_logging, StarknetStateBuilder, StarknetTestState};
use crate::common::transaction_utils::execute_txs_and_run_os;

#[derive(Debug)]
struct DeployArgs {
    contract_address_salt: ContractAddressSalt,
    class_hash: ClassHash,
    constructor_calldata: Vec<StarkFelt>,
    deployer_address: ContractAddress,
}

/// Fixture to create an initial Starknet state for deploy v1 tx tests.
///
/// One specificity of deploy txs is that the deployed contract funds its own deployment.
/// This means that the state must already provision balances for a yet-to-be-deployed contract.
/// For these tests we compute the contract address in advance and set funds accordingly.
#[fixture]
pub async fn initial_state_for_deploy_v1(
    block_context: BlockContext,
    #[from(init_logging)] _logging: (),
) -> (StarknetTestState, DeployArgs) {
    let account_with_dummy_validate = load_cairo0_feature_contract("account_with_dummy_validate");
    let account_with_long_validate = load_cairo0_feature_contract("account_with_long_validate");

    // This is the hardcoded class hash of `account_with_long_validate` (Cairo 0).
    // Recomputing it automatically requires a significant amount of code reorganization so
    // we hardcode it for simplicity.
    let class_hash = class_hash!("0x067605bc345e925118dd60e09888a600e338047aa61e66361d48604ea670b709");

    let deploy_args = DeployArgs {
        contract_address_salt: ContractAddressSalt::default(),
        class_hash,
        constructor_calldata: vec![stark_felt!(0u128), stark_felt!(101u128)],
        // The deployer address is always be 0 for deploy v1
        deployer_address: contract_address!("0x0"),
    };

    let deployed_contract_address = calculate_contract_address(
        deploy_args.contract_address_salt,
        deploy_args.class_hash,
        &Calldata(deploy_args.constructor_calldata.clone().into()),
        deploy_args.deployer_address,
    )
    .expect("Failed to calculate the contract address");

    let state = StarknetStateBuilder::new(&block_context)
        .deploy_cairo0_contract(account_with_dummy_validate.0, account_with_dummy_validate.1)
        .deploy_cairo0_contract(account_with_long_validate.0, account_with_long_validate.1)
        .fund_account(deployed_contract_address, BALANCE, BALANCE)
        .set_default_balance(BALANCE, BALANCE)
        .build()
        .await;

    (state, deploy_args)
}
#[rstest]
// We need to use the multi_thread runtime to use task::block_in_place for sync -> async calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn deploy_cairo0_account(
    #[future] initial_state_for_deploy_v1: (StarknetTestState, DeployArgs),
    block_context: BlockContext,
    max_fee: Fee,
) {
    let (initial_state, deploy_args) = initial_state_for_deploy_v1.await;

    let tx_version = TransactionVersion::ONE;
    let mut nonce_manager = NonceManager::default();

    let account_with_long_validate = initial_state.deployed_cairo0_contracts.get("account_with_long_validate").unwrap();

    let deployed_account_class_hash = account_with_long_validate.declaration.class_hash;
    // Sanity check, as we hardcode the class hash in the fixture we verify that we have
    // the right one.
    assert_eq!(deploy_args.class_hash, deployed_account_class_hash);

    let deploy_account_tx = AccountTransaction::DeployAccount(deploy_account_tx(
        deploy_account_tx_args! {
            class_hash: deployed_account_class_hash,
            max_fee,
            contract_address_salt: deploy_args.contract_address_salt,
            version: tx_version,
            constructor_calldata: Calldata(deploy_args.constructor_calldata.into())
        },
        &mut nonce_manager,
    ));

    let txs = vec![deploy_account_tx].into_iter().map(Into::into).collect();
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

/// Fixture to create initial test state in which all test contracts are deployed.
#[fixture]
pub async fn initial_state_for_deploy_v3(
    block_context: BlockContext,
    #[from(init_logging)] _logging: (),
) -> (StarknetTestState, DeployArgs) {
    let account_with_dummy_validate = load_cairo1_feature_contract("account_with_dummy_validate");
    let account_with_long_validate = load_cairo1_feature_contract("account_with_long_validate");

    // This is the hardcoded class hash of `account_with_long_validate` (Cairo 1).
    // Recomputing it automatically requires a significant amount of code reorganization so
    // we hardcode it for simplicity.
    let class_hash = class_hash!("0x075a5292e8eb5d722d4388ba904779dd2cf10fea514ece0d5ca9868224ccf6fc");

    let deploy_args = DeployArgs {
        contract_address_salt: ContractAddressSalt::default(),
        class_hash,
        constructor_calldata: vec![stark_felt!(0u128), stark_felt!(101u128)],
        // The deployer address is always be 0 for deploy v1
        deployer_address: contract_address!("0x0"),
    };

    let deployed_contract_address = calculate_contract_address(
        deploy_args.contract_address_salt,
        deploy_args.class_hash,
        &Calldata(deploy_args.constructor_calldata.clone().into()),
        deploy_args.deployer_address,
    )
    .expect("Failed to calculate the contract address");

    let state = StarknetStateBuilder::new(&block_context)
        .deploy_cairo1_contract(
            account_with_dummy_validate.0,
            account_with_dummy_validate.1,
            account_with_dummy_validate.2,
        )
        .deploy_cairo1_contract(
            account_with_long_validate.0,
            account_with_long_validate.1,
            account_with_long_validate.2,
        )
        .fund_account(deployed_contract_address, BALANCE, BALANCE)
        .set_default_balance(BALANCE, BALANCE)
        .build()
        .await;

    (state, deploy_args)
}

#[rstest]
// We need to use the multi_thread runtime to use task::block_in_place for sync -> async calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn deploy_cairo1_account(
    #[future] initial_state_for_deploy_v3: (StarknetTestState, DeployArgs),
    block_context: BlockContext,
    max_fee: Fee,
) {
    let (initial_state, deploy_args) = initial_state_for_deploy_v3.await;

    let tx_version = TransactionVersion::THREE;
    let mut nonce_manager = NonceManager::default();
    let account_with_long_validate = initial_state.deployed_cairo1_contracts.get("account_with_long_validate").unwrap();

    let deployed_account_class_hash = account_with_long_validate.declaration.class_hash;
    // Sanity check, as we hardcode the class hash in the fixture we verify that we have
    // the right one.
    assert_eq!(deploy_args.class_hash, deployed_account_class_hash);

    let deploy_account_tx = deploy_account_tx(
        deploy_account_tx_args! {
            class_hash: deployed_account_class_hash,
            max_fee,
            contract_address_salt: deploy_args.contract_address_salt,
            version: tx_version,
            constructor_calldata: Calldata(deploy_args.constructor_calldata.into()),
        },
        &mut nonce_manager,
    );

    let txs = vec![AccountTransaction::DeployAccount(deploy_account_tx)].into_iter().map(Into::into).collect();
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

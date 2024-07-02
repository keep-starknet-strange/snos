use blockifier::context::BlockContext;
use blockifier::deploy_account_tx_args;
use blockifier::test_utils::deploy_account::deploy_account_tx;
use blockifier::test_utils::{NonceManager, BALANCE};
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::test_utils::max_fee;
use rstest::{fixture, rstest};
use snos::crypto::poseidon::PoseidonHash;
use snos::starknet::business_logic::utils::write_class_facts;
use starknet_api::core::{calculate_contract_address, ClassHash, ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::transaction::{Calldata, ContractAddressSalt, Fee, TransactionVersion};
use starknet_api::{class_hash, contract_address, patricia_key, stark_felt};

use crate::common::block_context;
use crate::common::state::{
    init_logging, load_cairo0_contract, load_cairo1_contract, StarknetStateBuilder, StarknetTestState,
};
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
    let account_with_dummy_validate = load_cairo0_contract("account_with_dummy_validate");
    let account_with_long_validate = load_cairo0_contract("account_with_long_validate");

    // This is the hardcoded class hash of `account_with_long_validate`.
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
        .add_cairo0_contract(account_with_dummy_validate.0, account_with_dummy_validate.1)
        .add_cairo0_contract(account_with_long_validate.0, account_with_long_validate.1)
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

    let account_with_long_validate = initial_state.cairo0_contracts.get("account_with_long_validate").unwrap();

    let deployed_account_class_hash = account_with_long_validate.class_hash;
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

/// Fixture to create initial test state in which all test contracts are deployed.
#[fixture]
pub async fn initial_state_for_deploy_v3_tests(
    block_context: BlockContext,
    #[from(init_logging)] _logging: (),
) -> (StarknetTestState, ContractAddress) {
    let account_with_dummy_validate = load_cairo1_contract("account_with_dummy_validate");
    let account_with_long_validate = load_cairo1_contract("account_with_long_validate");

    // The hardcoded contract address
    let deployed_contract_address =
        contract_address!("0x02cd3a039d6d16cdee03011cfb3bc8f8356f78fe2fefff84e53db1baea0d929c");

    let state = StarknetStateBuilder::new(&block_context)
        .add_cairo1_contract(
            account_with_dummy_validate.0,
            account_with_dummy_validate.1,
            account_with_dummy_validate.2,
        )
        .add_cairo1_contract(account_with_long_validate.0, account_with_long_validate.1, account_with_long_validate.2)
        .fund_account(deployed_contract_address, BALANCE, BALANCE)
        .set_default_balance(BALANCE, BALANCE)
        .build()
        .await;

    (state, deployed_contract_address)
}

#[rstest]
// We need to use the multi_thread runtime to use task::block_in_place for sync -> async calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn deploy_cairo1_account(
    #[future] initial_state_for_deploy_v3_tests: (StarknetTestState, ContractAddress),
    block_context: BlockContext,
    max_fee: Fee,
) {
    let (initial_state, contract) = initial_state_for_deploy_v3_tests.await;

    let tx_version = TransactionVersion::THREE;
    let mut nonce_manager = NonceManager::default();
    // We want to declare a fresh (never-before-declared) contract, so we don't want to reuse
    // anything from the test fixtures, and we need to do it "by hand". The transaction will
    // error if the class trie already contains the class we are trying to deploy.
    let (_, sierra_class, casm_class) = load_cairo1_contract("account_with_long_validate");

    // We also need to write the class and compiled class facts so that the FFC will contain them
    // during block re-execution.
    let mut ffc = initial_state.clone_ffc::<PoseidonHash>();
    let (contract_class_hash, _) = write_class_facts(sierra_class.clone(), casm_class.clone(), &mut ffc).await.unwrap();

    let class_hash = starknet_api::core::ClassHash::try_from(contract_class_hash).unwrap();

    let deployed_account_class_hash = class_hash;

    let constructor_address_salt = ContractAddressSalt::default();

    let grind_on_deploy = stark_felt!(0u128);
    let ctor_arg = stark_felt!(101u128);

    let deploy_account_tx = deploy_account_tx(
        deploy_account_tx_args! {
            class_hash: deployed_account_class_hash,
            max_fee,
            contract_address_salt: constructor_address_salt,
            version: tx_version,
            constructor_calldata: Calldata(vec![grind_on_deploy, ctor_arg].into()),
        },
        &mut nonce_manager,
    );
    println!("class hash: {}", deployed_account_class_hash);
    println!("contract address: {}", deploy_account_tx.contract_address.to_string());

    assert_eq!(deploy_account_tx.contract_address, contract);

    let _result = execute_txs_and_run_os(
        initial_state.cached_state,
        block_context,
        vec![blockifier::transaction::account_transaction::AccountTransaction::DeployAccount(deploy_account_tx)],
        initial_state.cairo0_compiled_classes,
        initial_state.cairo1_compiled_classes,
    )
    .await
    .expect("OS run failed");
}

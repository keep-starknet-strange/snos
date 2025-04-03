/// Tests to ensure that class hashes are done correctly on snos
///
/// By default we write simple tests where in this case we could just declare a contract and see which class hash is accepted
/// But in this case it is not possible to do that, since our test setup can accept a state with an invalid class hash.
/// The solution applied here involves creating the state from scratch by two steps:
/// #### Initial setup via [`create_initial_transactions`]
/// The goal here is to create the state similar to [`StarknetStateBuilder`]:
///
/// - deploy a token
/// - fund an account
/// - deploy the account
///
/// #### Deploy our pre 0.9.0 contract
/// We will reuse the state for these txns.
/// We will also attempt to use both hashing mechanisms to assert which snos supports:
///
/// - declare the old contract
/// - deploy the old contract
///
/// These tests check which is supported and show that the pathfinder method is the correct one.
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use blockifier::{
    blockifier::block::BlockInfo,
    bouncer::BouncerConfig,
    context::{BlockContext, ChainInfo, FeeTokenAddresses},
    declare_tx_args, deploy_account_tx_args,
    execution::contract_class::ClassInfo,
    invoke_tx_args,
    state::cached_state::CachedState,
    test_utils::{
        create_calldata, declare::declare_tx, deploy_account::deploy_account_tx, invoke::invoke_tx, NonceManager,
    },
    transaction::{
        account_transaction::AccountTransaction,
        objects::TransactionExecutionInfo,
        test_utils::{account_invoke_tx, calculate_class_info_for_testing},
        transactions::ExecutableTransaction,
    },
    versioned_constants::VersionedConstants,
};

use starknet_api::deprecated_contract_class::ContractClass as DeprecatedContractClass;

use blockifier::transaction::transaction_execution::Transaction;
use cairo_vm::Felt252;
use rstest::{fixture, rstest};
use starknet_api::{
    core::{calculate_contract_address, ChainId, ClassHash, ContractAddress},
    transaction::{Calldata, ContractAddressSalt, TransactionVersion},
};
use starknet_os::{
    crypto::pedersen::PedersenHash,
    execution::helper::GenCallIter,
    starknet::business_logic::fact_state::state::SharedState,
    storage::{dict_storage::DictStorage, storage_utils::unpack_blockifier_state_async},
};
use starknet_os_types::starknet_core_addons::LegacyContractClass;

use crate::{
    common::{
        blockifier_contracts::{get_deprecated_feature_contract_path, load_cairo0_feature_contract},
        os_itest_contracts::load_os_itest_contract,
        state::{init_logging, DeclaredDeprecatedContract, StarknetStateBuilder, StarknetTestState},
        transaction_utils::execute_txs_and_run_os,
    },
    declare_txn_tests::default_testing_resource_bounds,
};
use blockifier::transaction::test_utils::block_context;
struct InitialTxs {
    deploy_token_tx: blockifier::transaction::transactions::DeployAccountTransaction,
    deploy_account_tx: blockifier::transaction::transactions::DeployAccountTransaction,
    fund_account_tx: blockifier::transaction::transactions::InvokeTransaction,
    fee_token_address: ContractAddress,
    dummy_account_address: ContractAddress,
}

impl InitialTxs {
    #[allow(clippy::wrong_self_convention)]
    fn to_vec(self) -> Vec<Transaction> {
        vec![
            AccountTransaction::DeployAccount(self.deploy_token_tx).into(),
            AccountTransaction::Invoke(self.fund_account_tx).into(),
            AccountTransaction::DeployAccount(self.deploy_account_tx).into(),
        ]
    }
}

async fn create_initial_transactions(
    nonce_manager: &mut NonceManager,
    dummy_token: &DeclaredDeprecatedContract,
    dummy_account: &DeclaredDeprecatedContract,
) -> InitialTxs {
    let deploy_token_tx_args = deploy_account_tx_args! {
        class_hash: dummy_token.class_hash,
        version: TransactionVersion::ONE,
    };
    let deploy_token_tx = deploy_account_tx(deploy_token_tx_args, nonce_manager);
    let fee_token_address = deploy_token_tx.contract_address;

    let deploy_account_tx_args = deploy_account_tx_args! {
        class_hash: dummy_account.class_hash,
        version: TransactionVersion::ONE,
    };

    let deploy_account_tx = deploy_account_tx(deploy_account_tx_args, nonce_manager);
    let dummy_account_address = deploy_account_tx.contract_address;

    let fund_account_tx_args = invoke_tx_args! {
        sender_address: fee_token_address,
        calldata: create_calldata(fee_token_address, "transfer", &[*dummy_account_address.0, 2u128.pow(120).into(), 0u128.into()]),
        nonce: nonce_manager.next(fee_token_address),
    };
    let fund_account_tx = invoke_tx(fund_account_tx_args);

    InitialTxs { deploy_token_tx, deploy_account_tx, fund_account_tx, fee_token_address, dummy_account_address }
}

/// Fixture state where we declare all the contracts that need to exist before running
/// this integration test suite.
#[fixture]
pub async fn initial_state_class_hash_itests(
    block_context: BlockContext,
    #[from(init_logging)] _logging: (),
) -> StarknetTestState {
    let account_with_dummy_validate = load_cairo0_feature_contract("account_with_dummy_validate");
    let delegate_proxy = load_os_itest_contract("delegate_proxy");
    let dummy_token = load_os_itest_contract("dummy_token");
    let test_contract_run_os = load_os_itest_contract("test_contract_run_os");
    let test_contract2 = load_os_itest_contract("test_contract2");
    let token_for_testing = load_os_itest_contract("token_for_testing");

    let pre_0_10_0_contract = load_cairo0_feature_contract("pre_0_10_0_contract");

    StarknetStateBuilder::new(&block_context)
        .declare_cairo0_contract(account_with_dummy_validate.0, account_with_dummy_validate.1)
        .declare_cairo0_contract(delegate_proxy.0, delegate_proxy.1)
        .declare_cairo0_contract(dummy_token.0, dummy_token.1)
        .declare_cairo0_contract(test_contract_run_os.0, test_contract_run_os.1)
        .declare_cairo0_contract(test_contract2.0, test_contract2.1)
        .declare_cairo0_contract(token_for_testing.0, token_for_testing.1)
        .declare_cairo0_contract(pre_0_10_0_contract.0, pre_0_10_0_contract.1)
        .build()
        .await
}

#[rstest]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn run_pathfinder_class_hash_version_test(#[future] initial_state_class_hash_itests: StarknetTestState) {
    let initial_state = initial_state_class_hash_itests.await;

    let chain_id = ChainId::Sepolia;
    let mut nonce_manager = NonceManager::default();

    let dummy_token = initial_state.declared_cairo0_contracts.get("token_for_testing").unwrap();
    let dummy_account = initial_state.declared_cairo0_contracts.get("account_with_dummy_validate").unwrap();

    // This sets up the state from scratch
    // It deploys a token and funds the dummy account
    let initial_txs = create_initial_transactions(&mut nonce_manager, dummy_token, dummy_account).await;

    let block_context = build_block_context(chain_id, initial_txs.fee_token_address);
    let dummy_account_address = initial_txs.dummy_account_address;

    let init_txs = initial_txs.to_vec();
    let mut cached_state = initial_state.cached_state;

    // Execute the init transactions. This prepares the state for testing deploying the contract
    let execution_infos: Vec<_> =
        init_txs.into_iter().map(|tx| execute_transaction(tx, &mut cached_state, &block_context)).collect();
    validate_execution_infos(&execution_infos);

    let mut tx_contracts = vec![];

    let mut txs = Vec::new();

    let (_, pre_0_10_0_contract) = load_cairo0_feature_contract("pre_0_10_0_contract");
    let pathfinder_class_hash = pre_0_10_0_contract.class_hash().unwrap();

    let class = pre_0_10_0_contract.get_blockifier_contract_class().map_err(|_| "Failed to get VM class").unwrap();
    let class_info = calculate_class_info_for_testing(class.clone().into());

    tx_contracts.push(
        add_declare_and_deploy_contract_txs(
            &dummy_account_address,
            &dummy_account_address,
            &mut nonce_manager,
            &mut txs,
            pathfinder_class_hash.into(),
            class_info,
            0u128.into(),
            vec![42u32.into()],
        )
        .unwrap(),
    );

    let (_, shared_state) = unpack_blockifier_state_async(cached_state).await.unwrap();
    let cached_state = CachedState::from(shared_state);

    let (_pie, os_output) = execute_txs_and_run_os(
        crate::common::DEFAULT_COMPILED_OS,
        cached_state,
        block_context,
        txs,
        initial_state.cairo0_compiled_classes,
        Default::default(),
        HashMap::default(),
    )
    .await
    .unwrap();

    let hashes: Vec<_> = os_output.state_diff.unwrap().contract_changes.iter().map(|s| s.class_hash.unwrap()).collect();

    let pf_hash: ClassHash = pathfinder_class_hash.into();

    assert!(hashes.contains(&pf_hash.0))
}

#[rstest]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[should_panic]
async fn run_starknet_class_hash_version_test(#[future] initial_state_class_hash_itests: StarknetTestState) {
    let initial_state = initial_state_class_hash_itests.await;

    let chain_id = ChainId::Sepolia;
    let mut nonce_manager = NonceManager::default();

    let dummy_token = initial_state.declared_cairo0_contracts.get("token_for_testing").unwrap();
    let dummy_account = initial_state.declared_cairo0_contracts.get("account_with_dummy_validate").unwrap();

    let initial_txs = create_initial_transactions(&mut nonce_manager, dummy_token, dummy_account).await;

    let block_context = build_block_context(chain_id, initial_txs.fee_token_address);
    let dummy_account_address = initial_txs.dummy_account_address;

    let init_txs = initial_txs.to_vec();
    let mut cached_state = initial_state.cached_state;

    // Execute the init transactions. This prepares the state for the rest of the integration
    // tests.
    let execution_infos: Vec<_> =
        init_txs.into_iter().map(|tx| execute_transaction(tx, &mut cached_state, &block_context)).collect();
    validate_execution_infos(&execution_infos);

    let mut tx_contracts = vec![];

    let mut txs = Vec::new();

    let contract_path = get_deprecated_feature_contract_path("pre_0_10_0_contract");
    let content = read_contract(&contract_path);
    let legacy_contract: LegacyContractClass =
        serde_json::from_slice(&content).unwrap_or_else(|e| panic!("Failed to load deprecated compiled class: {e}"));

    let dep_legacy_contract: DeprecatedContractClass =
        serde_json::from_slice(&content).unwrap_or_else(|e| panic!("Failed to load deprecated compiled class: {e}"));

    let class_info = calculate_class_info_for_testing(blockifier::execution::contract_class::ContractClass::V0(
        dep_legacy_contract.try_into().unwrap(),
    ));

    let starknet_class_hash = legacy_contract.class_hash().unwrap();

    tx_contracts.push(
        add_declare_and_deploy_contract_txs(
            &dummy_account_address,
            &dummy_account_address,
            &mut nonce_manager,
            &mut txs,
            ClassHash(starknet_class_hash),
            class_info,
            0u128.into(),
            vec![42u32.into()],
        )
        .unwrap(),
    );

    let (_, shared_state) = unpack_blockifier_state_async(cached_state).await.unwrap();
    let cached_state = CachedState::from(shared_state);

    let (_pie, os_output) = execute_txs_and_run_os(
        crate::common::DEFAULT_COMPILED_OS,
        cached_state,
        block_context,
        txs,
        initial_state.cairo0_compiled_classes,
        Default::default(),
        HashMap::default(),
    )
    .await
    .unwrap();

    let hashes: Vec<_> = os_output.state_diff.unwrap().contract_changes.iter().map(|s| s.class_hash.unwrap()).collect();
    // We never get here coz it should panic
    assert!(!hashes.contains(&starknet_class_hash))
}

fn execute_transaction(
    tx: Transaction,
    cached_state: &mut CachedState<SharedState<DictStorage, PedersenHash>>,
    block_context: &BlockContext,
) -> TransactionExecutionInfo {
    let tx_result = tx.execute(cached_state, block_context, true, true);
    match tx_result {
        Err(e) => {
            log::error!("Transaction failed in blockifier: {}", e);
            panic!("A transaction failed during execution");
        }
        Ok(info) => {
            if info.is_reverted() {
                log::error!("Transaction reverted: {:?}", info.revert_error);
                log::error!("TransactionExecutionInfo: {:?}", info);
                panic!("A transaction reverted during execution");
            }
            info
        }
    }
}

fn validate_execution_infos(execution_infos: &[TransactionExecutionInfo]) {
    for execution_info in execution_infos {
        for call_info in execution_info.gen_call_iterator() {
            assert!(!call_info.execution.failed, "Unexpected reverted transaction.");
        }
    }
}

fn build_block_context(chain_id: ChainId, fee_token_address: ContractAddress) -> BlockContext {
    let block_info = BlockInfo::create_for_testing();
    let mut versioned_constants = VersionedConstants::create_for_account_testing();
    // Recent versions of Blockifier disable redeclaration of Cairo0 classes. We do that quite
    // a bit in the test so the easy way out is to disable this feature.
    versioned_constants.disable_cairo0_redeclaration = false;

    let chain_info = ChainInfo {
        chain_id,
        fee_token_addresses: FeeTokenAddresses {
            strk_fee_token_address: fee_token_address,
            eth_fee_token_address: fee_token_address,
        },
    };

    let bouncer_config = BouncerConfig::max();

    BlockContext::new(block_info, chain_info, versioned_constants, bouncer_config)
}

/// This declares and deploys the pre 0.9 contract
/// We provide different class hashes to verify what is working correctly.
#[allow(clippy::too_many_arguments)]
fn add_declare_and_deploy_contract_txs(
    account_address: &ContractAddress,
    deploy_account_address: &ContractAddress,
    nonce_manager: &mut NonceManager,
    txs: &mut Vec<Transaction>,
    class_hash: ClassHash,
    class_info: ClassInfo,
    salt: Felt252,
    constructor_calldata: Vec<Felt252>,
) -> Result<ContractAddress, &'static str> {
    let declare_tx = declare_tx(
        declare_tx_args! {
            sender_address: *account_address,
            resource_bounds: default_testing_resource_bounds(),
            class_hash: class_hash,
            version: TransactionVersion::ONE,
            nonce: nonce_manager.next(*account_address)
        },
        class_info,
    );

    txs.push(Transaction::AccountTransaction(declare_tx));

    let mut ctor_calldata = vec![
        class_hash.0, // Class hash.
        salt,         // Salt.
    ];
    ctor_calldata.push(Felt252::from(constructor_calldata.len() as u128)); // Constructor calldata length.
    ctor_calldata.extend(constructor_calldata.iter());
    let invoke_tx = account_invoke_tx(invoke_tx_args! {
        sender_address: *deploy_account_address,
        calldata: create_calldata(
            *deploy_account_address,
            "deploy_contract",
            &ctor_calldata
        ),
        version: TransactionVersion::ONE,
        resource_bounds: default_testing_resource_bounds(),
        nonce: nonce_manager.next(*deploy_account_address)
    });

    txs.push(Transaction::AccountTransaction(invoke_tx));

    let contract_address = calculate_contract_address(
        ContractAddressSalt(salt),
        class_hash,
        &Calldata(constructor_calldata.into()),
        *deploy_account_address,
    )
    .map_err(|_| "Failed to calculate the contract address")?;

    Ok(contract_address)
}

fn read_contract(contract_rel_path: &Path) -> Vec<u8> {
    // Keep using Blockifier fixtures for now.
    let contracts_dir = get_contracts_dir();
    let contract_path = contracts_dir.join(contract_rel_path);

    std::fs::read(&contract_path).unwrap_or_else(|e| {
        panic!("Failed to read fixture {}: {e}", contract_path.to_string_lossy().as_ref());
    })
}

fn get_contracts_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("integration").join("contracts")
}

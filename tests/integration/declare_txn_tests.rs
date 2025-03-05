use std::collections::HashMap;

use blockifier::context::BlockContext;
use blockifier::declare_tx_args;
use blockifier::execution::contract_class::ClassInfo;
use blockifier::test_utils::{NonceManager, BALANCE};
use blockifier::transaction::test_utils::{calculate_class_info_for_testing, max_fee};
use rstest::{fixture, rstest};
use starknet_api::core::CompiledClassHash;
use starknet_api::transaction::{Fee, Resource, ResourceBounds, ResourceBoundsMapping, TransactionVersion};
use starknet_os::crypto::poseidon::PoseidonHash;
use starknet_os::starknet::business_logic::utils::write_class_facts;
use starknet_os_types::class_hash_utils::ContractClassComponentHashes;
use starknet_os_types::sierra_contract_class::GenericSierraContractClass;

use crate::common::block_context;
use crate::common::blockifier_contracts::{load_cairo0_feature_contract, load_cairo1_feature_contract};
use crate::common::state::{init_logging, initial_state_cairo1, StarknetStateBuilder, StarknetTestState};
use crate::common::transaction_utils::execute_txs_and_run_os;

// Copied from the non-public Blockifier fn
pub fn default_testing_resource_bounds() -> ResourceBoundsMapping {
    ResourceBoundsMapping::try_from(vec![
        (Resource::L1Gas, ResourceBounds { max_amount: 0, max_price_per_unit: 1 }),
        (Resource::L2Gas, ResourceBounds { max_amount: 0, max_price_per_unit: 0 }),
    ])
    .unwrap()
}

#[rstest]
// We need to use the multi_thread runtime to use task::block_in_place for sync -> async calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn declare_v3_cairo1_account(
    #[future] initial_state_cairo1: StarknetTestState,
    block_context: BlockContext,
    max_fee: Fee,
) {
    let initial_state = initial_state_cairo1.await;

    let tx_version = TransactionVersion::THREE;
    let mut nonce_manager = NonceManager::default();

    let account_contract = initial_state.deployed_cairo1_contracts.get("account_with_dummy_validate").unwrap();

    // We want to declare a fresh (never-before-declared) contract, so we don't want to reuse
    // anything from the test fixtures, and we need to do it "by hand". The transaction will
    // error if the class trie already contains the class we are trying to deploy.
    let (_, sierra_class, casm_class) = load_cairo1_feature_contract("empty_contract");

    // We also need to write the class and compiled class facts so that the FFC will contain them
    // during block re-execution.
    let mut ffc = initial_state.clone_ffc::<PoseidonHash>();
    let (contract_class_hash, compiled_class_hash) =
        write_class_facts(sierra_class.clone().into(), casm_class.clone(), &mut ffc).await.unwrap();

    let sender_address = account_contract.address;

    let contract_class = casm_class.to_blockifier_contract_class().unwrap();
    let class_hash = starknet_api::core::ClassHash::from(contract_class_hash);
    let compiled_class_hash = CompiledClassHash::from(compiled_class_hash);

    let sierra_program_len = sierra_class.sierra_program.len();
    let generic_sierra_class = GenericSierraContractClass::from(sierra_class);
    let flattened_sierra_class = generic_sierra_class.to_starknet_core_contract_class().unwrap();

    let class_hash_component_hashes =
        HashMap::from([(class_hash, ContractClassComponentHashes::from(flattened_sierra_class))]);

    let class_info = ClassInfo::new(&contract_class.into(), sierra_program_len, 0).unwrap();

    let declare_tx = blockifier::test_utils::declare::declare_tx(
        declare_tx_args! {
            max_fee,
            sender_address,
            version: tx_version,
            nonce: nonce_manager.next(sender_address),
            class_hash: class_hash,
            compiled_class_hash,
            resource_bounds: default_testing_resource_bounds(),
        },
        class_info,
    );

    let txs = vec![declare_tx].into_iter().map(Into::into).collect();
    let _result = execute_txs_and_run_os(
        crate::common::DEFAULT_COMPILED_OS,
        initial_state.cached_state,
        block_context,
        txs,
        initial_state.cairo0_compiled_classes,
        initial_state.cairo1_compiled_classes,
        class_hash_component_hashes,
    )
    .await
    .expect("OS run failed");
}

#[rstest]
// We need to use the multi_thread runtime to use task::block_in_place for sync -> async calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn declare_cairo1_account(
    #[future] initial_state_cairo1: StarknetTestState,
    block_context: BlockContext,
    max_fee: Fee,
) {
    let initial_state = initial_state_cairo1.await;

    let tx_version = TransactionVersion::TWO;
    let mut nonce_manager = NonceManager::default();

    let account_contract = initial_state.deployed_cairo1_contracts.get("account_with_dummy_validate").unwrap();

    // We want to declare a fresh (never-before-declared) contract, so we don't want to reuse
    // anything from the test fixtures, and we need to do it "by hand". The transaction will
    // error if the class trie already contains the class we are trying to deploy.
    let (_, sierra_class, casm_class) = load_cairo1_feature_contract("empty_contract");

    // We also need to write the class and compiled class facts so that the FFC will contain them
    // during block re-execution.
    let mut ffc = initial_state.clone_ffc::<PoseidonHash>();
    let (contract_class_hash, compiled_class_hash) =
        write_class_facts(sierra_class.clone().into(), casm_class.clone(), &mut ffc).await.unwrap();

    let sender_address = account_contract.address;

    let contract_class = casm_class.to_blockifier_contract_class().unwrap();
    let class_hash = starknet_api::core::ClassHash::from(contract_class_hash);
    let compiled_class_hash = CompiledClassHash::from(compiled_class_hash);

    let sierra_program_len = sierra_class.sierra_program.len();
    let generic_sierra_class = GenericSierraContractClass::from(sierra_class);
    let flattened_sierra_class = generic_sierra_class.to_starknet_core_contract_class().unwrap();

    let class_hash_component_hashes =
        HashMap::from([(class_hash, ContractClassComponentHashes::from(flattened_sierra_class))]);

    let class_info = ClassInfo::new(&contract_class.into(), sierra_program_len, 0).unwrap();

    let declare_tx = blockifier::test_utils::declare::declare_tx(
        declare_tx_args! {
            max_fee,
            sender_address,
            version: tx_version,
            nonce: nonce_manager.next(sender_address),
            class_hash: class_hash,
            compiled_class_hash,
        },
        class_info,
    );

    let txs = vec![declare_tx].into_iter().map(Into::into).collect();
    let _result = execute_txs_and_run_os(
        crate::common::DEFAULT_COMPILED_OS,
        initial_state.cached_state,
        block_context,
        txs,
        initial_state.cairo0_compiled_classes,
        initial_state.cairo1_compiled_classes,
        class_hash_component_hashes,
    )
    .await
    .expect("OS run failed");
}

#[fixture]
async fn initial_state_declare_cairo0(
    block_context: BlockContext,
    #[from(init_logging)] _logging: (),
) -> StarknetTestState {
    let account_with_dummy_validate = load_cairo0_feature_contract("account_with_dummy_validate");
    let account_with_syscall_checks = load_cairo0_feature_contract("account_with_syscall_checks");

    StarknetStateBuilder::new(&block_context)
        .deploy_cairo0_contract(account_with_dummy_validate.0, account_with_dummy_validate.1)
        .deploy_cairo0_contract(account_with_syscall_checks.0, account_with_syscall_checks.1)
        .set_default_balance(BALANCE, BALANCE)
        .build()
        .await
}

#[rstest]
// We need to use the multi_thread runtime to use task::block_in_place for sync -> async calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn declare_v1_cairo0_account(
    #[future] initial_state_declare_cairo0: StarknetTestState,
    block_context: BlockContext,
    max_fee: Fee,
) {
    let initial_state = initial_state_declare_cairo0.await;
    let sender_address = initial_state.deployed_cairo0_contracts.get("account_with_dummy_validate").unwrap().address;

    let (_, test_contract) = load_cairo0_feature_contract("test_contract");
    let class_hash = test_contract.class_hash().unwrap();

    let mut nonce_manager = NonceManager::default();
    let tx_version = TransactionVersion::ONE;

    let blockifier_class = test_contract.to_blockifier_contract_class().unwrap();
    let class_info = calculate_class_info_for_testing(blockifier_class.into());

    let declare_tx = blockifier::test_utils::declare::declare_tx(
        declare_tx_args! {
            max_fee,
            sender_address,
            version: tx_version,
            nonce: nonce_manager.next(sender_address),
            class_hash: class_hash.into(),
        },
        class_info,
    );

    let txs = vec![declare_tx].into_iter().map(Into::into).collect();
    let _result = execute_txs_and_run_os(
        crate::common::DEFAULT_COMPILED_OS,
        initial_state.cached_state,
        block_context,
        txs,
        initial_state.cairo0_compiled_classes,
        initial_state.cairo1_compiled_classes,
        HashMap::default(),
    )
    .await
    .expect("OS run failed");
}

#[rstest]
// We need to use the multi_thread runtime to use task::block_in_place for sync -> async calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn declare_cairo0_with_tx_info(
    #[future] initial_state_declare_cairo0: StarknetTestState,
    block_context: BlockContext,
    max_fee: Fee,
) {
    let tx_version = TransactionVersion::THREE;

    let mut nonce_manager = NonceManager::default();

    let initial_state = initial_state_declare_cairo0.await;
    let sender_address = initial_state.deployed_cairo0_contracts.get("account_with_syscall_checks").unwrap().address;

    // We want to declare a fresh (never-before-declared) contract, so we don't want to reuse
    // anything from the test fixtures, and we need to do it "by hand". The transaction will
    // error if the class trie already contains the class we are trying to deploy.
    let (_, sierra_class, casm_class) = load_cairo1_feature_contract("test_contract");

    // We also need to write the class and compiled class facts so that the FFC will contain them
    // during block re-execution.
    let mut ffc = initial_state.clone_ffc::<PoseidonHash>();
    let (contract_class_hash, compiled_class_hash) =
        write_class_facts(sierra_class.clone().into(), casm_class.clone(), &mut ffc).await.unwrap();

    let contract_class = casm_class.to_blockifier_contract_class().unwrap();
    let class_hash = starknet_api::core::ClassHash::from(contract_class_hash);
    let compiled_class_hash = CompiledClassHash::from(compiled_class_hash);

    let sierra_program_len = sierra_class.sierra_program.len();
    let generic_sierra_class = GenericSierraContractClass::from(sierra_class);
    let flattened_sierra_class = generic_sierra_class.to_starknet_core_contract_class().unwrap();

    let class_hash_component_hashes =
        HashMap::from([(class_hash, ContractClassComponentHashes::from(flattened_sierra_class))]);

    let class_info = ClassInfo::new(&contract_class.into(), sierra_program_len, 0).unwrap();

    let declare_tx = blockifier::test_utils::declare::declare_tx(
        declare_tx_args! {
            max_fee,
            sender_address,
            version: tx_version,
            nonce: nonce_manager.next(sender_address),
            class_hash: class_hash,
            compiled_class_hash,
            resource_bounds: default_testing_resource_bounds(),
        },
        class_info,
    );

    let txs = vec![declare_tx].into_iter().map(Into::into).collect();
    let _result = execute_txs_and_run_os(
        crate::common::DEFAULT_COMPILED_OS,
        initial_state.cached_state,
        block_context,
        txs,
        initial_state.cairo0_compiled_classes,
        initial_state.cairo1_compiled_classes,
        class_hash_component_hashes,
    )
    .await
    .expect("OS run failed");
}

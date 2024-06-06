use blockifier::context::BlockContext;
use blockifier::declare_tx_args;
use blockifier::execution::contract_class::ClassInfo;
use blockifier::test_utils::NonceManager;
use blockifier::transaction::test_utils::max_fee;
use rstest::rstest;
use snos::crypto::poseidon::PoseidonHash;
use snos::starknet::business_logic::utils::write_class_facts;
use snos::storage::storage_utils::compiled_contract_class_cl2vm;
use starknet_api::core::CompiledClassHash;
use starknet_api::transaction::{Fee, TransactionVersion};

use crate::common::block_context;
use crate::common::state::{initial_state_cairo1, load_cairo1_contract, StarknetTestState};
use crate::common::transaction_utils::execute_txs_and_run_os;

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

    let account_contract = initial_state.cairo1_contracts.get("account_with_dummy_validate").unwrap();

    // We want to declare a fresh (never-before-declared) contract, so we don't want to reuse
    // anything from the test fixtures, and we need to do it "by hand". The transaction will
    // error if the class trie already contains the class we are trying to deploy.
    let (_, sierra_class, casm_class) = load_cairo1_contract("empty_contract");

    // We also need to write the class and compiled class facts so that the FFC will contain them
    // during block re-execution.
    let mut ffc = initial_state.clone_ffc::<PoseidonHash>();
    let (contract_class_hash, compiled_class_hash) =
        write_class_facts(sierra_class.clone(), casm_class.clone(), &mut ffc).await.unwrap();

    let sender_address = account_contract.address;

    let contract_class = compiled_contract_class_cl2vm(&casm_class).unwrap();
    let class_hash = starknet_api::core::ClassHash::try_from(contract_class_hash).unwrap();
    let compiled_class_hash = CompiledClassHash::try_from(compiled_class_hash).unwrap();

    let class_info = ClassInfo::new(&contract_class, sierra_class.sierra_program.len(), 0).unwrap();

    let declare_tx = blockifier::test_utils::declare::declare_tx(
        declare_tx_args! {
            max_fee,
            sender_address,
            version: tx_version,
            nonce: nonce_manager.next(sender_address),
            class_hash: class_hash.into(),
            compiled_class_hash,
        },
        class_info,
    );

    let _result = execute_txs_and_run_os(
        initial_state.cached_state,
        block_context,
        vec![declare_tx],
        initial_state.cairo0_compiled_classes,
        initial_state.cairo1_compiled_classes,
    )
    .await
    .expect("OS run failed");
}

#[rstest]
// We need to use the multi_thread runtime to use task::block_in_place for sync -> async calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn declare_v2_cairo1_account(
    #[future] initial_state_cairo1: StarknetTestState,
    block_context: BlockContext,
    max_fee: Fee,
) {
    let initial_state = initial_state_cairo1.await;

    let tx_version = TransactionVersion::TWO;
    let mut nonce_manager = NonceManager::default();

    let account_contract = initial_state.cairo1_contracts.get("account_with_dummy_validate").unwrap();

    // We want to declare a fresh (never-before-declared) contract, so we don't want to reuse
    // anything from the test fixtures, and we need to do it "by hand". The transaction will
    // error if the class trie already contains the class we are trying to deploy.
    let (_, sierra_class, casm_class) = load_cairo1_contract("empty_contract");

    // We also need to write the class and compiled class facts so that the FFC will contain them
    // during block re-execution.
    let mut ffc = initial_state.clone_ffc::<PoseidonHash>();
    let (contract_class_hash, compiled_class_hash) =
        write_class_facts(sierra_class.clone(), casm_class.clone(), &mut ffc).await.unwrap();

    let sender_address = account_contract.address;

    let contract_class = compiled_contract_class_cl2vm(&casm_class).unwrap();
    let class_hash = starknet_api::core::ClassHash::try_from(contract_class_hash).unwrap();
    let compiled_class_hash = CompiledClassHash::try_from(compiled_class_hash).unwrap();

    let class_info = ClassInfo::new(&contract_class, sierra_class.sierra_program.len(), 0).unwrap();

    let declare_tx = blockifier::test_utils::declare::declare_tx(
        declare_tx_args! {
            max_fee,
            sender_address,
            version: tx_version,
            nonce: nonce_manager.next(sender_address),
            class_hash: class_hash.into(),
            compiled_class_hash,
        },
        class_info,
    );

    let _result = execute_txs_and_run_os(
        initial_state.cached_state,
        block_context,
        vec![declare_tx],
        initial_state.cairo0_compiled_classes,
        initial_state.cairo1_compiled_classes,
    )
    .await
    .expect("OS run failed");
}

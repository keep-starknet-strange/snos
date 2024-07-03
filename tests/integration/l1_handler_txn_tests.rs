use std::sync::Arc;

use blockifier::abi::abi_utils::selector_from_name;
use blockifier::context::BlockContext;
use blockifier::execution::contract_class::ClassInfo;
use blockifier::test_utils::{create_calldata, NonceManager, BALANCE};
use blockifier::transaction::test_utils::{block_context, max_fee};
use blockifier::transaction::transactions::L1HandlerTransaction;
use cairo_vm::Felt252;
use rstest::{fixture, rstest};
use snos::crypto::poseidon::PoseidonHash;
use snos::starknet::business_logic::utils::write_class_facts;
use snos::storage::storage_utils::compiled_contract_class_cl2vm;
use snos::utils::{felt_vm2api, Felt252Str};
use starknet_api::core::{CompiledClassHash, EntryPointSelector};
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use starknet_api::transaction::{Calldata, Fee, TransactionVersion};

use crate::common::state::{init_logging, initial_state_cairo1, load_cairo0_contract, load_cairo1_contract, StarknetStateBuilder, StarknetTestState};
use crate::common::transaction_utils::{execute_txs_and_run_os, to_felt252};

#[fixture]
pub async fn l1_initial_state_cairo1(
    block_context: BlockContext,
    #[from(init_logging)] _logging: (),
) -> StarknetTestState {
    let test_contract = load_cairo1_contract("test_contract");
    let account_with_dummy_validate = load_cairo1_contract("account_with_dummy_validate");

    StarknetStateBuilder::new(&block_context)
        .add_cairo1_contract(
            account_with_dummy_validate.0,
            account_with_dummy_validate.1,
            account_with_dummy_validate.2,
        )
        .add_cairo1_contract(test_contract.0, test_contract.1, test_contract.2)
        .set_default_balance(BALANCE, BALANCE)
        .build()
        .await
}

#[rstest]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn l1_handler_cairo1_account(
    #[future] l1_initial_state_cairo1: StarknetTestState,
    block_context: BlockContext,
    max_fee: Fee,
) {
    let initial_state = l1_initial_state_cairo1.await;

    let tx_version = TransactionVersion::THREE;
    let mut nonce_manager = NonceManager::default();

    let account_contract = initial_state.cairo1_contracts.get("account_with_dummy_validate").unwrap();

    // We want to declare a fresh (never-before-declared) contract, so we don't want to reuse
    // anything from the test fixtures, and we need to do it "by hand". The transaction will
    // error if the class trie already contains the class we are trying to deploy.
    let (_, sierra_class, casm_class) = load_cairo1_contract("test_contract");

    // We also need to write the class and compiled class facts so that the FFC will contain them
    // during block re-execution.
    let mut ffc = initial_state.clone_ffc::<PoseidonHash>();
    let (contract_class_hash, compiled_class_hash) =
        write_class_facts(sierra_class.clone(), casm_class.clone(), &mut ffc).await.unwrap();

    let sender_address = account_contract.address;
    let contract_address = initial_state.cairo1_contracts.get("test_contract").unwrap().address;

    let contract_class = compiled_contract_class_cl2vm(&casm_class).unwrap();
    let class_hash = starknet_api::core::ClassHash::try_from(contract_class_hash).unwrap();
    let compiled_class_hash = CompiledClassHash::try_from(compiled_class_hash).unwrap();

    let class_info = ClassInfo::new(&contract_class, sierra_class.sierra_program.len(), 0).unwrap();

    let calldata_args = vec![stark_felt!(1u128), stark_felt!(42u128)];

    let l1_tx = L1HandlerTransaction {
        paid_fee_on_l1: max_fee,
        tx: starknet_api::transaction::L1HandlerTransaction {
            contract_address,
            nonce: nonce_manager.next(sender_address),
            version: tx_version,
            entry_point_selector: EntryPointSelector(selector_from_name("l1_handle").0),
            // calldata: create_calldata(contract_address, "l1_handle", &calldata_args),
            calldata: Calldata(Arc::new(calldata_args)),
            ..Default::default()
        },
        tx_hash: Default::default(),
    };

    let _result = execute_txs_and_run_os(
        initial_state.cached_state,
        block_context,
        vec![l1_tx],
        initial_state.cairo0_compiled_classes,
        initial_state.cairo1_compiled_classes,
    )
    .await
    .expect("OS run failed");
}

use blockifier::context::BlockContext;
use blockifier::deploy_account_tx_args;
use blockifier::execution::contract_class::ClassInfo;
use blockifier::test_utils::deploy_account::deploy_account_tx;
use blockifier::test_utils::NonceManager;
use blockifier::transaction::test_utils::max_fee;
use rstest::rstest;
use snos::crypto::poseidon::PoseidonHash;
use snos::starknet::business_logic::utils::write_class_facts;
use snos::storage::storage_utils::compiled_contract_class_cl2vm;
use starknet_api::core::CompiledClassHash;
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{ContractAddressSalt, Fee, TransactionVersion};
use starknet_api::{calldata, stark_felt};

use crate::common::block_context;
use crate::common::state::{initial_state_cairo0, initial_state_cairo1, load_cairo1_contract, StarknetTestState};
use crate::common::transaction_utils::execute_txs_and_run_os;

#[rstest]
// We need to use the multi_thread runtime to use task::block_in_place for sync -> async calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn deploy_cairo1_account(
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

    // TODO: Figure what the salt is.
    let constructor_address_salt = ContractAddressSalt::default();
    use starknet_api::transaction::Calldata;
    let deploy_account_tx =
        blockifier::transaction::account_transaction::AccountTransaction::DeployAccount(deploy_account_tx(
            deploy_account_tx_args! {
                class_hash,
                max_fee,
                contract_address_salt: constructor_address_salt,
                deployer_address: sender_address,
                version: tx_version,
                constructor_calldata: calldata![
                    stark_felt!(3_u8), // Calldata: address.
                    stark_felt!(3_u8)  // Calldata: value.
                ],

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

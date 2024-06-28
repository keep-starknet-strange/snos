use blockifier::context::BlockContext;
use blockifier::deploy_account_tx_args;
use blockifier::test_utils::deploy_account::deploy_account_tx;
use blockifier::test_utils::NonceManager;
use blockifier::transaction::test_utils::max_fee;
use rstest::rstest;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use starknet_api::transaction::{ContractAddressSalt, Fee, TransactionVersion};

use crate::common::block_context;
use crate::common::state::{initial_state_cairo0, StarknetTestState};
use crate::common::transaction_utils::execute_txs_and_run_os;

#[rstest]
// We need to use the multi_thread runtime to use task::block_in_place for sync -> async calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn deploy_cairo0_account(
    #[future] initial_state_cairo0: StarknetTestState,
    block_context: BlockContext,
    max_fee: Fee,
) {
    let initial_state = initial_state_cairo0.await;

    let tx_version = TransactionVersion::ONE;
    let mut nonce_manager = NonceManager::default();

    let sender_address = initial_state.cairo0_contracts.get("account_with_dummy_validate").unwrap().address;
    let test_contract = initial_state.cairo0_contracts.get("test_contract").unwrap();

    let test_contract_class_hash = test_contract.class_hash;

    // TODO: Figure what the salt is.
    let constructor_address_salt =
        ContractAddressSalt(stark_felt!(u64::try_from(0).expect("Failed to convert usize to u64.")));

    let deploy_account_tx =
        blockifier::transaction::account_transaction::AccountTransaction::DeployAccount(deploy_account_tx(
            deploy_account_tx_args! {
                class_hash: test_contract_class_hash,
                max_fee,
                contract_address_salt: constructor_address_salt,
                deployer_address: sender_address,
                version: tx_version
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

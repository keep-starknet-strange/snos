use blockifier::block_context::BlockContext;
use blockifier::invoke_tx_args;
use blockifier::state::cached_state::CachedState;
use blockifier::test_utils::{BALANCE, CairoVersion, create_calldata, NonceManager};
use blockifier::test_utils::contracts::FeatureContract;
use blockifier::test_utils::dict_state_reader::DictStateReader;
use blockifier::test_utils::initial_test_state::test_state;
use blockifier::transaction::test_utils::{account_invoke_tx, max_fee};
use blockifier::transaction::transactions::ExecutableTransaction;
use rstest::{fixture, rstest};
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use starknet_api::transaction::{Fee, TransactionVersion};
use snos::state::SharedState;

#[fixture]
pub fn block_context() -> BlockContext {
    BlockContext::create_for_account_testing()
}

#[fixture]
pub fn simple_block(
    block_context: BlockContext,
    max_fee: Fee,
    #[default(CairoVersion::Cairo0)] cairo_version: CairoVersion,
    #[default(TransactionVersion::ZERO)] tx_version: TransactionVersion,
    #[default(false)] only_query: bool,
) -> CachedState<DictStateReader> {
    let account = FeatureContract::AccountWithoutValidations(cairo_version);
    let test_contract = FeatureContract::TestContract(cairo_version);
    let erc20 = FeatureContract::ERC20;
    let mut state = test_state(&block_context, BALANCE, &[(account, 1), (erc20, 1), (test_contract, 1)]);

    let account_address = account.get_instance_address(0);
    let contract_address = test_contract.get_instance_address(0);
    let mut nonce_manager = NonceManager::default();

    let tx = account_invoke_tx(invoke_tx_args! {
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

    // Invoke a function from the newly deployed contract.
    let tx_execution_info = tx.execute(&mut state, &block_context, true, true).unwrap();

    state
}
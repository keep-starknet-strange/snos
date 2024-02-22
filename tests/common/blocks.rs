use std::collections::HashMap;

use blockifier::block_context::BlockContext;
use blockifier::execution::contract_class::ContractClass::V0;
use blockifier::invoke_tx_args;
use blockifier::state::state_api::StateReader;
use blockifier::test_utils::contracts::FeatureContract;
use blockifier::test_utils::initial_test_state::test_state;
use blockifier::test_utils::{create_calldata, CairoVersion, NonceManager, BALANCE};
use blockifier::transaction::objects::FeeType;
use blockifier::transaction::test_utils::max_fee;
use blockifier::transaction::transactions::ExecutableTransaction;
use cairo_vm::Felt252;
use rstest::fixture;
use snos::execution::helper::ExecutionHelperWrapper;
use snos::hints::block_context::block_number;
use snos::io::input::{ContractState, StarknetOsInput, StorageCommitment};
use starknet_api::block::BlockNumber;
use starknet_api::core::ClassHash;
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedContractClass;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use starknet_api::transaction::{Fee, TransactionVersion};

use crate::common::transaction_utils::{account_invoke_tx, deprecated_class, to_felt252};

#[fixture]
pub fn block_context() -> BlockContext {
    BlockContext { block_number: BlockNumber(0), ..BlockContext::create_for_account_testing() }
}

#[fixture]
pub fn simple_block(
    block_context: BlockContext,
    max_fee: Fee,
    #[default(CairoVersion::Cairo0)] cairo_version: CairoVersion,
    #[default(TransactionVersion::ZERO)] tx_version: TransactionVersion,
    #[default(false)] only_query: bool,
) -> (StarknetOsInput, ExecutionHelperWrapper) {
    let account = FeatureContract::AccountWithoutValidations(cairo_version);
    let test_contract = FeatureContract::TestContract(cairo_version);
    let erc20 = FeatureContract::ERC20;

    let mut state = test_state(&block_context, BALANCE, &[(account, 1), (erc20, 1), (test_contract, 1)]);

    let account_address = account.get_instance_address(0);
    let contract_address = test_contract.get_instance_address(0);
    let mut nonce_manager = NonceManager::default();

    let (account_tx, account_tx_internal) = account_invoke_tx(invoke_tx_args! {
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

    let changes =
        state.get_actual_state_changes_for_fee_charge(block_context.fee_token_address(&FeeType::Eth), None).unwrap();

    let mut deprecated_compiled_classes: HashMap<Felt252, DeprecatedContractClass> = HashMap::default();

    for h in changes.class_hash_updates.values() {
        let blockifier_class = state.get_compiled_contract_class(h.clone()).unwrap();
        if let V0(_) = blockifier_class {
            deprecated_compiled_classes.insert(to_felt252(&h.0), deprecated_class(h));
        }
    }

    // Invoke a function from the newly deployed contract.
    let tx_execution_info = account_tx.execute(&mut state, &block_context, true, true).unwrap();

    let mut contracts: HashMap<Felt252, ContractState> = tx_execution_info
        .execute_call_info
        .clone()
        .unwrap()
        .get_visited_storage_entries()
        .iter()
        .map(|(address, _)| (to_felt252(address.0.key()), ContractState::default()))
        .collect();

    contracts.insert(Felt252::from(0), ContractState::default());
    contracts.insert(Felt252::from(1), ContractState::default());

    let os_input = StarknetOsInput {
        contract_state_commitment_info: Default::default(),
        contract_class_commitment_info: Default::default(),
        deprecated_compiled_classes,
        compiled_classes: Default::default(),
        compiled_class_visited_pcs: Default::default(),
        contracts,
        class_hash_to_compiled_class_hash: Default::default(),
        general_config: Default::default(),
        transactions: vec![account_tx_internal],
        block_hash: Default::default(),
    };

    let tx_execution_infos = vec![tx_execution_info];

    let execution_helper = ExecutionHelperWrapper::new(tx_execution_infos, &block_context);
    (os_input, execution_helper)
}

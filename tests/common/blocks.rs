use std::collections::HashMap;

use blockifier::block_context::BlockContext;
use blockifier::execution::contract_class::ContractClass::V0;
use blockifier::invoke_tx_args;
use blockifier::state::state_api::StateReader;
use blockifier::test_utils::{BALANCE, CairoVersion, create_calldata, NonceManager};
use blockifier::test_utils::contracts::FeatureContract;
use blockifier::transaction::objects::FeeType;
use blockifier::transaction::test_utils;
use blockifier::transaction::test_utils::max_fee;
use blockifier::transaction::transactions::ExecutableTransaction;
use cairo_vm::Felt252;
use rstest::fixture;
use starknet_api::block::BlockNumber;
use starknet_api::core::ContractAddress;
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedContractClass;
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::stark_felt;
use starknet_api::transaction::{Fee, TransactionVersion};

use snos::execution::helper::ExecutionHelperWrapper;
use snos::io::input::{ContractState, StarknetOsInput};

use crate::common::block_utils::{deprecated_class, get_contracts, test_state};
use crate::common::transaction_utils::{to_felt252, to_internal_tx};

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

    println!("contract addresses:");
    println!("\terc20(eth): {}", to_felt252(block_context.fee_token_address(&FeeType::Eth).0.key()));
    println!("\terc20(strk): {}", to_felt252(block_context.fee_token_address(&FeeType::Strk).0.key()));
    println!("\taccount: {}", to_felt252(account_address.0.key()));
    println!("\tcontract: {}", to_felt252(contract_address.0.key()));

    let account_tx = test_utils::account_invoke_tx(invoke_tx_args! {
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

    let account_tx_intenal = to_internal_tx(&account_tx);

    let tx_execution_info = account_tx.execute(&mut state, &block_context, true, true).unwrap();

    let mut contracts = get_contracts(&state);

    let mut deprecated_compiled_classes: HashMap<Felt252, DeprecatedContractClass> = Default::default();

    for c in contracts.keys() {
        let class_hash = state
            .get_class_hash_at(
                ContractAddress::try_from(StarkHash::try_from(c.to_hex_string().as_str()).unwrap()).unwrap(),
            )
            .unwrap();
        let blockifier_class = state.get_compiled_contract_class(class_hash).unwrap();
        if let V0(_) = blockifier_class {
            deprecated_compiled_classes.insert(to_felt252(&class_hash.0), deprecated_class(class_hash));
        }
    }

    contracts.insert(Felt252::from(0), ContractState::default());
    contracts.insert(Felt252::from(1), ContractState::default());

    println!("contracts: {:?}\ndeprecated_compiled_classes: {:?}", contracts.len(), deprecated_compiled_classes.len());

    println!("contracts to class_hash");
    for (a, c) in &contracts {
        println!("\t{} -> {}", a, c.contract_hash);
    }

    println!("deprecated classes");
    for (c, _) in &deprecated_compiled_classes {
        println!("\t{}", c);
    }

    let mut class_hash_to_compiled_class_hash: HashMap<Felt252, Felt252> = Default::default();
    for h in deprecated_compiled_classes.keys() {
        class_hash_to_compiled_class_hash.insert(h.clone(), h.clone());
    }

    println!("class_hash to compiled_class_hash");
    for (ch, cch) in &class_hash_to_compiled_class_hash {
        println!("\t{} -> {} class", ch, cch);
    }

    let os_input = StarknetOsInput {
        contract_state_commitment_info: Default::default(),
        contract_class_commitment_info: Default::default(),
        deprecated_compiled_classes,
        compiled_classes: Default::default(),
        compiled_class_visited_pcs: Default::default(),
        contracts,
        class_hash_to_compiled_class_hash,
        general_config: Default::default(),
        transactions: vec![account_tx_intenal],
        block_hash: Default::default(),
    };

    let tx_execution_infos = vec![tx_execution_info];

    let execution_helper = ExecutionHelperWrapper::new(tx_execution_infos, &block_context);
    (os_input, execution_helper)
}

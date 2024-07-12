use std::sync::Arc;

use blockifier::abi::abi_utils::selector_from_name;
use blockifier::context::BlockContext;
use blockifier::test_utils::declare::declare_tx;
use blockifier::test_utils::deploy_account::deploy_account_tx;
use blockifier::test_utils::invoke::invoke_tx;
use blockifier::test_utils::{create_calldata, NonceManager};
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::test_utils::{account_invoke_tx, calculate_class_info_for_testing, max_fee};
use blockifier::transaction::transaction_execution::Transaction;
use blockifier::transaction::transactions::L1HandlerTransaction;
use blockifier::{declare_tx_args, deploy_account_tx_args, invoke_tx_args};
use rstest::{fixture, rstest};
use snos::storage::storage_utils::deprecated_contract_class_api2vm;
use starknet_api::core::{calculate_contract_address, ContractAddress, EntryPointSelector};
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use starknet_api::transaction::{Calldata, ContractAddressSalt, TransactionSignature, TransactionVersion};

use crate::common::block_context;
use crate::common::state::{init_logging, load_cairo0_contract, StarknetStateBuilder, StarknetTestState};
use crate::common::transaction_utils::execute_txs_and_run_os;
use crate::declare_txn_tests::default_testing_resource_bounds;

macro_rules! build_invoke_tx {
    ($defaults:expr, $nonce_manager:expr, $contract_address:expr, $entry_point_selector:expr, $calldata:expr $(,)?) => {{
        let tx_args = invoke_tx_args! {
            sender_address: $defaults.account_address.clone(),
            calldata: create_calldata($contract_address, $entry_point_selector, &$calldata),
            nonce: $nonce_manager.next($defaults.account_address.clone()),
        };

        Transaction::AccountTransaction(AccountTransaction::Invoke(invoke_tx(tx_args)))
    }};
    (
        $defaults:expr,
        $nonce_manager:expr,
        $contract_address:expr,
        $entry_point_selector:expr,
        $calldata:expr,
        $signature:expr $(,)?
    ) => {{
        let tx_args = invoke_tx_args! {
            sender_address: $defaults.account_address.clone(),
            calldata: create_calldata($contract_address, $entry_point_selector, &$calldata),
            nonce: $nonce_manager.next($defaults.account_address.clone()),
            signature: TransactionSignature($signature),
        };

        Transaction::AccountTransaction(AccountTransaction::Invoke(invoke_tx(tx_args)))
    }};
}

struct BuildInvokeTxArgs {
    account_address: ContractAddress,
    // max_fee: Fee,
}

fn get_contract_address_by_index(contracts: &Vec<ContractAddress>, index: usize) -> ContractAddress {
    *contracts.get(index).unwrap()
}

fn deploy_contract(
    contract: &str,
    initial_state: &StarknetTestState,
    account_address: &ContractAddress,
    deploy_account_address: &ContractAddress,
    nonce_manager: &mut NonceManager,
    txs: &mut Vec<Transaction>,
    salt: StarkFelt,
    constructor_calldata: Vec<StarkFelt>,
) -> Result<ContractAddress, &'static str> {
    let contract = initial_state.cairo0_contracts.get(contract).ok_or("Contract not found")?;

    let class = deprecated_contract_class_api2vm(&contract.class).map_err(|_| "Failed to get VM class")?;

    let class_info = calculate_class_info_for_testing(class);
    let declare_tx = declare_tx(
        declare_tx_args! {
            sender_address: account_address.clone(),
            resource_bounds: default_testing_resource_bounds(),
            class_hash: contract.class_hash,
            version: TransactionVersion::ONE,
            nonce: nonce_manager.next(account_address.clone())
        },
        class_info,
    );

    txs.push(Transaction::AccountTransaction(declare_tx));

    let mut ctor_calldata = vec![
        contract.class_hash.0, // Class hash.
        salt,                  // Salt.
    ];
    ctor_calldata.push(stark_felt!(constructor_calldata.len() as u128)); // Constructor calldata length.
    ctor_calldata.extend(constructor_calldata.iter());
    let invoke_tx = account_invoke_tx(invoke_tx_args! {
        sender_address: deploy_account_address.clone(),
        calldata: create_calldata(
            deploy_account_address.clone(),
            "deploy_contract",
            &ctor_calldata
        ),
        version: TransactionVersion::ONE,
        resource_bounds: default_testing_resource_bounds(),
        nonce: nonce_manager.next(deploy_account_address.clone())
    });

    txs.push(Transaction::AccountTransaction(invoke_tx));

    let delegate_proxy_address = calculate_contract_address(
        ContractAddressSalt(salt),
        contract.class_hash,
        &Calldata(constructor_calldata.into()),
        deploy_account_address.clone(),
    )
    .map_err(|_| "Failed to calculate the contract address")?;

    Ok(delegate_proxy_address)
}

#[fixture]
pub async fn initial_state_run_os_v1(
    block_context: BlockContext,
    #[from(init_logging)] _logging: (),
) -> StarknetTestState {
    let token_for_testing = load_cairo0_contract("token_for_testing");
    let dummy_token = load_cairo0_contract("dummy_token");
    let dummy_account = load_cairo0_contract("account_with_dummy_validate");
    let test_contract = load_cairo0_contract("test_contract_run_os");
    let delegate_proxy_contract = load_cairo0_contract("delegate_proxy");
    let test_contract2 = load_cairo0_contract("test_contract2");

    StarknetStateBuilder::new(&block_context)
        .add_cairo0_contract(token_for_testing.0, token_for_testing.1)
        .add_cairo0_contract(dummy_token.0, dummy_token.1)
        .add_cairo0_contract(dummy_account.0, dummy_account.1)
        .add_cairo0_contract(test_contract.0, test_contract.1)
        .add_cairo0_contract(delegate_proxy_contract.0, delegate_proxy_contract.1)
        .add_cairo0_contract(test_contract2.0, test_contract2.1)
        .build()
        .await
}

#[rstest]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn run_os(#[future] initial_state_run_os_v1: StarknetTestState) {
    let mut nonce_manager = NonceManager::default();
    let initial_state = initial_state_run_os_v1.await;

    let dummy_token = initial_state.cairo0_contracts.get("dummy_token").unwrap();
    let dummy_account = initial_state.cairo0_contracts.get("account_with_dummy_validate").unwrap();

    let deploy_token_tx_args = deploy_account_tx_args! {
        class_hash: dummy_token.class_hash,
        version: TransactionVersion::ONE,
    };
    let inner_deploy_token_tx = deploy_account_tx(deploy_token_tx_args, &mut nonce_manager);
    let fee_token_address = inner_deploy_token_tx.contract_address;
    let deploy_token_tx = AccountTransaction::DeployAccount(inner_deploy_token_tx);

    let deploy_account_tx_args = deploy_account_tx_args! {
        class_hash: dummy_account.class_hash,
        version: TransactionVersion::ONE,
    };
    let inner_deploy_account_tx = deploy_account_tx(deploy_account_tx_args, &mut nonce_manager);
    let account_address = dummy_account.address;
    let deploy_account_address = inner_deploy_account_tx.contract_address;
    // assert_eq!(dummy_account.address, account_address);
    let deploy_account_tx = AccountTransaction::DeployAccount(inner_deploy_account_tx);

    let fund_account_tx_args = invoke_tx_args! {
        sender_address: fee_token_address,
        calldata: create_calldata(fee_token_address, "transfer", &[*account_address.0, 2u128.pow(120).into(), 0u128.into()]),
        nonce: nonce_manager.next(fee_token_address),
    };

    let fund_account_tx = AccountTransaction::Invoke(invoke_tx(fund_account_tx_args));

    let mut init_txns: Vec<Transaction> =
        vec![deploy_token_tx, fund_account_tx, deploy_account_tx].into_iter().map(Into::into).collect();

    let mut txns = prepare_extensive_os_test_params(
        &initial_state,
        &mut nonce_manager,
        account_address,
        deploy_account_address,
        fee_token_address,
        block_context(),
    )
    .await;

    init_txns.append(&mut txns);
    let res = execute_txs_and_run_os(
        initial_state.cached_state,
        block_context(),
        init_txns,
        initial_state.cairo0_compiled_classes,
        initial_state.cairo1_compiled_classes,
    )
    .await
    .unwrap();

    dbg!(res.1);
}

async fn prepare_extensive_os_test_params(
    initial_state: &StarknetTestState,
    nonce_manager: &mut NonceManager,
    account_address: ContractAddress,
    deploy_account_address: ContractAddress,
    fee_token_address: ContractAddress,
    block_context: BlockContext,
) -> Vec<Transaction> {
    let mut txs = Vec::new();
    let mut deployed_txs_addresses = Vec::new();
    let salts = vec![17u128, 42, 53];
    let calldatas = vec![vec![321u128, 543], vec![111, 987], vec![444, 0]];

    let test_contract = initial_state.cairo0_contracts.get("test_contract_run_os").unwrap();

    for (salt, calldata) in salts.into_iter().zip(calldatas.into_iter()) {
        let constructor_calldata: Vec<_> = calldata.iter().map(|felt| stark_felt!(*felt)).collect();
        deployed_txs_addresses.push(
            deploy_contract(
                "test_contract_run_os",
                initial_state,
                &account_address,
                &deploy_account_address,
                nonce_manager,
                &mut txs,
                salt.into(),
                constructor_calldata,
            )
            .unwrap(),
        );
    }

    let defaults = BuildInvokeTxArgs { account_address: deploy_account_address };

    txs.push(build_invoke_tx! {
            &defaults,
            nonce_manager,
            get_contract_address_by_index(&deployed_txs_addresses, 0),
            "set_value",
            vec![85u128.into(), 47u128.into()],
    });

    txs.push(build_invoke_tx!(
        &defaults,
        nonce_manager,
        get_contract_address_by_index(&deployed_txs_addresses, 0),
        "set_value",
        vec![81u128.into(), 0u128.into()],
    ));

    txs.push(build_invoke_tx!(
        &defaults,
        nonce_manager,
        get_contract_address_by_index(&deployed_txs_addresses, 2),
        "set_value",
        vec![97u128.into(), 0u128.into()],
    ));

    txs.push(build_invoke_tx!(
        &defaults,
        nonce_manager,
        get_contract_address_by_index(&deployed_txs_addresses, 1),
        "entry_point",
        vec![]
    ));

    txs.push(build_invoke_tx!(
        &defaults,
        nonce_manager,
        get_contract_address_by_index(&deployed_txs_addresses, 0),
        "test_builtins",
        vec![]
    ));

    // Fails

    // txs.push(build_invoke_tx!(
    //     &defaults,
    //     nonce_manager,
    //     get_contract_address_by_index(&deployed_txs_addresses, 1),
    //     "test_get_block_timestamp",
    //     vec![1000u128.into()],
    // ));

    txs.push(build_invoke_tx!(
        &defaults,
        nonce_manager,
        get_contract_address_by_index(&deployed_txs_addresses, 1),
        "test_emit_event",
        vec![1u128.into(), 1991u128.into(), 1u128.into(), 2021u128.into()],
    ));

    // Fails

    // txs.push(build_invoke_tx!(
    //     &defaults,
    //     nonce_manager,
    //     get_contract_address_by_index(&deployed_txs_addresses, 0),
    //     "test_get_block_number",
    //     vec![(block_context.block_info().block_number.0 + 1).into()],
    // ));

    txs.push(build_invoke_tx!(
        &defaults,
        nonce_manager,
        get_contract_address_by_index(&deployed_txs_addresses, 0),
        "test_call_contract",
        vec![
            get_contract_address_by_index(&deployed_txs_addresses, 0).into(),
            selector_from_name("send_message").0.into(),
            1u128.into(),
            85u128.into(),
        ],
    ));

    // # The transaction above should send the following message.
    // message_to_l1 = StarknetMessageToL1(
    //     from_address=contract_addresses[0], to_address=85, payload=[12, 34]
    // )

    txs.push(build_invoke_tx!(
        &defaults,
        nonce_manager,
        get_contract_address_by_index(&deployed_txs_addresses, 0),
        "test_call_contract",
        vec![
            get_contract_address_by_index(&deployed_txs_addresses, 1).into(),
            selector_from_name("test_get_caller_address").0.into(),
            1u128.into(),
            get_contract_address_by_index(&deployed_txs_addresses, 0).into(), // Expected address.
        ],
    ));

    txs.push(build_invoke_tx!(
        &defaults,
        nonce_manager,
        get_contract_address_by_index(&deployed_txs_addresses, 0),
        "test_get_contract_address",
        vec![get_contract_address_by_index(&deployed_txs_addresses, 0).into()], // Expected address.
    ));
    let delegate_proxy_address = deploy_contract(
        "delegate_proxy",
        initial_state,
        &account_address,
        &deploy_account_address,
        nonce_manager,
        &mut txs,
        0u128.into(),
        vec![],
    )
    .unwrap();
    deployed_txs_addresses.push(delegate_proxy_address);

    txs.push(build_invoke_tx!(
        &defaults,
        nonce_manager,
        delegate_proxy_address,
        "set_implementation_hash",
        vec![test_contract.class_hash.0.into()],
    ));

    txs.push(build_invoke_tx!(
        &defaults,
        nonce_manager,
        delegate_proxy_address,
        "test_get_contract_address",
        vec![delegate_proxy_address.into()]
    ));

    txs.push(build_invoke_tx!(
        &defaults,
        nonce_manager,
        delegate_proxy_address,
        "set_value",
        vec![123u128.into(), 456u128.into()]
    ));

    txs.push(build_invoke_tx!(
        &defaults,
        nonce_manager,
        delegate_proxy_address,
        "test_get_caller_address",
        vec![deploy_account_address.into()],
    ));

    // txs.push(build_invoke_tx!(
    //     &defaults,
    //     nonce_manager,
    //     get_contract_address_by_index(&deployed_txs_addresses, 0),
    //     "test_call_contract",
    //     vec![
    //         delegate_proxy_address.into(),
    //         selector_from_name("test_get_sequencer_address").0,
    //         1u128.into(),
    //         *fee_token_address.0, // This expects general_config.sequencer_address,
    //     ],
    // ));

    // # Invoke the l1_handler deposit(from_address=85, amount=2) through the delegate proxy.
    let calldata_args = vec![stark_felt!(85_u16), stark_felt!(2_u16)];
    let l1_tx = L1HandlerTransaction {
        paid_fee_on_l1: max_fee(),
        tx: starknet_api::transaction::L1HandlerTransaction {
            contract_address: delegate_proxy_address,
            entry_point_selector: EntryPointSelector(selector_from_name("deposit").0),
            calldata: Calldata(Arc::new(calldata_args)),
            ..Default::default()
        },
        tx_hash: Default::default(),
    };
    txs.push(Transaction::L1HandlerTransaction(l1_tx));

    // # The l1 handler above should consume the following message.
    // message_to_l2 = StarknetMessageToL2(
    //     from_address=85,
    //     to_address=delegate_proxy_address,
    //     l1_handler_selector=selector_from_name("deposit"),
    //     payload=[2],
    //     nonce=0,
    // )
    txs.push(build_invoke_tx!(
        &defaults,
        nonce_manager,
        get_contract_address_by_index(&deployed_txs_addresses, 0),
        "test_library_call_syntactic_sugar",
        vec![test_contract.class_hash.0],
    ));

    txs.push(build_invoke_tx!(
        &defaults,
        nonce_manager,
        get_contract_address_by_index(&deployed_txs_addresses, 0),
        "add_signature_to_counters",
        vec![2021u128.into()],
        vec![100u128.into(), 200u128.into()],
    ));

    // let get_tx_info_tx = build_invoke_tx!(
    //     &defaults,
    //     nonce_manager,
    //     get_contract_address_by_index(&deployed_txs_addresses, 0),
    //     "test_call_contract",
    //     vec![
    //         delegate_proxy_address.into(),
    //         selector_from_name("test_get_tx_info").0.into(),
    //         1u128.into(),
    //         account_address.into(),
    //     ],
    //     vec![100u128.into()],
    // );
    // txs.push(get_tx_info_tx);

    // # Declare test_contract2.
    let test_contract2 = initial_state.cairo0_contracts.get("test_contract2").unwrap();
    // initial_state.cairo0_contracts.get("test_contract2").unwrap();
    deployed_txs_addresses.push(test_contract2.address);

    let class_hash = test_contract2.class_hash;

    let class = deprecated_contract_class_api2vm(&test_contract2.class).unwrap();

    let class_info = calculate_class_info_for_testing(class);

    let declare_tx = blockifier::test_utils::declare::declare_tx(
        declare_tx_args! {
            sender_address: account_address,
            version: TransactionVersion::ONE,
            nonce: nonce_manager.next(account_address),
            class_hash: class_hash.into(),
        },
        class_info,
    );
    txs.push(Transaction::AccountTransaction(declare_tx));

    let tx = build_invoke_tx!(
        &defaults,
        nonce_manager,
        get_contract_address_by_index(&deployed_txs_addresses, 1),
        "test_library_call",
        vec![
            test_contract2.class_hash.0.into(),
            selector_from_name("test_storage_write").0.into(),
            2u128.into(),
            555u128.into(),
            888u128.into(),
        ],
        vec![100u128.into()],
    );
    txs.push(tx);
    let tx = build_invoke_tx!(
        &defaults,
        nonce_manager,
        get_contract_address_by_index(&deployed_txs_addresses, 1),
        "test_library_call_l1_handler",
        vec![
            test_contract2.class_hash.0.into(),
            selector_from_name("test_l1_handler_storage_write").0.into(),
            3u128.into(),
            85u128.into(),
            666u128.into(),
            999u128.into(),
        ],
        vec![100u128.into()],
    );
    txs.push(tx);

    let tx = build_invoke_tx!(
        &defaults,
        nonce_manager,
        get_contract_address_by_index(&deployed_txs_addresses, 0),
        "test_replace_class",
        vec![test_contract2.class_hash.0.into()],
    );
    txs.push(tx);

    txs
}

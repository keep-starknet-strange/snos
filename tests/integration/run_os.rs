use std::collections::HashMap;
use std::sync::Arc;

use blockifier::abi::abi_utils::selector_from_name;
use blockifier::context::BlockContext;
use blockifier::state::cached_state::CachedState;
use blockifier::test_utils::declare::declare_tx;
use blockifier::test_utils::deploy_account::deploy_account_tx;
use blockifier::test_utils::dict_state_reader::DictStateReader;
use blockifier::test_utils::invoke::invoke_tx;
use blockifier::test_utils::{create_calldata, NonceManager};
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::test_utils::{account_invoke_tx, calculate_class_info_for_testing, max_fee};
use blockifier::transaction::transaction_execution::Transaction;
use blockifier::transaction::transactions::{ExecutableTransaction, L1HandlerTransaction};
use blockifier::{declare_tx_args, deploy_account_tx_args, invoke_tx_args};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rstest::rstest;
use snos::crypto::pedersen::PedersenHash;
use snos::execution::helper::GenCallIter;
use snos::starknet::business_logic::fact_state::state::SharedState;
use snos::starknet::business_logic::utils::write_deprecated_compiled_class_fact;
use snos::storage::dict_storage::DictStorage;
use snos::storage::storage::FactFetchingContext;
use snos::storage::storage_utils::{deprecated_contract_class_api2vm, unpack_blockifier_state_async};
use snos::utils::felt_api2vm;
use starknet_api::core::{
    calculate_contract_address, ClassHash, CompiledClassHash, ContractAddress, EntryPointSelector,
};
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedCompiledClass;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use starknet_api::transaction::{Calldata, ContractAddressSalt, TransactionSignature, TransactionVersion};

use crate::common::state::{load_cairo0_contract, Cairo0Contract, DeprecatedContractDeployment};
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
    cairo0_contracts: &HashMap<String, DeprecatedContractDeployment>,
    account_address: &ContractAddress,
    deploy_account_address: &ContractAddress,
    nonce_manager: &mut NonceManager,
    txs: &mut Vec<Transaction>,
    salt: StarkFelt,
    constructor_calldata: Vec<StarkFelt>,
) -> Result<ContractAddress, &'static str> {
    let contract = cairo0_contracts.get(contract).ok_or("Contract not found")?;

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

    let contract_address = calculate_contract_address(
        ContractAddressSalt(salt),
        contract.class_hash,
        &Calldata(constructor_calldata.into()),
        deploy_account_address.clone(),
    )
    .map_err(|_| "Failed to calculate the contract address")?;

    Ok(contract_address)
}

#[rstest]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn run_os() {
    let mut nonce_manager = NonceManager::default();
    let block_context = BlockContext::create_for_account_testing();
    let mut address_generator = StdRng::seed_from_u64(1);

    let token_for_testing = load_cairo0_contract("token_for_testing");
    let dummy_token = load_cairo0_contract("dummy_token");
    let dummy_account = load_cairo0_contract("account_with_dummy_validate");
    let test_contract = load_cairo0_contract("test_contract_run_os");
    let delegate_proxy_contract = load_cairo0_contract("delegate_proxy");
    let test_contract2 = load_cairo0_contract("test_contract2");

    let deprecated_compiled_classes =
        [token_for_testing, dummy_token, dummy_account, test_contract, delegate_proxy_contract, test_contract2];

    let mut ffc: FactFetchingContext<DictStorage, PedersenHash> = FactFetchingContext::new(DictStorage::default());
    let mut dict_state_reader = DictStateReader::default();

    let mut deployed_contracts = HashMap::<String, DeprecatedContractDeployment>::new();
    let mut compiled_contract_classes = HashMap::<ClassHash, DeprecatedCompiledClass>::new();

    let cairo0_contracts = deprecated_compiled_classes.iter().map(|c| {
        (
            c.0.clone(),
            Cairo0Contract { deprecated_compiled_class: c.1.clone(), address: address_generator.gen::<u32>().into() },
        )
    });
    for (name, contract) in cairo0_contracts {
        let class_hash =
            write_deprecated_compiled_class_fact(contract.deprecated_compiled_class.clone(), &mut ffc).await.unwrap();
        let class_hash = ClassHash::try_from(class_hash).expect("Class hash is not in prime field");

        // Add entries in the dict state
        let vm_class = deprecated_contract_class_api2vm(&contract.deprecated_compiled_class).unwrap();
        dict_state_reader.class_hash_to_class.insert(class_hash, vm_class);
        dict_state_reader.class_hash_to_compiled_class_hash.insert(class_hash, CompiledClassHash(class_hash.0));

        log::debug!("Inserting deprecated class_hash_to_class: {:?} -> {:?}", contract.address, class_hash);
        dict_state_reader.address_to_class_hash.insert(contract.address.clone(), class_hash);

        deployed_contracts.insert(
            name.clone(),
            DeprecatedContractDeployment {
                class_hash,
                address: contract.address.clone(),
                class: contract.deprecated_compiled_class.clone(),
            },
        );
        compiled_contract_classes.insert(class_hash, contract.deprecated_compiled_class.clone());
    }

    let shared_state = SharedState::from_blockifier_state(ffc, dict_state_reader)
        .await
        .expect("failed to apply initial state as updates to SharedState");

    let mut cached_state = CachedState::from(shared_state);

    let dummy_token = deployed_contracts.get("token_for_testing").unwrap();
    let dummy_account = deployed_contracts.get("account_with_dummy_validate").unwrap();
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

    let deploy_account_tx = AccountTransaction::DeployAccount(inner_deploy_account_tx);

    let fund_account_tx_args = invoke_tx_args! {
        sender_address: fee_token_address,
        calldata: create_calldata(fee_token_address, "transfer", &[*account_address.0, 2u128.pow(120).into(), 0u128.into()]),
        nonce: nonce_manager.next(fee_token_address),
    };

    let fund_account_tx = AccountTransaction::Invoke(invoke_tx(fund_account_tx_args));

    let init_txns: Vec<Transaction> =
        vec![deploy_token_tx, fund_account_tx, deploy_account_tx].into_iter().map(Into::into).collect();

    let execution_infos: Vec<_> = init_txns
        .into_iter()
        .map(|tx| {
            let tx_result = tx.execute(&mut cached_state, &block_context, true, true);
            return match tx_result {
                Err(e) => {
                    log::error!("Transaction failed in blockifier: {}", e);
                    panic!("A transaction failed during execution");
                }
                Ok(info) => {
                    if info.is_reverted() {
                        log::error!("Transaction reverted: {:?}", info.revert_error);
                        log::warn!("TransactionExecutionInfo: {:?}", info);
                        panic!("A transaction reverted during execution");
                    }
                    info
                }
            };
        })
        .collect();

    for execution_info in execution_infos.iter() {
        for call_info in execution_info.gen_call_iterator() {
            assert!(!call_info.execution.failed, "Unexpected reverted transaction.");
        }
    }

    let mut tx_contracts: Vec<_> = vec![];

    let txns = prepare_extensive_os_test_params(
        &deployed_contracts,
        &mut nonce_manager,
        account_address,
        deploy_account_address,
        &mut tx_contracts,
        &block_context,
    )
    .await;

    // init_txns.extend(txns.into_iter());
    let (_, shared_state) = unpack_blockifier_state_async(cached_state).await.unwrap();
    // // init_txns.append(&mut txns);
    let cached_state = CachedState::from(shared_state);

    let (_pie, os_output) =
        execute_txs_and_run_os(cached_state, block_context, txns, compiled_contract_classes, Default::default())
            .await
            .unwrap();
    dbg!(&os_output);

    let output_messages_to_l1 = os_output.messages_to_l1;
    // message_to_l1 = StarknetMessageToL1(
    //     from_address=contract_addresses[0], to_address=85, payload=[12, 34]
    // )

    let expected_messages_to_l1 = [
        felt_api2vm(*tx_contracts[0].0.key()), // from address
        85.into(),                             // to address
        2.into(),                              // PAYLOAD_SIZE
        12.into(),                             // PAYLOAD_1
        34.into(),                             // PAYLOAD_1
    ];
    assert_eq!(&*output_messages_to_l1, expected_messages_to_l1);

    // message_to_l2 = StarknetMessageToL2(
    //     from_address=85,
    //     to_address=delegate_proxy_address,
    //     l1_handler_selector=get_selector_from_name("deposit"),
    //     payload=[2],
    //     nonce=0,
    // )
    let expected_messages_to_l2 = [
        85.into(),                             // from address
        felt_api2vm(*tx_contracts[3].0.key()), // the delegate_proxy_address
        0.into(),                              // Nonce
        felt_api2vm(selector_from_name("deposit").0),
        1u64.into(), // PAYLOAD_SIZE
        2u64.into(), // PAYLOAD_1
    ];

    assert_eq!(os_output.messages_to_l2, expected_messages_to_l2);
}

async fn prepare_extensive_os_test_params(
    cairo0_contracts: &HashMap<String, DeprecatedContractDeployment>,
    nonce_manager: &mut NonceManager,
    account_address: ContractAddress,
    deploy_account_address: ContractAddress,
    deployed_txs_addresses: &mut Vec<ContractAddress>,
    block_context: &BlockContext,
) -> Vec<Transaction> {
    let mut txs = Vec::new();
    let salts = vec![17u128, 42, 53];
    let calldatas = vec![vec![321u128, 543], vec![111, 987], vec![444, 0]];

    let test_contract = cairo0_contracts.get("test_contract_run_os").unwrap();

    for (salt, calldata) in salts.into_iter().zip(calldatas.into_iter()) {
        let constructor_calldata: Vec<_> = calldata.iter().map(|felt| stark_felt!(*felt)).collect();
        deployed_txs_addresses.push(
            deploy_contract(
                "test_contract_run_os",
                cairo0_contracts,
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

    txs.push(build_invoke_tx!(
        &defaults,
        nonce_manager,
        get_contract_address_by_index(&deployed_txs_addresses, 1),
        "test_get_block_timestamp",
        vec![1072023u128.into()],
    ));

    txs.push(build_invoke_tx!(
        &defaults,
        nonce_manager,
        get_contract_address_by_index(&deployed_txs_addresses, 1),
        "test_emit_event",
        vec![1u128.into(), 1991u128.into(), 1u128.into(), 2021u128.into()],
    ));

    txs.push(build_invoke_tx!(
        &defaults,
        nonce_manager,
        get_contract_address_by_index(&deployed_txs_addresses, 0),
        "test_get_block_number",
        vec![(block_context.block_info().block_number.0).into()],
    ));

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
        cairo0_contracts,
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

    txs.push(build_invoke_tx!(
        &defaults,
        nonce_manager,
        get_contract_address_by_index(&deployed_txs_addresses, 0),
        "test_call_contract",
        vec![
            delegate_proxy_address.into(),
            selector_from_name("test_get_sequencer_address").0,
            1u128.into(),
            4096u128.into()
        ],
    ));

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

    // UNCOMMENT THIS
    // let tx_args = invoke_tx_args! {
    //     sender_address: deploy_account_address,
    //     calldata: create_calldata(get_contract_address_by_index(&deployed_txs_addresses, 0),
    //     "test_call_contract",
    //     &vec![
    //         delegate_proxy_address.into(),
    //         selector_from_name("test_get_tx_info").0.into(),
    //         1u128.into(),
    //         (*deploy_account_address.0).into(),
    //     ]),
    //     nonce: nonce_manager.next(deploy_account_address),
    //     signature: TransactionSignature(vec![100u128.into()]),
    //     // max_fee: max_fee()
    // };

    // txs.push(Transaction::AccountTransaction(AccountTransaction::Invoke(invoke_tx(tx_args))));

    // # Declare test_contract2.
    let test_contract2 = cairo0_contracts.get("test_contract2").unwrap();

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

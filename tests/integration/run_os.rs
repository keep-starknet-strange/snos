use std::collections::HashMap;
use std::sync::Arc;

use blockifier::abi::abi_utils::selector_from_name;
use blockifier::block::BlockInfo;
use blockifier::context::{BlockContext, ChainInfo, FeeTokenAddresses};
use blockifier::state::cached_state::CachedState;
use blockifier::test_utils::declare::declare_tx;
use blockifier::test_utils::deploy_account::deploy_account_tx;
use blockifier::test_utils::invoke::invoke_tx;
use blockifier::test_utils::{create_calldata, NonceManager};
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::objects::TransactionExecutionInfo;
use blockifier::transaction::test_utils::{account_invoke_tx, calculate_class_info_for_testing, max_fee};
use blockifier::transaction::transaction_execution::Transaction;
use blockifier::transaction::transactions::{ExecutableTransaction, L1HandlerTransaction};
use blockifier::versioned_constants::VersionedConstants;
use blockifier::{declare_tx_args, deploy_account_tx_args, invoke_tx_args};
use rstest::{fixture, rstest};
use starknet_api::core::{calculate_contract_address, ChainId, ContractAddress, EntryPointSelector};
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, Fee, TransactionHash, TransactionSignature, TransactionVersion,
};
use starknet_os::crypto::pedersen::PedersenHash;
use starknet_os::execution::helper::GenCallIter;
use starknet_os::io::output::StarknetOsOutput;
use starknet_os::starknet::business_logic::fact_state::state::SharedState;
use starknet_os::storage::dict_storage::DictStorage;
use starknet_os::storage::storage_utils::unpack_blockifier_state_async;
use starknet_os::utils::felt_api2vm;

use crate::common::block_context;
use crate::common::blockifier_contracts::load_cairo0_feature_contract;
use crate::common::os_itest_contracts::load_os_itest_contract;
use crate::common::state::{init_logging, DeclaredDeprecatedContract, StarknetStateBuilder, StarknetTestState};
use crate::common::transaction_utils::execute_txs_and_run_os;
use crate::declare_txn_tests::default_testing_resource_bounds;

type ContractMap = HashMap<String, DeclaredDeprecatedContract>;

macro_rules! build_invoke_tx {
    (
        $deploy_account_address:expr,
        $nonce_manager:expr,
        $contract_address:expr,
        $entry_point_selector:expr,
        $calldata:expr $(,)?
    ) => {{
        let tx_args = invoke_tx_args! {
            sender_address: $deploy_account_address,
            calldata: create_calldata($contract_address, $entry_point_selector, &$calldata),
            nonce: $nonce_manager.next($deploy_account_address),
        };

        Transaction::AccountTransaction(AccountTransaction::Invoke(invoke_tx(tx_args)))
    }};
    (
        $deploy_account_address:expr,
        $nonce_manager:expr,
        $contract_address:expr,
        $entry_point_selector:expr,
        $calldata:expr,
        $signature:expr $(,)?
    ) => {{
        let tx_args = invoke_tx_args! {
            sender_address: $deploy_account_address,
            calldata: create_calldata($contract_address, $entry_point_selector, &$calldata),
            nonce: $nonce_manager.next($deploy_account_address),
            signature: TransactionSignature($signature),
        };

        Transaction::AccountTransaction(AccountTransaction::Invoke(invoke_tx(tx_args)))
    }};
}

struct InitialTxs {
    deploy_token_tx: blockifier::transaction::transactions::DeployAccountTransaction,
    deploy_account_tx: blockifier::transaction::transactions::DeployAccountTransaction,
    fund_account_tx: blockifier::transaction::transactions::InvokeTransaction,
    fee_token_address: ContractAddress,
    dummy_account_address: ContractAddress,
}

impl InitialTxs {
    #[allow(clippy::wrong_self_convention)]
    fn to_vec(self) -> Vec<Transaction> {
        vec![
            AccountTransaction::DeployAccount(self.deploy_token_tx).into(),
            AccountTransaction::Invoke(self.fund_account_tx).into(),
            AccountTransaction::DeployAccount(self.deploy_account_tx).into(),
        ]
    }
}

async fn create_initial_transactions(
    nonce_manager: &mut NonceManager,
    dummy_token: &DeclaredDeprecatedContract,
    dummy_account: &DeclaredDeprecatedContract,
) -> InitialTxs {
    let deploy_token_tx_args = deploy_account_tx_args! {
        class_hash: dummy_token.class_hash,
        version: TransactionVersion::ONE,
    };
    let deploy_token_tx = deploy_account_tx(deploy_token_tx_args, nonce_manager);
    let fee_token_address = deploy_token_tx.contract_address;

    let deploy_account_tx_args = deploy_account_tx_args! {
        class_hash: dummy_account.class_hash,
        version: TransactionVersion::ONE,
    };

    let deploy_account_tx = deploy_account_tx(deploy_account_tx_args, nonce_manager);
    let dummy_account_address = deploy_account_tx.contract_address;

    let fund_account_tx_args = invoke_tx_args! {
        sender_address: fee_token_address,
        calldata: create_calldata(fee_token_address, "transfer", &[*dummy_account_address.0, 2u128.pow(120).into(), 0u128.into()]),
        nonce: nonce_manager.next(fee_token_address),
    };
    let fund_account_tx = invoke_tx(fund_account_tx_args);

    InitialTxs { deploy_token_tx, deploy_account_tx, fund_account_tx, fee_token_address, dummy_account_address }
}

async fn prepare_extensive_os_test_params(
    cairo0_contracts: &ContractMap,
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
        let constructor_calldata: Vec<_> = calldata.iter().map(|&felt| stark_felt!(felt)).collect();
        deployed_txs_addresses.push(
            add_declare_and_deploy_contract_txs(
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

    let test_contract1_address = deployed_txs_addresses[0];
    let test_contract2_address = deployed_txs_addresses[1];
    let test_contract3_address = deployed_txs_addresses[2];

    txs.push(build_invoke_tx!(
        deploy_account_address,
        nonce_manager,
        test_contract1_address,
        "set_value",
        [85u128.into(), 47u128.into()],
    ));

    txs.push(build_invoke_tx!(
        deploy_account_address,
        nonce_manager,
        test_contract1_address,
        "set_value",
        [81u128.into(), 0u128.into()],
    ));

    txs.push(build_invoke_tx!(
        deploy_account_address,
        nonce_manager,
        test_contract3_address,
        "set_value",
        [97u128.into(), 0u128.into()],
    ));

    txs.push(build_invoke_tx!(deploy_account_address, nonce_manager, test_contract2_address, "entry_point", []));

    txs.push(build_invoke_tx!(deploy_account_address, nonce_manager, test_contract1_address, "test_builtins", []));

    txs.push(build_invoke_tx!(
        deploy_account_address,
        nonce_manager,
        test_contract2_address,
        "test_get_block_timestamp",
        [1072023u128.into()],
    ));

    txs.push(build_invoke_tx!(
        deploy_account_address,
        nonce_manager,
        test_contract2_address,
        "test_emit_event",
        [1u128.into(), 1991u128.into(), 1u128.into(), 2021u128.into()],
    ));

    txs.push(build_invoke_tx!(
        deploy_account_address,
        nonce_manager,
        test_contract1_address,
        "test_get_block_number",
        [block_context.block_info().block_number.0.into()],
    ));

    txs.push(build_invoke_tx!(
        deploy_account_address,
        nonce_manager,
        test_contract1_address,
        "test_call_contract",
        [test_contract1_address.into(), selector_from_name("send_message").0, 1u128.into(), 85u128.into(),],
    ));

    txs.push(build_invoke_tx!(
        deploy_account_address,
        nonce_manager,
        test_contract1_address,
        "test_call_contract",
        [
            test_contract2_address.into(),
            selector_from_name("test_get_caller_address").0,
            1u128.into(),
            test_contract1_address.into(), // Expected address.
        ],
    ));

    txs.push(build_invoke_tx!(
        deploy_account_address,
        nonce_manager,
        test_contract1_address,
        "test_get_contract_address",
        [test_contract1_address.into()], // Expected address.
    ));

    let delegate_proxy_address = add_declare_and_deploy_contract_txs(
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
        deploy_account_address,
        nonce_manager,
        delegate_proxy_address,
        "set_implementation_hash",
        [test_contract.class_hash.0],
    ));

    txs.push(build_invoke_tx!(
        deploy_account_address,
        nonce_manager,
        delegate_proxy_address,
        "test_get_contract_address",
        [delegate_proxy_address.into()]
    ));

    txs.push(build_invoke_tx!(
        deploy_account_address,
        nonce_manager,
        delegate_proxy_address,
        "set_value",
        [123u128.into(), 456u128.into()]
    ));

    txs.push(build_invoke_tx!(
        deploy_account_address,
        nonce_manager,
        delegate_proxy_address,
        "test_get_caller_address",
        [deploy_account_address.into()],
    ));

    txs.push(build_invoke_tx!(
        deploy_account_address,
        nonce_manager,
        test_contract1_address,
        "test_call_contract",
        [
            delegate_proxy_address.into(),
            selector_from_name("test_get_sequencer_address").0,
            1u128.into(),
            4096u128.into()
        ],
    ));

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

    txs.push(build_invoke_tx!(
        deploy_account_address,
        nonce_manager,
        test_contract1_address,
        "test_library_call_syntactic_sugar",
        [test_contract.class_hash.0],
    ));

    txs.push(build_invoke_tx!(
        deploy_account_address,
        nonce_manager,
        test_contract1_address,
        "add_signature_to_counters",
        [2021u128.into()],
        vec![100u128.into(), 200u128.into()],
    ));

    let inner_invoke_tx = {
        let tx_args = invoke_tx_args! {
            sender_address: deploy_account_address,
            calldata: create_calldata(test_contract1_address,
            "test_call_contract",
            &[
                delegate_proxy_address.into(),
                selector_from_name("test_get_tx_info").0,
                1u128.into(),
                (*deploy_account_address.0),
            ]),
            nonce: nonce_manager.next(deploy_account_address),
            signature: TransactionSignature(vec![100u128.into()]),
            max_fee: Fee(0x10000000000000000000000000u128),     // 2**100
        };
        let mut tx = invoke_tx(tx_args);
        tx.tx_hash = TransactionHash(stark_felt!("0x19c90daecc4e3ed29743b0331024b3014b9f2c4620ee7ec441b4a7ec330583"));
        tx
    };
    txs.push(Transaction::AccountTransaction(AccountTransaction::Invoke(inner_invoke_tx)));

    let test_contract2 = cairo0_contracts.get("test_contract2").unwrap();

    let class_hash = test_contract2.class_hash;
    let class = test_contract2.class.get_blockifier_contract_class().unwrap().clone();
    let class_info = calculate_class_info_for_testing(class.into());

    let declare_tx = declare_tx(
        declare_tx_args! {
            sender_address: account_address,
            version: TransactionVersion::ONE,
            nonce: nonce_manager.next(account_address),
            class_hash: class_hash,
        },
        class_info,
    );
    txs.push(Transaction::AccountTransaction(declare_tx));

    txs.push(build_invoke_tx!(
        deploy_account_address,
        nonce_manager,
        test_contract2_address,
        "test_library_call",
        [
            test_contract2.class_hash.0,
            selector_from_name("test_storage_write").0,
            2u128.into(),
            555u128.into(),
            888u128.into(),
        ],
        vec![100u128.into()],
    ));

    txs.push(build_invoke_tx!(
        deploy_account_address,
        nonce_manager,
        test_contract2_address,
        "test_library_call_l1_handler",
        [
            test_contract2.class_hash.0,
            selector_from_name("test_l1_handler_storage_write").0,
            3u128.into(),
            85u128.into(),
            666u128.into(),
            999u128.into(),
        ],
        vec![100u128.into()],
    ));

    txs.push(build_invoke_tx!(
        deploy_account_address,
        nonce_manager,
        test_contract1_address,
        "test_replace_class",
        [test_contract2.class_hash.0],
    ));

    txs
}

fn build_block_context(chain_id: ChainId, fee_token_address: ContractAddress) -> BlockContext {
    let block_info = BlockInfo::create_for_testing();
    let versioned_constants = VersionedConstants::create_for_account_testing();

    let chain_info = ChainInfo {
        chain_id,
        fee_token_addresses: FeeTokenAddresses {
            strk_fee_token_address: fee_token_address,
            eth_fee_token_address: fee_token_address,
        },
    };

    BlockContext::new_unchecked(&block_info, &chain_info, &versioned_constants)
}

#[allow(clippy::too_many_arguments)]
fn add_declare_and_deploy_contract_txs(
    contract: &str,
    cairo0_contracts: &ContractMap,
    account_address: &ContractAddress,
    deploy_account_address: &ContractAddress,
    nonce_manager: &mut NonceManager,
    txs: &mut Vec<Transaction>,
    salt: StarkFelt,
    constructor_calldata: Vec<StarkFelt>,
) -> Result<ContractAddress, &'static str> {
    let contract = cairo0_contracts.get(contract).ok_or("Contract not found")?;

    let class = contract.class.get_blockifier_contract_class().map_err(|_| "Failed to get VM class")?;
    let class_info = calculate_class_info_for_testing(class.clone().into());
    let declare_tx = declare_tx(
        declare_tx_args! {
            sender_address: *account_address,
            resource_bounds: default_testing_resource_bounds(),
            class_hash: contract.class_hash,
            version: TransactionVersion::ONE,
            nonce: nonce_manager.next(*account_address)
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
        sender_address: *deploy_account_address,
        calldata: create_calldata(
            *deploy_account_address,
            "deploy_contract",
            &ctor_calldata
        ),
        version: TransactionVersion::ONE,
        resource_bounds: default_testing_resource_bounds(),
        nonce: nonce_manager.next(*deploy_account_address)
    });

    txs.push(Transaction::AccountTransaction(invoke_tx));

    let contract_address = calculate_contract_address(
        ContractAddressSalt(salt),
        contract.class_hash,
        &Calldata(constructor_calldata.into()),
        *deploy_account_address,
    )
    .map_err(|_| "Failed to calculate the contract address")?;

    Ok(contract_address)
}

fn execute_transaction(
    tx: Transaction,
    cached_state: &mut CachedState<SharedState<DictStorage, PedersenHash>>,
    block_context: &BlockContext,
) -> TransactionExecutionInfo {
    let tx_result = tx.execute(cached_state, block_context, true, true);
    match tx_result {
        Err(e) => {
            log::error!("Transaction failed in blockifier: {}", e);
            panic!("A transaction failed during execution");
        }
        Ok(info) => {
            if info.is_reverted() {
                log::error!("Transaction reverted: {:?}", info.revert_error);
                log::error!("TransactionExecutionInfo: {:?}", info);
                panic!("A transaction reverted during execution");
            }
            info
        }
    }
}

fn validate_execution_infos(execution_infos: &[TransactionExecutionInfo]) {
    for execution_info in execution_infos {
        for call_info in execution_info.gen_call_iterator() {
            assert!(!call_info.execution.failed, "Unexpected reverted transaction.");
        }
    }
}

fn validate_os_output(os_output: &StarknetOsOutput, tx_contracts: &[ContractAddress]) {
    let output_messages_to_l1 = &os_output.messages_to_l1;

    let expected_messages_to_l1 = [
        felt_api2vm(*tx_contracts[0].0.key()), // from address
        85.into(),                             // to address
        2.into(),                              // PAYLOAD_SIZE
        12.into(),                             // PAYLOAD_1
        34.into(),                             // PAYLOAD_1
    ];
    assert_eq!(output_messages_to_l1, &expected_messages_to_l1);

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

/// Fixture state where we declare all the contracts that need to exist before running
/// this integration test suite.
#[fixture]
pub async fn initial_state_full_itests(
    block_context: BlockContext,
    #[from(init_logging)] _logging: (),
) -> StarknetTestState {
    let account_with_dummy_validate = load_cairo0_feature_contract("account_with_dummy_validate");
    let delegate_proxy = load_os_itest_contract("delegate_proxy");
    let dummy_token = load_os_itest_contract("dummy_token");
    let test_contract_run_os = load_os_itest_contract("test_contract_run_os");
    let test_contract2 = load_os_itest_contract("test_contract2");
    let token_for_testing = load_os_itest_contract("token_for_testing");

    StarknetStateBuilder::new(&block_context)
        .declare_cairo0_contract(account_with_dummy_validate.0, account_with_dummy_validate.1)
        .declare_cairo0_contract(delegate_proxy.0, delegate_proxy.1)
        .declare_cairo0_contract(dummy_token.0, dummy_token.1)
        .declare_cairo0_contract(test_contract_run_os.0, test_contract_run_os.1)
        .declare_cairo0_contract(test_contract2.0, test_contract2.1)
        .declare_cairo0_contract(token_for_testing.0, token_for_testing.1)
        .build()
        .await
}

/// A full integration test that executes many transactions, simulating a block.
#[rstest]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn run_os_tests(#[future] initial_state_full_itests: StarknetTestState) {
    let initial_state = initial_state_full_itests.await;

    let chain_id = ChainId("SN_GOERLI".to_string());
    let mut nonce_manager = NonceManager::default();

    let dummy_token = initial_state.declared_cairo0_contracts.get("token_for_testing").unwrap();
    let dummy_account = initial_state.declared_cairo0_contracts.get("account_with_dummy_validate").unwrap();

    let initial_txs = create_initial_transactions(&mut nonce_manager, dummy_token, dummy_account).await;

    let block_context = build_block_context(chain_id, initial_txs.fee_token_address);
    let dummy_account_address = initial_txs.dummy_account_address;

    let init_txs = initial_txs.to_vec();
    let mut cached_state = initial_state.cached_state;

    // Execute the init transactions. This prepares the state for the rest of the integration
    // tests.
    let execution_infos: Vec<_> =
        init_txs.into_iter().map(|tx| execute_transaction(tx, &mut cached_state, &block_context)).collect();
    validate_execution_infos(&execution_infos);

    let mut tx_contracts = vec![];

    let txs = prepare_extensive_os_test_params(
        &initial_state.declared_cairo0_contracts,
        &mut nonce_manager,
        dummy_account_address,
        dummy_account_address,
        &mut tx_contracts,
        &block_context,
    )
    .await;

    let (_, shared_state) = unpack_blockifier_state_async(cached_state).await.unwrap();
    let cached_state = CachedState::from(shared_state);

    let (_pie, os_output) = execute_txs_and_run_os(
        cached_state,
        block_context,
        txs,
        initial_state.cairo0_compiled_classes,
        Default::default(),
    )
    .await
    .unwrap();

    validate_os_output(&os_output, &tx_contracts);
}

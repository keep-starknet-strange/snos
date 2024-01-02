use std::collections::HashMap;
use std::sync::Arc;

use blockifier::abi::abi_utils::selector_from_name;
use blockifier::abi::constants::N_STEPS_RESOURCE;
use blockifier::block_context::BlockContext;
use blockifier::invoke_tx_args;
use blockifier::state::cached_state::CachedState;
use blockifier::state::state_api::State;
use blockifier::test_utils::{deploy_account_tx, invoke_tx, DictStateReader, InvokeTxArgs, NonceManager};
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::objects::TransactionExecutionInfo;
use blockifier::transaction::transactions::ExecutableTransaction;
use cairo_vm::felt::felt_str;
use cairo_vm::vm::runners::builtin_runner::{
    BITWISE_BUILTIN_NAME, EC_OP_BUILTIN_NAME, HASH_BUILTIN_NAME, OUTPUT_BUILTIN_NAME, POSEIDON_BUILTIN_NAME,
    RANGE_CHECK_BUILTIN_NAME, SIGNATURE_BUILTIN_NAME,
};
use rstest::fixture;
use snos::config::{StarknetGeneralConfig, DEFAULT_FEE_TOKEN_ADDR};
use snos::state::SharedState;
use starknet_api::block::{BlockNumber, BlockTimestamp};
use starknet_api::core::{calculate_contract_address, ClassHash, ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{Calldata, ContractAddressSalt, Fee, TransactionSignature, TransactionVersion};
use starknet_api::{calldata, class_hash, contract_address, patricia_key, stark_felt};

use super::defs::{
    DELEGATE_PROXY_HASH_0_12_2, DUMMY_ACCOUNT_ADDRESS_0_12_2, DUMMY_ACCOUNT_HASH_0_12_2, DUMMY_TOKEN_HASH_0_12_2,
    EXPECTED_PREV_ROOT, TESTING_1_ADDREESS_0_12_2, TESTING_2_ADDREESS_0_12_2, TESTING_3_ADDREESS_0_12_2,
    TESTING_DELEGATE_ADDREESS_0_12_2, TESTING_FEE, TESTING_HASH_0_12_2, TESTING_HASH_2_0_12_2, TESTING_TRANSFER_AMOUNT,
    TOKEN_FOR_TESTING_HASH_0_12_2,
};
use super::utils::{load_class_v0, raw_deploy};

#[fixture]
pub fn block_context() -> BlockContext {
    let mut conf = StarknetGeneralConfig::default();
    conf.starknet_os_config.fee_token_address = contract_address!(DEFAULT_FEE_TOKEN_ADDR);

    let mut block_context = conf.empty_block_context();

    block_context.vm_resource_fee_cost = Arc::new(HashMap::from([
        (N_STEPS_RESOURCE.to_string(), 1_f64),
        (HASH_BUILTIN_NAME.to_string(), 0_f64),
        (RANGE_CHECK_BUILTIN_NAME.to_string(), 0_f64),
        (SIGNATURE_BUILTIN_NAME.to_string(), 0_f64),
        (BITWISE_BUILTIN_NAME.to_string(), 0_f64),
        (POSEIDON_BUILTIN_NAME.to_string(), 0_f64),
        (OUTPUT_BUILTIN_NAME.to_string(), 0_f64),
        (EC_OP_BUILTIN_NAME.to_string(), 0_f64),
    ]));

    block_context
}

#[fixture]
pub fn cache() -> CachedState<DictStateReader> {
    let mut cached_state = CachedState::from(DictStateReader::default());

    cached_state
        .set_contract_class(&class_hash!(DUMMY_TOKEN_HASH_0_12_2), load_class_v0("build/contracts/dummy_token.json"))
        .unwrap();
    cached_state
        .set_contract_class(
            &class_hash!(DUMMY_ACCOUNT_HASH_0_12_2),
            load_class_v0("build/contracts/dummy_account.json"),
        )
        .unwrap();
    cached_state
        .set_contract_class(
            &class_hash!(TOKEN_FOR_TESTING_HASH_0_12_2),
            load_class_v0("build/contracts/token_for_testing.json"),
        )
        .unwrap();

    cached_state
}

#[fixture(token_class_hash=DUMMY_TOKEN_HASH_0_12_2)]
pub fn initial_state(
    token_class_hash: &str,
    mut cache: CachedState<DictStateReader>,
    mut block_context: BlockContext,
) -> SharedState<DictStateReader> {
    let mut nonce_manager = NonceManager::default();

    let deploy_token_tx = deploy_account_tx(token_class_hash, Fee(TESTING_FEE), None, None, &mut nonce_manager);
    AccountTransaction::DeployAccount(deploy_token_tx.clone())
        .execute(&mut cache, &block_context, false, true)
        .unwrap();

    let tranfer_selector = selector_from_name("transfer");
    let fund_account = invoke_tx(invoke_tx_args! {
        max_fee: Fee(TESTING_FEE),
        nonce: nonce_manager.next(deploy_token_tx.contract_address),
        sender_address: deploy_token_tx.contract_address,
        calldata: calldata![
            *deploy_token_tx.contract_address.0.key(),
            tranfer_selector.0,
            stark_felt!(3_u8),
            *DUMMY_ACCOUNT_ADDRESS_0_12_2.0.key(),
            stark_felt!(TESTING_TRANSFER_AMOUNT),
            stark_felt!(0_u8)
        ],
        version: TransactionVersion::ONE,
    });
    AccountTransaction::Invoke(fund_account).execute(&mut cache, &block_context, false, true).unwrap();

    let deploy_account_tx =
        deploy_account_tx(DUMMY_ACCOUNT_HASH_0_12_2, Fee(TESTING_FEE), None, None, &mut nonce_manager);
    AccountTransaction::DeployAccount(deploy_account_tx).execute(&mut cache, &block_context, false, true).unwrap();

    block_context.block_number = BlockNumber(0);
    block_context.block_timestamp = BlockTimestamp(1001);

    let mut shared_state = SharedState::new(cache, block_context);
    let commitment = shared_state.apply_state();

    // expected root parsed from current os_test.py & test_utils.py(0.12.2)
    assert_eq!(felt_str!(EXPECTED_PREV_ROOT, 16), commitment.updated_root);

    shared_state
}

#[fixture]
pub fn prepare_os_test(
    mut initial_state: SharedState<DictStateReader>,
) -> (SharedState<DictStateReader>, Vec<TransactionExecutionInfo>) {
    let contract_addresses = [*TESTING_1_ADDREESS_0_12_2, *TESTING_2_ADDREESS_0_12_2, *TESTING_3_ADDREESS_0_12_2];
    let contract_calldata = [
        vec![stark_felt!(321_u32), stark_felt!(543_u32)],
        vec![stark_felt!(111_u32), stark_felt!(987_u32)],
        vec![stark_felt!(444_u32), stark_felt!(0_u32)],
    ];
    let contract_salts = [stark_felt!(17_u32), stark_felt!(42_u32), stark_felt!(53_u32)];

    let mut nonce_manager = NonceManager::default();
    let sender_addr = *DUMMY_ACCOUNT_ADDRESS_0_12_2;
    nonce_manager.next(sender_addr);

    initial_state
        .cache
        .set_contract_class(&class_hash!(TESTING_HASH_0_12_2), load_class_v0("build/contracts/test_contract.json"))
        .unwrap();
    for (i, expected_addr) in contract_addresses.into_iter().enumerate() {
        let contract_addr = calculate_contract_address(
            ContractAddressSalt(contract_salts[i]),
            class_hash!(TESTING_HASH_0_12_2),
            &Calldata(Arc::new(contract_calldata[i].clone())),
            contract_address!(0_u32),
        )
        .unwrap();
        initial_state.cache.set_class_hash_at(contract_addr, class_hash!(TESTING_HASH_0_12_2)).unwrap();
        initial_state.cache.set_storage_at(
            contract_addr,
            StorageKey(patricia_key!(*contract_calldata[i].first().unwrap())),
            *contract_calldata[i].last().unwrap(),
        );

        assert_eq!(expected_addr, contract_addr);
    }

    let mut txs: Vec<Calldata> = vec![
        calldata![
            *contract_addresses[0].0.key(),
            selector_from_name("set_value").0,
            stark_felt!(2_u8),
            stark_felt!(85_u8),
            stark_felt!(47_u8)
        ],
        calldata![
            *contract_addresses[0].0.key(),
            selector_from_name("set_value").0,
            stark_felt!(2_u8),
            stark_felt!(81_u8),
            stark_felt!(0_u8)
        ],
        calldata![
            *contract_addresses[2].0.key(),
            selector_from_name("set_value").0,
            stark_felt!(2_u8),
            stark_felt!(97_u8),
            stark_felt!(0_u8)
        ],
        calldata![*contract_addresses[1].0.key(), selector_from_name("entry_point").0, stark_felt!(0_u8)],
        calldata![*contract_addresses[0].0.key(), selector_from_name("test_builtins").0, stark_felt!(0_u8)],
        calldata![
            *contract_addresses[1].0.key(),
            selector_from_name("test_get_block_timestamp").0,
            stark_felt!(1_u8),
            stark_felt!(1000_u32)
        ],
        calldata![
            *contract_addresses[1].0.key(),
            selector_from_name("test_emit_event").0,
            stark_felt!(4_u8),
            stark_felt!(1_u8),
            stark_felt!(1991_u32),
            stark_felt!(1_u8),
            stark_felt!(2021_u32)
        ],
        calldata![
            *contract_addresses[0].0.key(),
            selector_from_name("test_get_block_number").0,
            stark_felt!(1_u32),
            stark_felt!(initial_state.block_context.block_number.0 + 1_u64)
        ],
        calldata![
            *contract_addresses[0].0.key(),
            selector_from_name("test_call_contract").0,
            stark_felt!(4_u32),
            *contract_addresses[0].0.key(),
            stark_felt!(selector_from_name("send_message").0),
            stark_felt!(1_u8),
            stark_felt!(85_u8)
        ],
        calldata![
            *contract_addresses[0].0.key(),
            selector_from_name("test_call_contract").0,
            stark_felt!(4_u32),
            *contract_addresses[1].0.key(),
            stark_felt!(selector_from_name("test_get_caller_address").0),
            stark_felt!(1_u8),
            *contract_addresses[0].0.key()
        ],
        calldata![
            *contract_addresses[0].0.key(),
            selector_from_name("test_get_contract_address").0,
            stark_felt!(1_u32),
            *contract_addresses[0].0.key()
        ],
    ];

    let delegate_addr =
        raw_deploy(&mut initial_state, "build/contracts/delegate_proxy.json", class_hash!(DELEGATE_PROXY_HASH_0_12_2));

    assert_eq!(*TESTING_DELEGATE_ADDREESS_0_12_2, delegate_addr);

    txs.push(calldata![
        *delegate_addr.0.key(),
        selector_from_name("set_implementation_hash").0,
        stark_felt!(1_u32),
        stark_felt!(TESTING_HASH_0_12_2)
    ]);

    txs.push(calldata![
        *delegate_addr.0.key(),
        selector_from_name("test_get_contract_address").0,
        stark_felt!(1_u32),
        *delegate_addr.0.key()
    ]);

    txs.push(calldata![
        *delegate_addr.0.key(),
        selector_from_name("set_value").0,
        stark_felt!(2_u32),
        stark_felt!(123_u32),
        stark_felt!(456_u32)
    ]);

    txs.push(calldata![
        *delegate_addr.0.key(),
        selector_from_name("test_get_caller_address").0,
        stark_felt!(1_u32),
        *DUMMY_ACCOUNT_ADDRESS_0_12_2.0.key()
    ]);

    txs.push(calldata![
        *delegate_addr.0.key(),
        selector_from_name("test_call_contract").0,
        stark_felt!(4_u32),
        *delegate_addr.0.key(),
        selector_from_name("test_get_sequencer_address").0,
        stark_felt!(1_u8),
        *initial_state.block_context.sequencer_address.0.key()
    ]);

    txs.push(calldata![
        *contract_addresses[0].0.key(),
        selector_from_name("test_library_call_syntactic_sugar").0,
        stark_felt!(1_u32),
        stark_felt!(TESTING_HASH_0_12_2)
    ]);

    let mut sig_txs: Vec<(Calldata, TransactionSignature)> = Vec::new();

    sig_txs.push((
        calldata![
            *contract_addresses[0].0.key(),
            selector_from_name("add_signature_to_counters").0,
            stark_felt!(1_u32),
            stark_felt!(2021_u32)
        ],
        TransactionSignature(vec![stark_felt!(100_u32), stark_felt!(200_u32)]),
    ));

    sig_txs.push((
        calldata![
            *contract_addresses[0].0.key(),
            selector_from_name("test_call_contract").0,
            stark_felt!(4_u32),
            *delegate_addr.0.key(),
            selector_from_name("test_get_tx_info").0,
            stark_felt!(1_u8),
            *DUMMY_ACCOUNT_ADDRESS_0_12_2.0.key()
        ],
        TransactionSignature(vec![stark_felt!(100_u32)]),
    ));

    let test_contract_2_addr =
        raw_deploy(&mut initial_state, "build/contracts/test_contract2.json", class_hash!(TESTING_HASH_2_0_12_2));

    sig_txs.push((
        calldata![
            *contract_addresses[1].0.key(),
            selector_from_name("test_library_call").0,
            stark_felt!(5_u32),
            class_hash!(TESTING_HASH_2_0_12_2).0,
            selector_from_name("test_storage_write").0,
            stark_felt!(2_u8),
            stark_felt!(555_u32),
            stark_felt!(888_u32)
        ],
        TransactionSignature(vec![stark_felt!(100_u32)]),
    ));

    sig_txs.push((
        calldata![
            *contract_addresses[1].0.key(),
            selector_from_name("test_library_call_l1_handler").0,
            stark_felt!(6_u32),
            class_hash!(TESTING_HASH_2_0_12_2).0,
            selector_from_name("test_l1_handler_storage_write").0,
            stark_felt!(3_u8),
            stark_felt!(85_u32),
            stark_felt!(666_u32),
            stark_felt!(999_u32)
        ],
        TransactionSignature(vec![stark_felt!(100_u32)]),
    ));

    sig_txs.push((
        calldata![
            *contract_addresses[0].0.key(),
            selector_from_name("test_replace_class").0,
            stark_felt!(1_u32),
            *test_contract_2_addr.0.key()
        ],
        TransactionSignature(vec![]),
    ));
    // duplicate this tx w/o storage impact to set DUMMY ACCOUNT NONCE TO CORRECT VAL
    sig_txs.push((
        calldata![
            *contract_addresses[0].0.key(),
            selector_from_name("test_replace_class").0,
            stark_felt!(1_u32),
            *test_contract_2_addr.0.key()
        ],
        TransactionSignature(vec![]),
    ));

    let mut exec_info: Vec<TransactionExecutionInfo> = Vec::new();

    for tx in txs.clone().into_iter() {
        let account_tx = invoke_tx(invoke_tx_args! {
            max_fee: Fee(TESTING_FEE),
            nonce: nonce_manager.next(sender_addr),
            sender_address: sender_addr,
            calldata: tx,
            version: TransactionVersion::ONE,
        });
        let tx_info = AccountTransaction::Invoke(account_tx)
            .execute(&mut initial_state.cache, &initial_state.block_context, false, true)
            .unwrap();
        exec_info.push(tx_info);
    }

    for sig_tx in sig_txs.clone().into_iter() {
        let account_tx = invoke_tx(invoke_tx_args! {
            max_fee: Fee(TESTING_FEE),
            nonce: nonce_manager.next(sender_addr),
            sender_address: sender_addr,
            calldata: sig_tx.0,
            signature: sig_tx.1,
            version: TransactionVersion::ONE,
        });
        let tx_info = AccountTransaction::Invoke(account_tx)
            .execute(&mut initial_state.cache, &initial_state.block_context, false, true)
            .unwrap();
        exec_info.push(tx_info);
    }

    initial_state.cache.set_storage_at(
        delegate_addr,
        StorageKey(patricia_key!(300_u32)),
        stark_felt!("4e5e39d16e565bacdbc7d8d13b9bc2b51a32c8b2b49062531688dcd2f6ec834"),
    );
    initial_state.cache.set_storage_at(
        delegate_addr,
        StorageKey(patricia_key!(311_u32)),
        stark_felt!(1536727068981429685321_u128),
    );
    initial_state.cache.set_storage_at(
        delegate_addr,
        StorageKey(patricia_key!("1cda892019d02a987cdc80f1500179f0e33fbd6cac8cb2ffef5d6d05101a8dc")),
        stark_felt!(2_u8),
    );

    (initial_state, exec_info)
}

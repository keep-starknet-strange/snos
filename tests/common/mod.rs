pub mod serde_utils;
pub mod utils;

use std::collections::HashMap;
use std::fs;
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
use cairo_felt::felt_str;
use cairo_vm::cairo_run::{cairo_run, CairoRunConfig};
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
use cairo_vm::vm::runners::builtin_runner::{
    BITWISE_BUILTIN_NAME, EC_OP_BUILTIN_NAME, HASH_BUILTIN_NAME, OUTPUT_BUILTIN_NAME, POSEIDON_BUILTIN_NAME,
    RANGE_CHECK_BUILTIN_NAME, SIGNATURE_BUILTIN_NAME,
};
use cairo_vm::vm::runners::cairo_pie::CairoPie;
use cairo_vm::vm::runners::cairo_runner::CairoRunner;
use cairo_vm::vm::vm_core::VirtualMachine;
use rstest::{fixture, rstest};
use snos::config::{StarknetGeneralConfig, DEFAULT_FEE_TOKEN_ADDR, DEFAULT_INPUT_PATH};
use snos::io::{output::decode_output, StarknetOsInput, StarknetOsOutput};
use snos::state::SharedState;
use starknet_api::block::{BlockNumber, BlockTimestamp};
use starknet_api::core::{calculate_contract_address, ClassHash, ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{Calldata, ContractAddressSalt, Fee, TransactionSignature, TransactionVersion};
use starknet_api::{calldata, class_hash, contract_address, patricia_key, stark_felt};

pub const TESTING_FEE: u128 = 0x10000000000000000000000000;
pub const TESTING_TRANSFER_AMOUNT: u128 = 0x01000000000000000000000000000000;

// Contract Addresses - 0.12.2
pub const _TOKEN_FOR_TESTING_ADDRESS_0_12_2: &str = "572b6542feb4bf285b57a056b588d649e067b9cfab2a88c2b2df9ea6bae6049";
pub const DUMMY_ACCOUNT_ADDRESS_0_12_2: &str = "5ca2b81086d3fbb4f4af2f1deba4b7fd35e8f4b2caee4e056005c51c05c3dd0";
pub const _DUMMY_TOKEN_ADDRESS_0_12_2: &str = "3400a86fdc294a70fac1cf84f81a2127419359096b846be9814786d4fc056b8";

// Class Hashes - 0.12.2
// int - 1950604961159131904798252922088285101498625538306083185117403934352241550198
pub const TOKEN_FOR_TESTING_HASH_0_12_2: &str = "45000d731e6d5ad0023e448dd15cab6f997b04a39120daf56a8816d9f436376";

// int - 646245114977324210659279014519951538684823368221946044944492064370769527799
pub const DUMMY_ACCOUNT_HASH_0_12_2: &str = "16dc3038da22dde8ad61a786ab9930699cc496c8bccb90d77cc8abee89803f7";

// int - 3531298130119845387864440863187980726515137569165069484670944625223023734186
pub const DUMMY_TOKEN_HASH_0_12_2: &str = "7cea4d7710723fa9e33472b6ceb71587a0ce4997ef486638dd0156bdb6c2daa";

// int - 3262122051170176624039908867798875903980511552421730070376672653403179864416
pub const TESTING_HASH_0_12_2: &str = "7364bafc3d2c56bc84404a6d8be799f533e518b8808bce86395a9442e1e5160";

pub const TESTING_HASH_2_0_12_2: &str = "49bcc976d628b1b238aefc20e77303a251a14ba6c99cd543a86708513414057";

pub const DELEGATE_PROXY_HASH_0_12_2: &str = "1880d2c303f26b658392a2c92a0677f3939f5fdfb960ecf5912afa06ad0b9d9";

#[allow(dead_code)]
pub const TESTING_BLOCK_HASH: &str = "59b01ba262c999f2617412ffbba780f80b0103d928cbce1aecbaa50de90abda";
#[allow(dead_code)]
pub const EXPECTED_PREV_ROOT: &str = "473010ec333f16b84334f9924912d7a13ce8296b0809c2091563ddfb63011d";
#[allow(dead_code)]
pub const EXPECTED_UPDATED_ROOT: &str = "482c9ce8a99afddc9777ff048520fcbfab6c0389f51584016c80a2e94ab8ca7";

#[fixture]
#[once]
pub fn load_and_write_input() {
    let os_input = serde_utils::StarknetOsInputUtil::load("tests/common/os_input.json");
    os_input.dump(DEFAULT_INPUT_PATH).unwrap();
}

#[fixture]
#[once]
pub fn load_input(_load_and_write_input: ()) -> StarknetOsInput {
    StarknetOsInput::load(DEFAULT_INPUT_PATH)
}

#[fixture]
pub fn setup_runner() -> (CairoRunner, VirtualMachine) {
    let program_content = fs::read("build/programs/fact.json").unwrap();

    let mut hint_processor = BuiltinHintProcessor::new_empty();

    // Run the program
    cairo_run(
        &program_content,
        &CairoRunConfig {
            entrypoint: "main",
            trace_enabled: true,
            relocate_mem: true,
            layout: "small",
            proof_mode: false,
            secure_run: Some(true),
            disable_trace_padding: false,
        },
        &mut hint_processor,
    )
    .unwrap()
}

#[fixture]
pub fn setup_pie(setup_runner: (CairoRunner, VirtualMachine)) -> CairoPie {
    // Run the runner
    let (runner, vm) = setup_runner;

    runner.get_cairo_pie(&vm).unwrap()
}

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
        .set_contract_class(
            &class_hash!(DUMMY_TOKEN_HASH_0_12_2),
            utils::load_class_v0("build/contracts/dummy_token.json"),
        )
        .unwrap();
    cached_state
        .set_contract_class(
            &class_hash!(DUMMY_ACCOUNT_HASH_0_12_2),
            utils::load_class_v0("build/contracts/dummy_account.json"),
        )
        .unwrap();
    cached_state
        .set_contract_class(
            &class_hash!(TOKEN_FOR_TESTING_HASH_0_12_2),
            utils::load_class_v0("build/contracts/token_for_testing.json"),
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
            stark_felt!(DUMMY_ACCOUNT_ADDRESS_0_12_2),
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

#[rstest]
fn shared_state(initial_state: SharedState<DictStateReader>) {
    let block_num = initial_state.get_block_num();
    assert_eq!(BlockNumber(1), block_num);
}

#[fixture]
pub fn prepare_os_test(
    mut initial_state: SharedState<DictStateReader>,
) -> (SharedState<DictStateReader>, Vec<TransactionExecutionInfo>) {
    let contract_addresses = [
        contract_address!("46fd0893101585e0c7ebd3caf8097b179f774102d6373760c8f60b1a5ef8c92"),
        contract_address!("4e9665675ca1ac12820b7aff2f44fec713e272efcd3f20aa0fd8ca277f25dc6"),
        contract_address!("74cebec93a58b4400af9c082fb3c5adfa0800ff1489f8fc030076491ff86c48"),
    ];
    let contract_calldata = [
        vec![stark_felt!(321_u32), stark_felt!(543_u32)],
        vec![stark_felt!(111_u32), stark_felt!(987_u32)],
        vec![stark_felt!(444_u32), stark_felt!(0_u32)],
    ];
    let contract_salts = [stark_felt!(17_u32), stark_felt!(42_u32), stark_felt!(53_u32)];

    let mut nonce_manager = NonceManager::default();
    let sender_addr = contract_address!(DUMMY_ACCOUNT_ADDRESS_0_12_2);
    nonce_manager.next(sender_addr);

    initial_state
        .cache
        .set_contract_class(
            &class_hash!(TESTING_HASH_0_12_2),
            utils::load_class_v0("build/contracts/test_contract.json"),
        )
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

    let delegate_addr = utils::raw_deploy(
        &mut initial_state,
        "build/contracts/delegate_proxy.json",
        class_hash!(DELEGATE_PROXY_HASH_0_12_2),
    );

    assert_eq!(contract_address!("238e6b5dffc9f0eb2fe476855d0cd1e9e034e5625663c7eda2d871bd4b6eac0"), delegate_addr);

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
        stark_felt!(DUMMY_ACCOUNT_ADDRESS_0_12_2)
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
            stark_felt!(DUMMY_ACCOUNT_ADDRESS_0_12_2)
        ],
        TransactionSignature(vec![stark_felt!(100_u32)]),
    ));

    let test_contract_2_addr = utils::raw_deploy(
        &mut initial_state,
        "build/contracts/test_contract2.json",
        class_hash!(TESTING_HASH_2_0_12_2),
    );

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

#[fixture]
pub fn load_output() -> StarknetOsOutput {
    let buf = fs::read_to_string("tests/common/os_output.json").unwrap();
    let raw_output: serde_utils::RawOsOutput = serde_json::from_str(&buf).unwrap();

    decode_output(raw_output.0).unwrap()
}

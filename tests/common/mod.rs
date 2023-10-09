pub mod utils;

use blockifier::abi::constants::N_STEPS_RESOURCE;

use blockifier::abi::abi_utils::selector_from_name;
use blockifier::block_context::BlockContext;
use blockifier::block_execution::pre_process_block;
use blockifier::state::cached_state::{CachedState, ContractClassMapping};
use blockifier::state::state_api::State;
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::transactions::ExecutableTransaction;
use cairo_vm::cairo_run::{cairo_run, CairoRunConfig};
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
use cairo_vm::vm::runners::builtin_runner::{
    BITWISE_BUILTIN_NAME, EC_OP_BUILTIN_NAME, HASH_BUILTIN_NAME, OUTPUT_BUILTIN_NAME,
    POSEIDON_BUILTIN_NAME, RANGE_CHECK_BUILTIN_NAME, SIGNATURE_BUILTIN_NAME,
};
use cairo_vm::vm::runners::cairo_pie::CairoPie;
use cairo_vm::vm::runners::cairo_runner::CairoRunner;
use cairo_vm::vm::vm_core::VirtualMachine;
use snos::config::{StarknetGeneralConfig, DEFAULT_FEE_TOKEN_ADDR};
use starknet_api::block::{BlockHash, BlockNumber, BlockTimestamp};
use starknet_api::core::{calculate_contract_address, ClassHash, ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::DeprecatedDeclaredClasses;
use starknet_api::transaction::{Calldata, ContractAddressSalt, Fee, TransactionVersion};
use starknet_api::{calldata, class_hash, contract_address, patricia_key, stark_felt};

use std::collections::HashMap;
use std::fs;
use std::sync::Arc;

use rstest::*;

use blockifier::{invoke_tx_args, test_utils::*};

pub const TESTING_FEE: u128 = 0x10000000000000000000000000;
pub const TESTING_TRANSFER_AMOUNT: u128 = 0x01000000000000000000000000000000;

// Contract Addresses - 0.12.2
pub const _TOKEN_FOR_TESTING_ADDRESS_0_12_2: &str =
    "572b6542feb4bf285b57a056b588d649e067b9cfab2a88c2b2df9ea6bae6049";
pub const DUMMY_ACCOUNT_ADDRESS_0_12_2: &str =
    "5ca2b81086d3fbb4f4af2f1deba4b7fd35e8f4b2caee4e056005c51c05c3dd0";
pub const _DUMMY_TOKEN_ADDRESS_0_12_2: &str =
    "3400a86fdc294a70fac1cf84f81a2127419359096b846be9814786d4fc056b8";

// Class Hashes - 0.12.2
// int - 1950604961159131904798252922088285101498625538306083185117403934352241550198
pub const TOKEN_FOR_TESTING_HASH_0_12_2: &str =
    "45000d731e6d5ad0023e448dd15cab6f997b04a39120daf56a8816d9f436376";

// int - 646245114977324210659279014519951538684823368221946044944492064370769527799
pub const DUMMY_ACCOUNT_HASH_0_12_2: &str =
    "16dc3038da22dde8ad61a786ab9930699cc496c8bccb90d77cc8abee89803f7";

// int - 3531298130119845387864440863187980726515137569165069484670944625223023734186
pub const DUMMY_TOKEN_HASH_0_12_2: &str =
    "7cea4d7710723fa9e33472b6ceb71587a0ce4997ef486638dd0156bdb6c2daa";

// int - 3262122051170176624039908867798875903980511552421730070376672653403179864416
pub const TESTING_HASH_0_12_2: &str =
    "7364bafc3d2c56bc84404a6d8be799f533e518b8808bce86395a9442e1e5160";

pub const TESTING_HASH_2_0_12_2: &str =
    "49bcc976d628b1b238aefc20e77303a251a14ba6c99cd543a86708513414057";

pub const DELEGATE_PROXY_HASH_0_12_2: &str =
    "1880d2c303f26b658392a2c92a0677f3939f5fdfb960ecf5912afa06ad0b9d9";

pub struct TestingContext {
    pub block_context: BlockContext,
    pub state: CachedState<DictStateReader>,
}

#[fixture]
pub fn setup_runner() -> (CairoRunner, VirtualMachine) {
    let program_content = fs::read("build/fact.json").unwrap();

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
    block_context.block_timestamp = BlockTimestamp(1000);

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
pub fn state() -> CachedState<DictStateReader> {
    let class_hash_to_class: ContractClassMapping = HashMap::from([
        (
            class_hash!(DUMMY_TOKEN_HASH_0_12_2),
            utils::load_class_v0("build/dummy_token.json"),
        ),
        (
            class_hash!(DUMMY_ACCOUNT_HASH_0_12_2),
            utils::load_class_v0("build/dummy_account.json"),
        ),
        (
            class_hash!(TOKEN_FOR_TESTING_HASH_0_12_2),
            utils::load_class_v0("build/token_for_testing.json"),
        ),
    ]);

    CachedState::from(DictStateReader {
        class_hash_to_class,
        ..Default::default()
    })
}

#[fixture]
pub fn raw_state() -> DeprecatedDeclaredClasses {
    DeprecatedDeclaredClasses::from([
        (
            class_hash!(DUMMY_TOKEN_HASH_0_12_2),
            utils::load_deprecated_class("build/dummy_token.json"),
        ),
        (
            class_hash!(DUMMY_ACCOUNT_HASH_0_12_2),
            utils::load_deprecated_class("build/dummy_account.json"),
        ),
        (
            class_hash!(TOKEN_FOR_TESTING_HASH_0_12_2),
            utils::load_deprecated_class("build/token_for_testing.json"),
        ),
    ])
}

#[fixture(token_class_hash=DUMMY_TOKEN_HASH_0_12_2)]
pub fn initial_state(
    token_class_hash: &str,
    mut block_context: BlockContext,
    mut state: CachedState<DictStateReader>,
) -> TestingContext {
    let mut nonce_manager = NonceManager::default();

    let deploy_token_tx = deploy_account_tx(
        token_class_hash,
        Fee(TESTING_FEE),
        None,
        None,
        &mut nonce_manager,
    );
    AccountTransaction::DeployAccount(deploy_token_tx.clone())
        .execute(&mut state, &block_context, false, true)
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
    AccountTransaction::Invoke(fund_account.into())
        .execute(&mut state, &block_context, false, true)
        .unwrap();

    let deploy_account_tx = deploy_account_tx(
        DUMMY_ACCOUNT_HASH_0_12_2,
        Fee(TESTING_FEE),
        None,
        None,
        &mut nonce_manager,
    );
    AccountTransaction::DeployAccount(deploy_account_tx)
        .execute(&mut state, &block_context, false, true)
        .unwrap();

    pre_process_block(
        &mut state,
        Some((BlockNumber(0), BlockHash(StarkFelt::from(20u32)))),
    );
    block_context.block_number = BlockNumber(1);
    block_context.block_timestamp = BlockTimestamp(1001);

    TestingContext {
        block_context,
        state,
    }
}

#[fixture]
pub fn prepare_os_test(mut initial_state: TestingContext) -> (TestingContext, Vec<Calldata>) {
    let mut nonce_manager = NonceManager::default();
    let sender_addr = contract_address!(DUMMY_ACCOUNT_ADDRESS_0_12_2);
    nonce_manager.next(sender_addr);

    let test_contract_class = utils::load_class_v0("build/test_contract.json");
    initial_state
        .state
        .set_contract_class(&class_hash!(TESTING_HASH_0_12_2), test_contract_class)
        .unwrap();

    let contract_addresses = [
        contract_address!("46fd0893101585e0c7ebd3caf8097b179f774102d6373760c8f60b1a5ef8c92"),
        contract_address!("4e9665675ca1ac12820b7aff2f44fec713e272efcd3f20aa0fd8ca277f25dc6"),
        contract_address!("74cebec93a58b4400af9c082fb3c5adfa0800ff1489f8fc030076491ff86c48"),
    ];
    let testing_1 = calculate_contract_address(
        ContractAddressSalt(stark_felt!(17_u32)),
        class_hash!(TESTING_HASH_0_12_2),
        &calldata![
            stark_felt!(321_u32), // Calldata: address.
            stark_felt!(543_u32)  // Calldata: value.
        ],
        contract_address!(0_u32),
    )
    .unwrap();
    assert_eq!(contract_addresses[0], testing_1);

    let account_tx = invoke_tx(invoke_tx_args! {
        max_fee: Fee(TESTING_FEE),
        nonce: nonce_manager.next(sender_addr),
        sender_address: sender_addr,
        calldata: calldata![
            *sender_addr.0.key(),
            selector_from_name("deploy_contract").0,
            stark_felt!(5_u32),
            stark_felt!(TESTING_HASH_0_12_2),
            stark_felt!(17_u32),
            stark_felt!(2_u32),
            stark_felt!(321_u32),
            stark_felt!(543_u32)
        ],
        version: TransactionVersion::ONE,
    });
    AccountTransaction::Invoke(account_tx.into())
        .execute(
            &mut initial_state.state,
            &mut initial_state.block_context,
            false,
            true,
        )
        .unwrap();

    let testing_2 = calculate_contract_address(
        ContractAddressSalt(stark_felt!(42_u32)),
        class_hash!(TESTING_HASH_0_12_2),
        &calldata![
            stark_felt!(111_u32), // Calldata: address.
            stark_felt!(987_u32)  // Calldata: value.
        ],
        contract_address!(0_u32),
    )
    .unwrap();
    assert_eq!(contract_addresses[1], testing_2);
    let account_tx = invoke_tx(invoke_tx_args! {
        max_fee: Fee(TESTING_FEE),
        nonce: nonce_manager.next(sender_addr),
        sender_address: sender_addr,
        calldata: calldata![
            *sender_addr.0.key(),
            selector_from_name("deploy_contract").0,
            stark_felt!(5_u32),
            stark_felt!(TESTING_HASH_0_12_2),
            stark_felt!(17_u32),
            stark_felt!(2_u32),
            stark_felt!(321_u32),
            stark_felt!(543_u32)
        ],
        version: TransactionVersion::ONE,
    });
    AccountTransaction::Invoke(account_tx.into())
        .execute(
            &mut initial_state.state,
            &mut initial_state.block_context,
            false,
            true,
        )
        .unwrap();

    let testing_3 = calculate_contract_address(
        ContractAddressSalt(stark_felt!(53_u32)),
        class_hash!(TESTING_HASH_0_12_2),
        &calldata![
            stark_felt!(444_u32), // Calldata: address.
            stark_felt!(0_u32)    // Calldata: value.
        ],
        contract_address!(0_u32),
    )
    .unwrap();
    assert_eq!(contract_addresses[2], testing_3);

    let mut txs: Vec<Calldata> = Vec::new();

    txs.push(calldata![
        *contract_addresses[0].0.key(),
        selector_from_name("set_value").0,
        stark_felt!(2_u8),
        stark_felt!(85_u8),
        stark_felt!(47_u8)
    ]);

    txs.push(calldata![
        *contract_addresses[0].0.key(),
        selector_from_name("set_value").0,
        stark_felt!(2_u8),
        stark_felt!(81_u8),
        stark_felt!(0_u8)
    ]);

    txs.push(calldata![
        *contract_addresses[2].0.key(),
        selector_from_name("set_value").0,
        stark_felt!(2_u8),
        stark_felt!(97_u8),
        stark_felt!(0_u8)
    ]);

    txs.push(calldata![
        *contract_addresses[1].0.key(),
        selector_from_name("entry_point").0,
        stark_felt!(0_u8)
    ]);

    txs.push(calldata![
        *contract_addresses[0].0.key(),
        selector_from_name("test_builtins").0,
        stark_felt!(0_u8)
    ]);

    txs.push(calldata![
        *contract_addresses[1].0.key(),
        selector_from_name("test_get_block_timestamp").0,
        stark_felt!(1_u8),
        stark_felt!(1000_u32)
    ]);

    txs.push(calldata![
        *contract_addresses[1].0.key(),
        selector_from_name("test_emit_event").0,
        stark_felt!(4_u8),
        stark_felt!(1_u8),
        stark_felt!(1991_u32),
        stark_felt!(1_u8),
        stark_felt!(2021_u32)
    ]);

    txs.push(calldata![
        *contract_addresses[0].0.key(),
        selector_from_name("test_get_block_number").0,
        stark_felt!(1_u32),
        stark_felt!(initial_state.block_context.block_number.0 + 1_u64)
    ]);

    txs.push(calldata![
        *contract_addresses[0].0.key(),
        selector_from_name("test_call_contract").0,
        stark_felt!(4_u32),
        *contract_addresses[0].0.key(),
        stark_felt!(selector_from_name("send_message").0),
        stark_felt!(1_u8),
        stark_felt!(85_u8)
    ]);

    // TODO: StarknetMessageToL1

    txs.push(calldata![
        *contract_addresses[0].0.key(),
        selector_from_name("test_call_contract").0,
        stark_felt!(4_u32),
        *contract_addresses[1].0.key(),
        stark_felt!(selector_from_name("test_get_caller_address").0),
        stark_felt!(1_u8),
        *contract_addresses[0].0.key()
    ]);

    txs.push(calldata![
        *contract_addresses[0].0.key(),
        selector_from_name("test_get_contract_address").0,
        stark_felt!(1_u32),
        *contract_addresses[0].0.key()
    ]);

    let delegate_proxy_contract_class = utils::load_class_v0("build/delegate_proxy.json");
    let delegate_addr = calculate_contract_address(
        ContractAddressSalt::default(),
        class_hash!(DELEGATE_PROXY_HASH_0_12_2),
        &calldata![],
        contract_address!(0_u32),
    )
    .unwrap();
    assert_eq!(
        contract_address!("0x0238e6b5dffc9f0eb2fe476855d0cd1e9e034e5625663c7eda2d871bd4b6eac0"),
        delegate_addr
    );
    initial_state
        .state
        .set_contract_class(
            &class_hash!(DELEGATE_PROXY_HASH_0_12_2),
            delegate_proxy_contract_class,
        )
        .unwrap();
    initial_state
        .state
        .set_class_hash_at(delegate_addr, class_hash!(DELEGATE_PROXY_HASH_0_12_2))
        .unwrap();

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
        *delegate_addr.0.key(),
        selector_from_name("deposit").0,
        stark_felt!(2_u32),
        stark_felt!(85_u32),
        stark_felt!(2_u32)
    ]);

    // // TODO handle message to L2

    txs.push(calldata![
        *contract_addresses[0].0.key(),
        selector_from_name("test_library_call_syntactic_sugar").0,
        stark_felt!(1_u32),
        stark_felt!(TESTING_HASH_0_12_2)
    ]);

    // TODO: add sig
    txs.push(calldata![
        *contract_addresses[0].0.key(),
        selector_from_name("add_signature_to_counters").0,
        stark_felt!(1_u32),
        stark_felt!(2021_u32)
    ]);

    // TODO: add sig
    txs.push(calldata![
        *contract_addresses[0].0.key(),
        selector_from_name("test_call_contract").0,
        stark_felt!(4_u32),
        *delegate_addr.0.key(),
        selector_from_name("test_get_tx_info").0,
        stark_felt!(1_u8),
        stark_felt!(DUMMY_ACCOUNT_ADDRESS_0_12_2)
    ]);

    let test_contract_2_contract_class = utils::load_class_v0("build/test_contract2.json");
    let test_contract_2_addr = calculate_contract_address(
        ContractAddressSalt::default(),
        class_hash!(TESTING_HASH_2_0_12_2),
        &calldata![],
        contract_address!(0_u32),
    )
    .unwrap();
    initial_state
        .state
        .set_contract_class(
            &class_hash!(TESTING_HASH_2_0_12_2),
            test_contract_2_contract_class,
        )
        .unwrap();
    initial_state
        .state
        .set_class_hash_at(test_contract_2_addr, class_hash!(TESTING_HASH_2_0_12_2))
        .unwrap();

    // TODO: add sig
    txs.push(calldata![
        *contract_addresses[1].0.key(),
        selector_from_name("test_library_call").0,
        stark_felt!(5_u32),
        *test_contract_2_addr.0.key(),
        selector_from_name("test_storage_write").0,
        stark_felt!(2_u8),
        stark_felt!(555_u32),
        stark_felt!(888_u32)
    ]);

    // TODO: add sig
    txs.push(calldata![
        *contract_addresses[1].0.key(),
        selector_from_name("test_library_call_l1_handler").0,
        stark_felt!(6_u32),
        *test_contract_2_addr.0.key(),
        selector_from_name("test_l1_handler_storage_write").0,
        stark_felt!(3_u8),
        stark_felt!(85_u32),
        stark_felt!(666_u32),
        stark_felt!(999_u32)
    ]);

    // TODO: add sig
    txs.push(calldata![
        *contract_addresses[0].0.key(),
        selector_from_name("test_replace_class").0,
        stark_felt!(1_u32),
        *test_contract_2_addr.0.key()
    ]);

    for tx in txs.clone().into_iter() {
        let account_tx = invoke_tx(invoke_tx_args! {
            max_fee: Fee(TESTING_FEE),
            nonce: nonce_manager.next(sender_addr),
            sender_address: sender_addr,
            calldata: tx,
            version: TransactionVersion::ONE,
        });
        AccountTransaction::Invoke(account_tx.into())
            .execute(
                &mut initial_state.state,
                &mut initial_state.block_context,
                false,
                true,
            )
            .unwrap();
    }

    pre_process_block(
        &mut initial_state.state,
        Some((BlockNumber(1), BlockHash(StarkFelt::from(21u32)))),
    );
    // TODO: expected storage updates
    (initial_state, txs)
}

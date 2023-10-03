pub mod utils;

use blockifier::abi::constants::N_STEPS_RESOURCE;

use blockifier::abi::abi_utils::selector_from_name;
use blockifier::block_context::BlockContext;
use blockifier::block_execution::pre_process_block;
use blockifier::state::cached_state::{CachedState, ContractClassMapping};
use blockifier::state::state_api::{State, StateReader};
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
use snos::utils::definitions::general_config::{StarknetGeneralConfig, DEFAULT_FEE_TOKEN_ADDR};
use starknet_api::block::{BlockHash, BlockNumber, BlockTimestamp};
use starknet_api::core::{ClassHash, ContractAddress, Nonce, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::transaction::{Calldata, Fee, TransactionVersion};
use starknet_api::{calldata, class_hash, contract_address, patricia_key, stark_felt};

use std::collections::HashMap;
use std::fs;
use std::sync::Arc;

use rstest::*;

use blockifier::{invoke_tx_args, test_utils::*};

pub const TESTING_FEE: u128 = 0x10000000000000000000000000;
pub const TESTING_TRANSFER_AMOUNT: u128 = 0x01000000000000000000000000000000;

// Contract Addresses - 0.12.2
pub const DUMMY_ACCOUNT_ADDRESS_0_12_2: &str =
    "0x05ca2b81086d3fbb4f4af2f1deba4b7fd35e8f4b2caee4e056005c51c05c3dd0";

// Class Hashes - 0.12.2
// int - 1950604961159131904798252922088285101498625538306083185117403934352241550198
pub const TOKEN_FOR_TESTING_HASH_0_12_2: &str =
    "0x045000d731e6d5ad0023e448dd15cab6f997b04a39120daf56a8816d9f436376";

// int - 646245114977324210659279014519951538684823368221946044944492064370769527799
pub const DUMMY_ACCOUNT_HASH_0_12_2: &str =
    "0x016dc3038da22dde8ad61a786ab9930699cc496c8bccb90d77cc8abee89803f7";

// int - 3531298130119845387864440863187980726515137569165069484670944625223023734186
pub const DUMMY_TOKEN_HASH_0_12_2: &str =
    "0x07cea4d7710723fa9e33472b6ceb71587a0ce4997ef486638dd0156bdb6c2daa";

// int - 3262122051170176624039908867798875903980511552421730070376672653403179864416
pub const TESTING_HASH_0_12_2: &str =
    "0x07364bafc3d2c56bc84404a6d8be799f533e518b8808bce86395a9442e1e5160";

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
pub fn empty_block_context() -> BlockContext {
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
pub fn testing_state() -> CachedState<DictStateReader> {
    let class_hash_to_class: ContractClassMapping = HashMap::from([
        (
            class_hash!(DUMMY_TOKEN_HASH_0_12_2),
            utils::load_contract_class_v0("build/dummy_token.json"),
        ),
        (
            class_hash!(DUMMY_ACCOUNT_HASH_0_12_2),
            utils::load_contract_class_v0("build/dummy_account.json"),
        ),
        (
            class_hash!(TOKEN_FOR_TESTING_HASH_0_12_2),
            utils::load_contract_class_v0("build/token_for_testing.json"),
        ),
    ]);

    CachedState::from(DictStateReader {
        class_hash_to_class,
        ..Default::default()
    })
}

// StateDiff(
#[rstest]
pub fn setup_snos_data(
    empty_block_context: BlockContext,
    mut testing_state: CachedState<DictStateReader>,
) {
    let mut nonce_manager = NonceManager::default();

    //CarriedState vs SharedState, empty either way

    let deploy_token_tx = deploy_account_tx(
        DUMMY_TOKEN_HASH_0_12_2,
        Fee(TESTING_FEE),
        None,
        None,
        &mut nonce_manager,
    );
    let deploy_token_info = AccountTransaction::DeployAccount(deploy_token_tx.clone()).execute(
        &mut testing_state,
        &empty_block_context,
        false,
        true,
    );
    // println!("DEPLOY INFO: {:?}", deploy_token_info);
    println!("DIFF: {:?}", testing_state.to_state_diff());

    let tranfer_selector = selector_from_name("transfer");
    let execute_calldata = calldata![
        *deploy_token_tx.contract_address.0.key(),
        tranfer_selector.0,
        stark_felt!(3_u8),
        stark_felt!(DUMMY_ACCOUNT_ADDRESS_0_12_2),
        stark_felt!(TESTING_TRANSFER_AMOUNT),
        stark_felt!(0_u8)
    ];

    let (low, high) = testing_state
        .get_fee_token_balance(
            &contract_address!(DUMMY_ACCOUNT_ADDRESS_0_12_2),
            &deploy_token_tx.contract_address,
        )
        .unwrap();
    println!("BEFOREE: {:?} {:?}", low, high);

    let fund_account = invoke_tx(invoke_tx_args! {
        max_fee: Fee(TESTING_FEE),
        nonce: Nonce(stark_felt!(1_u8)),
        sender_address: deploy_token_tx.contract_address,
        calldata: execute_calldata,
        version: TransactionVersion::ONE,
    });
    let fund_account_info = AccountTransaction::Invoke(fund_account.into()).execute(
        &mut testing_state,
        &empty_block_context,
        false,
        true,
    );

    let (low, high) = testing_state
        .get_fee_token_balance(
            &contract_address!(DUMMY_ACCOUNT_ADDRESS_0_12_2),
            &deploy_token_tx.contract_address,
        )
        .unwrap();
    println!("AFTER: {:?} {:?}", low, high);
    // println!("TOKEN FUNDING: {:?}", fund_account_info);

    let deploy_account_tx = deploy_account_tx(
        DUMMY_ACCOUNT_HASH_0_12_2,
        Fee(TESTING_FEE),
        None,
        None,
        &mut nonce_manager,
    );
    let deploy_account_info = AccountTransaction::DeployAccount(deploy_account_tx.clone()).execute(
        &mut testing_state,
        &empty_block_context,
        false,
        true,
    );
    // println!("DEPLOY TOKEN: {:?}", deploy_account_info);
    let block_number: u64 = 0;
    let block_hash = StarkFelt::from(20u32);
    let hash = pre_process_block(
        &mut testing_state,
        Some((BlockNumber(block_number), BlockHash(block_hash))),
    );

    println!(
        "DIFF({:?}): {:?}",
        block_hash,
        testing_state.to_state_diff()
    );
}

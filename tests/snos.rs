mod common;

use blockifier::test_utils::DictStateReader;
use blockifier::transaction::objects::TransactionExecutionInfo;
use cairo_felt::felt_str;
use common::{
    initial_state, load_input, prepare_os_test, EXPECTED_PREV_ROOT, EXPECTED_UPDATED_ROOT, TESTING_BLOCK_HASH,
};
use rstest::*;
use snos::io::StarknetOsInput;
use snos::state::SharedState;
use snos::SnOsRunner;
use starknet_api::block::BlockNumber;
use starknet_api::core::{ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::{contract_address, patricia_key, stark_felt};

#[rstest]
fn snos_run_test(_load_input: &StarknetOsInput, initial_state: SharedState<DictStateReader>) {
    let snos_runner = SnOsRunner::with_os_path("build/os_debug.json");
    let runner_res = snos_runner.run(initial_state);
    println!("{:#?}", runner_res);
}

#[rstest]
fn prepared_os_test(prepare_os_test: (SharedState<DictStateReader>, Vec<TransactionExecutionInfo>)) {
    let (mut prepare_os_test, _) = prepare_os_test;
    let _commitment = prepare_os_test.apply_state();
    assert_eq!(BlockNumber(2), prepare_os_test.get_block_num());

    let addr_1_root = prepare_os_test
        .get_contract_root(contract_address!("46fd0893101585e0c7ebd3caf8097b179f774102d6373760c8f60b1a5ef8c92"))
        .unwrap();
    assert_eq!(stark_felt!("7d4b1bcb63f8b7f53ef32d5761afc3249180f03dc9773e421a9574c51453c00"), addr_1_root.0);
    let addr_2_root = prepare_os_test
        .get_contract_root(contract_address!("4e9665675ca1ac12820b7aff2f44fec713e272efcd3f20aa0fd8ca277f25dc6"))
        .unwrap();
    assert_eq!(stark_felt!("1fc35de150561b6229137b3f253fc1c894c93b1c184a8ca0d0f7171a64bcd04"), addr_2_root.0);
    let delegate_root = prepare_os_test
        .get_contract_root(contract_address!("238e6b5dffc9f0eb2fe476855d0cd1e9e034e5625663c7eda2d871bd4b6eac0"))
        .unwrap();
    assert_eq!(stark_felt!("4ed2a0d5f47780aee355c14a37ab2ae7dc8fb6f73773563e02fef51b4ec4abe"), delegate_root.0);
}

#[rstest]
fn parse_os_input(load_input: &StarknetOsInput) {
    assert_eq!(felt_str!(TESTING_BLOCK_HASH, 16), load_input.block_hash);
    assert_eq!(felt_str!(EXPECTED_PREV_ROOT, 16), load_input.contract_state_commitment_info.previous_root);
    assert_eq!(felt_str!(EXPECTED_UPDATED_ROOT, 16), load_input.contract_state_commitment_info.updated_root);
    assert!(!load_input.transactions.is_empty());
}

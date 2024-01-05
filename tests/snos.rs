mod common;

use blockifier::state::state_api::State;
use blockifier::test_utils::DictStateReader;
use blockifier::transaction::objects::TransactionExecutionInfo;
use cairo_vm::Felt252;
use common::defs::{
    EXPECTED_PREV_ROOT, EXPECTED_UPDATED_ROOT, TESTING_1_ADDREESS_0_12_2, TESTING_2_ADDREESS_0_12_2,
    TESTING_BLOCK_HASH, TESTING_DELEGATE_ADDREESS_0_12_2, TESTING_HASH_0_12_2,
};
use common::prepared_os_test::prepare_os_test;
use common::{load_input, load_output};
use rstest::rstest;
use snos::io::input::StarknetOsInput;
use snos::io::output::StarknetOsOutput;
use snos::state::SharedState;
use snos::utils::felt_api2vm;
use snos::SnOsRunner;
use starknet_api::block::BlockNumber;
use starknet_api::core::PatriciaKey;
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::{patricia_key, stark_felt};

#[rstest]
fn snos_run_test(
    _load_input: &StarknetOsInput,
    prepare_os_test: (SharedState<DictStateReader>, Vec<TransactionExecutionInfo>),
) {
    let snos_runner = SnOsRunner::with_os_path("build/os_latest.json");
    let runner_res = snos_runner.run(prepare_os_test.0, prepare_os_test.1);

    println!("{:#?}", runner_res);
}

#[rstest]
fn validate_prepared_os_test(prepare_os_test: (SharedState<DictStateReader>, Vec<TransactionExecutionInfo>)) {
    let (mut prepare_os_test, _) = prepare_os_test;
    let diff = prepare_os_test.cache.to_state_diff();

    let addr_1_updates = diff.storage_updates.get(&(*TESTING_1_ADDREESS_0_12_2)).unwrap();
    assert_eq!(5, addr_1_updates.len());
    assert_eq!(&stark_felt!(47_u32), addr_1_updates.get(&StorageKey(patricia_key!(85_u32))).unwrap());
    assert_eq!(&stark_felt!(543_u32), addr_1_updates.get(&StorageKey(patricia_key!(321_u32))).unwrap());
    assert_eq!(&stark_felt!(666_u32), addr_1_updates.get(&StorageKey(patricia_key!(444_u32))).unwrap());

    let addr_2_updates = diff.storage_updates.get(&(*TESTING_2_ADDREESS_0_12_2)).unwrap();
    assert_eq!(&stark_felt!(1_u32), addr_2_updates.get(&StorageKey(patricia_key!(15_u32))).unwrap());
    assert_eq!(&stark_felt!(987_u32), addr_2_updates.get(&StorageKey(patricia_key!(111_u32))).unwrap());
    assert_eq!(&stark_felt!(888_u32), addr_2_updates.get(&StorageKey(patricia_key!(555_u32))).unwrap());
    assert_eq!(&stark_felt!(999_u32), addr_2_updates.get(&StorageKey(patricia_key!(666_u32))).unwrap());

    let delegate_addr_updates = diff.storage_updates.get(&(*TESTING_DELEGATE_ADDREESS_0_12_2)).unwrap();
    assert_eq!(&stark_felt!(456_u32), delegate_addr_updates.get(&StorageKey(patricia_key!(123_u32))).unwrap());
    assert_eq!(
        &stark_felt!("4e5e39d16e565bacdbc7d8d13b9bc2b51a32c8b2b49062531688dcd2f6ec834"),
        delegate_addr_updates.get(&StorageKey(patricia_key!(300_u32))).unwrap()
    );
    assert_eq!(
        &stark_felt!(1536727068981429685321_u128),
        delegate_addr_updates.get(&StorageKey(patricia_key!(311_u32))).unwrap()
    );
    assert_eq!(&stark_felt!(19_u32), delegate_addr_updates.get(&StorageKey(patricia_key!(322_u32))).unwrap());
    assert_eq!(
        &stark_felt!(TESTING_HASH_0_12_2),
        delegate_addr_updates
            .get(&StorageKey(patricia_key!("2e9111f912ea3746e28b8e693578fdbcc18d64a3380d03bd67c0c04f5715ed1")))
            .unwrap()
    );
    assert_eq!(
        &stark_felt!(2_u8),
        delegate_addr_updates
            .get(&StorageKey(patricia_key!("1cda892019d02a987cdc80f1500179f0e33fbd6cac8cb2ffef5d6d05101a8dc")))
            .unwrap()
    );

    let _commitment = prepare_os_test.apply_state();
    assert_eq!(BlockNumber(2), prepare_os_test.get_block_num());

    let addr_1_root = prepare_os_test.get_contract_root(*TESTING_1_ADDREESS_0_12_2).unwrap();
    assert_eq!(stark_felt!("7d4b1bcb63f8b7f53ef32d5761afc3249180f03dc9773e421a9574c51453c00"), addr_1_root.0);
    let addr_2_root = prepare_os_test.get_contract_root(*TESTING_2_ADDREESS_0_12_2).unwrap();
    assert_eq!(stark_felt!("1fc35de150561b6229137b3f253fc1c894c93b1c184a8ca0d0f7171a64bcd04"), addr_2_root.0);
    let delegate_root = prepare_os_test.get_contract_root(*TESTING_DELEGATE_ADDREESS_0_12_2).unwrap();
    assert_eq!(stark_felt!("4ed2a0d5f47780aee355c14a37ab2ae7dc8fb6f73773563e02fef51b4ec4abe"), delegate_root.0);
}

#[rstest]
fn parse_os_input(load_input: &StarknetOsInput) {
    assert_eq!(Felt252::from_hex(TESTING_BLOCK_HASH).unwrap(), load_input.block_hash);
    assert_eq!(Felt252::from_hex(EXPECTED_PREV_ROOT).unwrap(), load_input.contract_state_commitment_info.previous_root);
    assert_eq!(
        Felt252::from_hex(EXPECTED_UPDATED_ROOT).unwrap(),
        load_input.contract_state_commitment_info.updated_root
    );
    assert!(!load_input.transactions.is_empty());
}

#[rstest]
fn parse_os_output(load_input: &StarknetOsInput, load_output: StarknetOsOutput) {
    assert_eq!(load_input.contract_state_commitment_info.previous_root, load_output.prev_state_root);
    assert_eq!(load_input.contract_state_commitment_info.updated_root, load_output.new_state_root);
    assert_eq!(Felt252::from(1), load_output.block_number);
    assert_eq!(load_input.block_hash, load_output.block_hash);
    assert_eq!(felt_api2vm(load_input.general_config.starknet_os_config.hash()), load_output.config_hash);
    assert_eq!(4, load_output.messages_to_l1.len());
    assert_eq!(4, load_output.messages_to_l2.len());
    assert_eq!(4, load_output.state_updates.len());
    assert_eq!(4, load_output.contract_class_diff.len());
}

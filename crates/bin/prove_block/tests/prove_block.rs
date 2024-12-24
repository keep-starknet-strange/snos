use cairo_vm::types::layout_name::LayoutName;
use cairo_vm::vm::runners::cairo_pie::CairoPie;
use prove_block::{debug_prove_error, get_memory_segment, prove_block};
use rstest::rstest;
const DEFAULT_COMPILED_OS: &[u8] = include_bytes!("../../../../build/os_latest.json");

// # These blocks verify the following issues:
// # * 76793: the first block that we managed to prove, only has a few invoke txs
// # * 76766 / 76775: additional basic blocks
// # * 76832: contains a reverted tx
// # * 86507 / 124533: a failing assert that happened because we used the wrong VersionedConstants
// # * 87023: failing for Core(TestLessThanOrEqualAddress) hint not being implemented in cairo vm and SHA256_PROCESS_BLOCK syscall in SNOS
// # * 87019: diff assert values in contract subcall
// # * 90000: one of the subcalls results in a call to `replace_class()`.
// # * 87041: block with nonce bump inconsistency
// # * 66645 / 66776: Blob DA blocks
// # * 97581, 101556, 102076 deploy account txns
// # * 155016 / 125622 fix writes to zero (storage value not included in the tree)
// # * 160035: EvalCircuit hint used
// # * 164333 / 169203: Declare and Deploy on the same block
// # * 155140 / 155830: dest_ptr not a relocatable
#[rstest]
#[case::small_block_with_only_invoke_txs(76793, "v0_7")]
#[case::additional_basic_blocks_1(76766, "v0_7")]
#[case::additional_basic_blocks_2(76775, "v0_7")]
#[case::block_with_reverted_tx(76832, "v0_7")]
#[case::failing_assert_on_versioned_constants_1(86507, "v0_7")]
#[case::core_hint_test_less_than_or_equal_address(87023, "v0_7")]
#[case::failing_assert_on_versioned_constants_2(124533, "v0_7")]
#[case::fix_diff_assert_values_in_contract_subcall(87019, "v0_7")]
#[case::invoke_with_replace_class(90000, "v0_7")]
#[case::write_to_zero_with_edge_node(125622, "v0_7")]
#[case::l1_handler(98000, "v0_7")]
#[case::invoke_with_call_to_deploy_syscall(124534, "v0_7")]
#[case::block_with_nonce_bump_inconsistency(87041, "v0_7")]
#[case::block_with_blob_da_1(66645, "v0_7")]
#[case::block_with_blob_da_2(66776, "v0_7")]
#[case::declare_tx(76840, "v0_7")]
#[case::deploy_account_v1(97581, "v0_7")]
#[case::deploy_account_v3(101556, "v0_7")]
#[case::deploy_account_many_txs(102076, "v0_7")]
#[case::edge_bottom_not_found(155016, "v0_7")]
#[case::eval_circuit(160035, "v0_7")]
#[case::declare_and_deploy_in_same_block(164333, "v0_7")]
#[case::declare_and_deploy_in_same_block(169206, "v0_7")]
#[case::dest_ptr_not_a_relocatable(155140, "v0_7")]
#[case::dest_ptr_not_a_relocatable_2(155830, "v0_7")]
#[case::inconsistent_cairo0_class_hash_0(30000, "v0_7")]
#[case::inconsistent_cairo0_class_hash_1(204936, "v0_7")]
#[case::no_possible_convertion_1(155007, "v0_7")]
#[case::no_possible_convertion_2(155029, "v0_7")]
#[case::reference_pie_with_full_output_enabled(173404, "v0_7")]
#[case::inconsistent_cairo0_class_hash_2(159674, "v0_7")]
#[case::inconsistent_cairo0_class_hash_3(164180, "v0_7")]
#[case::key_not_in_proof_0(155087, "v0_7")]
#[case::key_not_in_proof_1(162388, "v0_7")]
#[case::key_not_in_proof_2(155172, "v0_7")]
#[case::l1_gas_and_l1_gas_price_are_0(161476, "v0_7")]
#[case::key_not_in_proof_3(156855, "v0_7")]
#[case::key_not_in_proof_4(174968, "v0_7")]
#[case::timestamp_rounding_1(162389, "v0_7")]
#[case::timestamp_rounding_2(167815, "v0_7")]
#[case::missing_constant_max_high(164684, "v0_7")]
#[case::retdata_not_a_relocatable(160033, "v0_7")]
#[case::get_tx_info_using_ptr_over_relocatable(243766, "v0_7")]
// The following four tests were added due to errors encountered during reexecution with blockifier
#[case::dict_error_no_value_found_for_key(161599, "v0_7")]
#[case::peekable_peek_is_none(174156, "v0_7")]
#[case::no_more_storage_reads_available(161884, "v0_7")]
#[case::no_more_storage_reads_available(174027, "v0_7")]
#[case::memory_addresses_must_be_relocatable(202083, "v0_7")]
#[case::memory_invalid_signature(216914, "v0_7")]
#[case::diff_assert_values(218624, "v0_7")]
#[case::could_nt_compute_operand_op1(204337, "v0_7")]
// The following ten tests were added due key not found in preimage (verify_game contract function related)
#[case::key_not_found_in_preimage_0(237025, "v0_7")]
#[case::key_not_found_in_preimage_1(237030, "v0_7")]
#[case::key_not_found_in_preimage_2(237037, "v0_7")]
#[case::key_not_found_in_preimage_3(237042, "v0_7")]
#[case::key_not_found_in_preimage_4(237044, "v0_7")]
#[case::key_not_found_in_preimage_5(237053, "v0_7")]
#[case::key_not_found_in_preimage_6(237083, "v0_7")]
#[case::key_not_found_in_preimage_7(237086, "v0_7")]
#[case::key_not_found_in_preimage_8(235385, "v0_7")]
#[case::key_not_found_in_preimage_9(235620, "v0_7")]
// The following five tests were added due to test the json rpc api v0_8
#[case::small_block_with_only_invoke_txs_v08(76793, "v0_8")]
#[case::block_with_reverted_tx_v08(76832, "v0_8")]
#[case::invoke_with_replace_class_v08(90000, "v0_8")]
#[case::l1_handler_v08(98000, "v0_8")]
#[case::key_not_in_proof_v08(155087, "v0_8")]
#[ignore = "Requires a running Pathfinder node"]
#[tokio::test(flavor = "multi_thread")]
async fn test_prove_selected_blocks(#[case] block_number: u64, #[case] rpc_version: &str) {
    let endpoint = std::env::var("PATHFINDER_RPC_URL").expect("Missing PATHFINDER_RPC_URL in env");
    let (snos_pie, _snos_output) =
        prove_block(DEFAULT_COMPILED_OS, block_number, &endpoint, rpc_version, LayoutName::all_cairo, true)
            .await
            .map_err(debug_prove_error)
            .expect("OS generate Cairo PIE");
    snos_pie.run_validity_checks().expect("Valid SNOS PIE");

    if let Some(reference_pie_bytes) = get_reference_pie_bytes(block_number) {
        println!("Block {}: Checking against reference PIE", block_number);
        let reference_pie = CairoPie::from_bytes(&reference_pie_bytes).expect("reference PIE");
        reference_pie.run_validity_checks().expect("Valid reference PIE");

        let output_segment_index = 2;
        assert_eq!(
            get_memory_segment(&reference_pie, output_segment_index),
            get_memory_segment(&snos_pie, output_segment_index)
        );
    }
}

fn get_reference_pie_bytes(block_number: u64) -> Option<Vec<u8>> {
    match block_number {
        173404 => Some(include_bytes!("../reference-pies/173404.zip").to_vec()),
        _ => None,
    }
}

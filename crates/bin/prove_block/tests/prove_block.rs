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
#[case::small_block_with_only_invoke_txs(76793)]
#[case::additional_basic_blocks_1(76766)]
#[case::additional_basic_blocks_2(76775)]
#[case::block_with_reverted_tx(76832)]
#[case::failing_assert_on_versioned_constants_1(86507)]
#[case::core_hint_test_less_than_or_equal_address(87023)]
#[case::failing_assert_on_versioned_constants_2(124533)]
#[case::fix_diff_assert_values_in_contract_subcall(87019)]
#[case::invoke_with_replace_class(90000)]
#[case::write_to_zero_with_edge_node(125622)]
#[case::l1_handler(98000)]
#[case::invoke_with_call_to_deploy_syscall(124534)]
#[case::block_with_nonce_bump_inconsistency(87041)]
#[case::block_with_blob_da_1(66645)]
#[case::block_with_blob_da_2(66776)]
#[case::declare_tx(76840)]
#[case::deploy_account_v1(97581)]
#[case::deploy_account_v3(101556)]
#[case::deploy_account_many_txs(102076)]
#[case::edge_bottom_not_found(155016)]
#[case::eval_circuit(160035)]
#[case::declare_and_deploy_in_same_block(164333)]
#[case::declare_and_deploy_in_same_block(169206)]
#[case::dest_ptr_not_a_relocatable(155140)]
#[case::dest_ptr_not_a_relocatable_2(155830)]
#[case::inconsistent_cairo0_class_hash_0(30000)]
#[case::inconsistent_cairo0_class_hash_1(204936)]
#[case::no_possible_convertion_1(155007)]
#[case::no_possible_convertion_2(155029)]
#[case::reference_pie_with_full_output_enabled(173404)]
#[case::inconsistent_cairo0_class_hash_2(159674)]
#[case::inconsistent_cairo0_class_hash_3(164180)]
#[case::key_not_in_proof_0(155087)]
#[case::key_not_in_proof_1(162388)]
#[case::key_not_in_proof_2(155172)]
#[case::l1_gas_and_l1_gas_price_are_0(161476)]
#[case::key_not_in_proof_3(156855)]
#[case::key_not_in_proof_4(174968)]
#[case::timestamp_rounding_1(162389)]
#[case::timestamp_rounding_2(167815)]
#[case::missing_constant_max_high(164684)]
#[case::retdata_not_a_relocatable(160033)]
#[case::get_tx_info_using_ptr_over_relocatable(243766)]
// The following four tests were added due to errors encountered during reexecution with blockifier
#[case::dict_error_no_value_found_for_key(161599)]
#[case::peekable_peek_is_none(174156)]
#[case::no_more_storage_reads_available(161884)]
#[case::no_more_storage_reads_available(174027)]
#[ignore = "Requires a running Pathfinder node"]
#[tokio::test(flavor = "multi_thread")]
async fn test_prove_selected_blocks(#[case] block_number: u64) {
    let endpoint = std::env::var("PATHFINDER_RPC_URL").expect("Missing PATHFINDER_RPC_URL in env");
    let (snos_pie, _snos_output) =
        prove_block(DEFAULT_COMPILED_OS, block_number, &endpoint, LayoutName::all_cairo, true)
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

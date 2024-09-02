use cairo_vm::types::layout_name::LayoutName;
use prove_block::{debug_prove_error, prove_block};
use rstest::rstest;

// # These blocks verify the following issues:
// # * 76793: the first block that we managed to prove, only has a few invoke txs
// # * 76766 / 76775: additional basic blocks
// # * 76832: contains a reverted tx
// # * 86507 / 124533: a failing assert that happened because we used the wrong VersionedConstants
// # * 87019: diff assert values in contract subcall
// # * 90000: one of the subcalls results in a call to `replace_class()`.
#[rstest]
#[case::small_block_with_only_invoke_txs(76793)]
#[case::additional_basic_blocks_1(76766)]
#[case::additional_basic_blocks_2(76775)]
#[case::block_with_reverted_tx(76832)]
#[case::failing_assert_on_versioned_constants_1(86507)]
#[case::failing_assert_on_versioned_constants_2(124533)]
#[case::fix_diff_assert_values_in_contract_subcall(87019)]
#[case::invoke_with_replace_class(90000)]
#[ignore = "Requires a running Pathfinder node"]
#[tokio::test(flavor = "multi_thread")]
async fn test_prove_selected_blocks(#[case] block_number: u64) {
    let endpoint = std::env::var("PATHFINDER_RPC_URL").expect("Missing PATHFINDER_RPC_URL in env");
    prove_block(block_number, &endpoint, LayoutName::all_cairo)
        .await
        .map_err(debug_prove_error)
        .expect("Block could not be proven");
}

use cairo_vm::types::layout_name::LayoutName;
use prove_block::prove_block;
use rstest::rstest;

// # These blocks verify the following issues:
// # * 76793: the first block that we managed to prove, only has a few invoke txs
// # * 76766 / 76775: additional basic blocks
// # * 86507 / 124533: a failing assert that happened because we used the wrong VersionedConstants
// # * 87019: diff assert values in contract subcall
#[rstest(
    block_number => [76793, 76766, 76775, 86507, 87019, 124533]
)]
#[ignore = "Requires a running Pathfinder node"]
#[tokio::test(flavor = "multi_thread")]
async fn test_prove_selected_blocks(block_number: u64) {
    let endpoint = std::env::var("PATHFINDER_RPC_URL").expect("Missing PATHFINDER_RPC_URL in env");
    prove_block(block_number, &endpoint, LayoutName::starknet_with_keccak).await.expect("Block could not be proved");
}

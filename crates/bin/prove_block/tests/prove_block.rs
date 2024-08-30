use cairo_vm::types::layout_name::LayoutName;
use cairo_vm::vm::errors::cairo_run_errors::CairoRunError;
use prove_block::{prove_block, ProveBlockError};
use rstest::rstest;
use starknet_os::error::SnOsError;

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
    let res = prove_block(block_number, &endpoint, LayoutName::starknet_with_keccak).await;
    match &res {
        Err(ProveBlockError::SnOsError(SnOsError::Runner(CairoRunError::VmException(vme)))) => {
            if let Some(traceback) = vme.traceback.as_ref() {
                log::error!("traceback:\n{}", traceback);
            }
            if let Some(inst_location) = &vme.inst_location {
                log::error!("died at: {}:{}", inst_location.input_file.filename, inst_location.start_line);
                log::error!("inst_location:\n{:?}", inst_location);
            }
        }
        Err(e) => {
            log::error!("exception:\n{:#?}", e);
        }
        _ => {}
    }
}

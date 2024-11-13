use std::fs;
use std::path::PathBuf;

use cairo_vm::hint_processor::hint_processor_utils::felt_to_usize;
use cairo_vm::types::layout_name::LayoutName;
use cairo_vm::vm::runners::cairo_pie::CairoPie;
use cairo_vm::Felt252;
use clap::Parser;
use prove_block::{debug_prove_error, get_memory_segment, prove_block};

const DEFAULT_COMPILED_OS: &[u8] = include_bytes!("../../../../build/os_latest.json");

#[derive(Parser, Debug)]
struct Args {
    /// Pie-zip to compare.
    #[arg(long = "pie-path")]
    zip_pie_path: PathBuf,

    /// RPC endpoint to use for fact fetching
    #[arg(long = "rpc-provider", default_value = "http://localhost:9545")]
    rpc_provider: String,
}

fn init_logging() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .format_timestamp(None)
        .try_init()
        .expect("Failed to configure env_logger");
}

#[tokio::main]
async fn main() {
    init_logging();

    let args = Args::parse();

    let zip_pie_path = args.zip_pie_path;
    let endpoint = args.rpc_provider;

    let reference_pie_bytes = fs::read(zip_pie_path).expect("Read Reference PIE");
    let reference_pie = CairoPie::from_bytes(&reference_pie_bytes).expect("reference PIE");
    reference_pie.run_validity_checks().expect("Valid reference PIE");

    let block_number: u64 =
        felt_to_usize(&get_pie_block_number(&reference_pie)).unwrap().try_into().expect("Block number is too big");

    log::info!("Runnin SNOS for block number: {}", block_number);

    let (snos_pie, _snos_output) =
        prove_block(DEFAULT_COMPILED_OS, block_number, &endpoint, LayoutName::all_cairo, true)
            .await
            .map_err(debug_prove_error)
            .expect("OS generate Cairo PIE");

    snos_pie.run_validity_checks().expect("Valid SNOS PIE");

    // While initializing cairo-vm, the first segment is the the one containing the program instructions. The second one is the execution segment.
    // After that, the builtins are loaded in order. The first one is always the output builtin
    // References:
    // https://github.com/lambdaclass/cairo-vm/blob/159f67da19964cc54a95423a69470a26e534a13d/vm/src/vm/runners/cairo_runner.rs#L249-L279
    // https://github.com/lambdaclass/cairo-vm/blob/159f67da19964cc54a95423a69470a26e534a13d/vm/src/vm/runners/cairo_runner.rs#L456-L466
    // cairo-vm test output segment:
    // https://github.com/lambdaclass/cairo-vm/blob/159f67da19964cc54a95423a69470a26e534a13d/cairo1-run/src/cairo_run.rs#L1732
    let output_segment_index = 2;

    assert_eq!(
        get_memory_segment(&reference_pie, output_segment_index),
        get_memory_segment(&snos_pie, output_segment_index)
    );

    log::info!("✅ SNOS Pie has the same output as reference pie");
}

fn get_pie_block_number(cairo_pie: &CairoPie) -> Felt252 {
    // We know that current block number is on position (2,3)
    // Output segment, position 3.
    let output_segment_index = 2_usize;
    let current_block_index = 3_usize;
    let block_number = cairo_pie
        .memory
        .0
        .iter()
        .find(|((segment_index, offset), _value)| {
            *segment_index == output_segment_index && *offset == current_block_index
        })
        .map(|((_segment_index, _offset), value)| value.clone())
        .expect("Block number not found in CairoPie memory.");

    block_number.get_int().expect("Block number is a Int")
}

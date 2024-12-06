use cairo_vm::types::layout_name::LayoutName;
use clap::Parser;
use prove_block::debug_prove_error;

const DEFAULT_COMPILED_OS: &[u8] = include_bytes!("../../../../build/os_latest.json");

#[derive(Parser, Debug)]
struct Args {
    /// Block to prove.
    #[arg(long = "block-number")]
    block_number: u64,

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

    let block_number = args.block_number;
    let layout = LayoutName::all_cairo;

    let result = prove_block::prove_block(DEFAULT_COMPILED_OS, block_number, &args.rpc_provider, layout, true).await;
    let (pie, _snos_output) = result.map_err(debug_prove_error).expect("Block proven");
    pie.run_validity_checks().expect("Valid PIE");
}

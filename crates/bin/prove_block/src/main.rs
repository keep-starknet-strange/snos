use cairo_vm::types::layout_name::LayoutName;
use clap::Parser;
use prove_block::{debug_prove_error, ProveBlockError};

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
async fn main() -> Result<(), Box<ProveBlockError>> {
    init_logging();

    let args = Args::parse();

    let block_number = args.block_number;
    let layout = LayoutName::all_cairo;

    let result = prove_block::prove_block(block_number, &args.rpc_provider, layout, true).await;
    match result {
        Ok((_pie, _output)) => {
            println!("Block {} proven successfully", block_number);
            Ok(())
        },
        Err(err) => {
            // Use debug_prove_error to format the error and return it
            let formatted_error = debug_prove_error(err);
            eprintln!("Error proving block {}: {:?}", block_number, formatted_error);
            Err(Box::new(formatted_error)) // Return the error here
        }
    }
}


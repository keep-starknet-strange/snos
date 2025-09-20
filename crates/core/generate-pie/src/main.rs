//! Main entry point for the generate-pie application.
//!
//! This binary demonstrates how to use the generate-pie library to generate
//! Cairo PIE files from Starknet blocks.

use clap::Parser;
use generate_pie::generate_pie;
use generate_pie::types::{ChainConfig, OsHintsConfiguration, PieGenerationInput};
use log::{error, info};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(name = "snos-poc")]
#[command(about = "SNOS PoC - Starknet OS Proof of Concept for block processing")]
struct Cli {
    /// RPC URL to connect to
    #[arg(short, long, default_value = "https://pathfinder-mainnet.d.karnot.xyz")]
    rpc_url: String,

    /// Block number(s) to process
    #[arg(short, long, value_delimiter = ',')]
    blocks: Vec<u64>,

    /// Output path for the PIE file
    #[arg(short, long)]
    output: Option<String>,

    /// Chain configuration (defaults to Sepolia)
    #[arg(long, default_value = "sepolia")]
    chain: String,
}
/// Main entry point for the generate-pie application.
///
/// This function demonstrates the usage of the generate-pie library by:
/// 1. Initializing logging
/// 2. Creating a configuration for PIE generation
/// 3. Calling the core PIE generation function
/// 4. Handling the results and errors appropriately
///
/// # Returns
///
/// Returns `Ok(())` if the PIE generation completes successfully, or an error
/// if any step of the process fails.
///
/// # Errors
///
/// This function can return various errors including
/// - Configuration validation errors
/// - RPC client connection errors
/// - Block processing errors
/// - OS execution errors
/// - File I/O errors
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize logging
    env_logger::init();

    let cli = Cli::parse();

    info!("Starting SNOS PIE generation application");

    // Validate that at least one block is provided
    if cli.blocks.is_empty() {
        error!("At least one block number must be provided");
        std::process::exit(1);
    }

    // Build the input configuration
    let input = PieGenerationInput {
        rpc_url: cli.rpc_url.clone(),
        blocks: cli.blocks.clone(),
        chain_config: ChainConfig::default(), // Uses Sepolia defaults for now
        os_hints_config: OsHintsConfiguration::default(), // Uses sensible defaults
        output_path: cli.output.clone(),
    };

    // Display configuration information
    info!("Configuration:");
    info!("  RPC URL: {}", input.rpc_url);
    info!("  Blocks: {:?}", input.blocks);
    info!("  Chain ID: {:?}", input.chain_config.chain_id);
    info!("  Is L3: {}", input.chain_config.is_l3);
    info!("  Debug mode: {}", input.os_hints_config.debug_mode);
    info!("  Use KZG DA: {}", input.os_hints_config.use_kzg_da);
    info!("  Output path: {:?}", input.output_path);

    // Call the core PIE generation function
    match generate_pie(input).await {
        Ok(result) => {
            info!("PIE generation completed successfully!");
            info!("  Blocks processed: {:?}", result.blocks_processed);
            if let Some(output_path) = result.output_path {
                info!("  Output written to: {}", output_path);
            }
        }
        Err(e) => {
            error!("PIE generation failed: {}", e);
            return Err(e.into());
        }
    }

    info!("SNOS execution completed successfully!");
    Ok(())
}

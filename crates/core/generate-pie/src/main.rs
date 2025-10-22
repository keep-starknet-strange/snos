//! Main entry point for the generate-pie application.
//!
//! This binary demonstrates how to use the generate-pie library to generate
//! Cairo PIE files from Starknet blocks.

use cairo_vm::types::layout_name::LayoutName;
use clap::Parser;
use generate_pie::constants::{DEFAULT_SEPOLIA_ETH_FEE_TOKEN, DEFAULT_SEPOLIA_STRK_FEE_TOKEN};
use generate_pie::types::{ChainConfig, OsHintsConfiguration, PieGenerationInput};
use generate_pie::{generate_pie, parse_layout};
use log::{error, info};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(name = "snos")]
#[command(about = "SNOS - Starknet OS for block processing")]
struct Cli {
    /// Block number(s) to process
    #[arg(short, long, value_delimiter = ',', required = true, env = "SNOS_BLOCKS")]
    blocks: Vec<u64>,

    /// RPC URL to connect to
    #[arg(short, long, required = true, env = "SNOS_RPC_URL")]
    rpc_url: String,

    /// Layout to be used for SNOS
    #[arg(short, long, default_value = "all_cairo", value_parser=parse_layout, env = "SNOS_LAYOUT")]
    layout: LayoutName,

    /// Chain configuration (defaults to Sepolia)
    #[arg(long, env = "SNOS_NETWORK", default_value = "sepolia")]
    chain: String,

    /// STRK fee token address
    #[arg(short, long, default_value = DEFAULT_SEPOLIA_STRK_FEE_TOKEN, env = "SNOS_STRK_FEE_TOKEN_ADDRESS")]
    strk_fee_token_address: String,

    /// ETH fee token address
    #[arg(short, long, default_value = DEFAULT_SEPOLIA_ETH_FEE_TOKEN, env = "SNOS_ETH_FEE_TOKEN_ADDRESS")]
    eth_fee_token_address: String,

    /// Is L3
    #[arg(short, long, default_value = "false", env = "SNOS_IS_L3")]
    is_l3: bool,

    /// Output path for the PIE file
    #[arg(short, long, env = "SNOS_OUTPUT")]
    output: Option<String>,
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
        chain_config: ChainConfig::new(&cli.chain, &cli.strk_fee_token_address, &cli.eth_fee_token_address, false),
        os_hints_config: OsHintsConfiguration::default_with_is_l3(cli.is_l3),
        output_path: cli.output.clone(),
        layout: cli.layout,
    };

    // Display configuration information
    info!("Configuration:");
    info!("  RPC URL: {}", input.rpc_url);
    info!("  Blocks: {:?}", input.blocks);
    info!("  Chain ID: {:?}", input.chain_config.chain_id);
    info!("  STRK Fee Token: {:?}", input.chain_config.strk_fee_token_address);
    info!("  ETH Fee Token: {:?}", input.chain_config.eth_fee_token_address);
    info!("  Layout: {:?}", input.layout);
    info!("  Is L3: {}", input.chain_config.is_l3);
    info!("  Debug mode: {}", input.os_hints_config.debug_mode);
    info!("  Full Output: {}", input.os_hints_config.full_output);
    info!("  Use KZG DA: {}", input.os_hints_config.use_kzg_da);
    info!("  Output path: {:?}", input.output_path);

    // Call the core PIE generation function
    match generate_pie(input).await {
        Ok((result, _)) => {
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

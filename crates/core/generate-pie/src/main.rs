//! Main entry point for the generate-pie application.
//!
//! This binary demonstrates how to use the generate-pie library to generate
//! Cairo PIE files from Starknet blocks.

use anyhow::bail;
use cairo_vm::types::layout_name::LayoutName;
use clap::Parser;
use generate_pie::constants::{DEFAULT_SEPOLIA_ETH_FEE_TOKEN, DEFAULT_SEPOLIA_STRK_FEE_TOKEN};
use generate_pie::generate_pie;
use generate_pie::types::{ChainConfig, OsHintsConfiguration, PieGenerationInput};
use log::{error, info};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(name = "snos")]
#[command(about = "SNOS - Starknet OS for block processing")]
struct Cli {
    /// RPC URL to connect to
    #[arg(short, long, required = true, env = "SNOS_RPC_URL")]
    rpc_url: String,

    /// Block number(s) to process
    #[arg(short, long, value_delimiter = ',', required = true, env = "SNOS_BLOCKS")]
    blocks: Vec<u64>,

    /// Layout to be used for SNOS
    #[arg(short, long, required = true, default_value = "all_cairo", value_parser=parse_layout, env = "SNOS_LAYOUT")]
    layout: LayoutName,

    /// STRK fee token address
    #[arg(short, long, required = true, default_value = DEFAULT_SEPOLIA_STRK_FEE_TOKEN, env = "SNOS_STRK_FEE_TOKEN_ADDRESS")]
    pub strk_fee_token_address: String,

    /// ETH fee token address
    #[arg(short, long, required = true, default_value = DEFAULT_SEPOLIA_ETH_FEE_TOKEN, env = "SNOS_ETH_FEE_TOKEN_ADDRESS")]
    pub eth_fee_token_address: String,

    /// Output path for the PIE file
    #[arg(short, long, env = "SNOS_OUTPUT")]
    output: Option<String>,

    /// Chain configuration (defaults to Sepolia)
    #[arg(long, env = "SNOS_NETWORK", default_value = "mainnet")]
    chain: String,

    /// Whether this is an L3 chain (true) or L2 chain (false)
    #[arg(long, env = "SNOS_IS_L3", default_value = "false")]
    is_l3: bool,
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

    // Build the chain configuration using the builder pattern
    let chain_config = ChainConfig::new()
        .with_chain_id(&cli.chain)
        .with_strk_fee_token_address_str(&cli.strk_fee_token_address)?
        .with_is_l3(cli.is_l3);

    // Build the input configuration
    let input = PieGenerationInput {
        rpc_url: cli.rpc_url.clone(),
        blocks: cli.blocks.clone(),
        chain_config,
        os_hints_config: OsHintsConfiguration::default(), // Uses sensible defaults
        output_path: cli.output.clone(),
        layout: cli.layout,
        strk_fee_token_address: cli.strk_fee_token_address,
        eth_fee_token_address: cli.eth_fee_token_address,
    };

    // Display configuration information
    info!("Configuration:");
    info!("  RPC URL: {}", input.rpc_url);
    info!("  Blocks: {:?}", input.blocks);
    info!("  Chain ID: {:?}", input.chain_config.chain_id);
    info!("  Layout: {:?}", input.layout);
    info!("  Is L3: {}", input.chain_config.is_l3);
    info!("  Debug mode: {}", input.os_hints_config.debug_mode);
    info!("  Full Output: {}", input.os_hints_config.full_output);
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

fn parse_layout(layout: &str) -> anyhow::Result<LayoutName> {
    match layout {
        "plain" => Ok(LayoutName::plain),
        "small" => Ok(LayoutName::small),
        "dex" => Ok(LayoutName::dex),
        "recursive" => Ok(LayoutName::recursive),
        "starknet" => Ok(LayoutName::starknet),
        "starknet_with_keccak" => Ok(LayoutName::starknet_with_keccak),
        "recursive_large_output" => Ok(LayoutName::recursive_large_output),
        "recursive_with_poseidon" => Ok(LayoutName::recursive_with_poseidon),
        "all_solidity" => Ok(LayoutName::all_solidity),
        "all_cairo" => Ok(LayoutName::all_cairo),
        "dynamic" => Ok(LayoutName::dynamic),
        "all_cairo_stwo" => Ok(LayoutName::all_cairo_stwo),
        _ => bail!("Invalid layout: {}", layout),
    }
}

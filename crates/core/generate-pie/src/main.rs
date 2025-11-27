//! Main entry point for the generate-pie application.
//!
//! This binary demonstrates how to use the generate-pie library to generate
//! Cairo PIE files from Starknet blocks.

use std::collections::BTreeSet;

use cairo_vm::types::layout_name::LayoutName;
use clap::Parser;
use generate_pie::constants::{DEFAULT_SEPOLIA_ETH_FEE_TOKEN, DEFAULT_SEPOLIA_STRK_FEE_TOKEN};
use generate_pie::types::{ChainConfig, OsHintsConfiguration, PieGenerationInput};
use generate_pie::utils::load_versioned_constants;
use generate_pie::{generate_pie, parse_layout};
use log::{error, info};

/// Parses a range string in format "start,end" and returns (start, end).
/// Both start and end are inclusive.
fn parse_range(range_str: &str) -> Result<(u64, u64), String> {
    let parts: Vec<&str> = range_str.split(',').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid range format '{}'. Expected format: start,end (e.g., 1,999)", range_str));
    }

    let start: u64 = parts[0]
        .trim()
        .parse()
        .map_err(|_| format!("Invalid start value '{}'. Must be a positive integer.", parts[0]))?;
    let end: u64 = parts[1]
        .trim()
        .parse()
        .map_err(|_| format!("Invalid end value '{}'. Must be a positive integer.", parts[1]))?;

    if start > end {
        return Err(format!("Invalid range: start ({}) must be less than or equal to end ({})", start, end));
    }

    Ok((start, end))
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(name = "snos")]
#[command(about = "SNOS - Starknet OS for block processing")]
struct Cli {
    /// Block number(s) to process (comma-separated)
    #[arg(short, long, value_delimiter = ',', env = "SNOS_BLOCKS")]
    blocks: Vec<u64>,

    /// Block range to process (format: start,end - inclusive)
    #[arg(short = 'R', long, env = "SNOS_RANGE")]
    range: Option<String>,

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

    /// Path to a JSON file containing versioned constants (optional)
    #[arg(long, env = "SNOS_VERSIONED_CONSTANTS_PATH")]
    versioned_constants_path: Option<String>,
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

    // Collect blocks from --blocks and --range arguments
    let mut blocks: BTreeSet<u64> = cli.blocks.into_iter().collect();

    // Parse and add blocks from range if provided
    if let Some(range_str) = &cli.range {
        match parse_range(range_str) {
            Ok((start, end)) => {
                info!("Adding blocks from range {} to {} (inclusive)", start, end);
                for block in start..=end {
                    blocks.insert(block);
                }
            }
            Err(e) => {
                error!("Range parsing error: {}", e);
                std::process::exit(1);
            }
        }
    }

    // Convert to sorted Vec
    let blocks: Vec<u64> = blocks.into_iter().collect();

    // Validate that at least one block is provided
    if blocks.is_empty() {
        error!("At least one block number must be provided. Use --blocks and/or --range.");
        std::process::exit(1);
    }

    // Load versioned constants from file if provided
    let versioned_constants = load_versioned_constants(cli.versioned_constants_path.as_deref()).map_err(|e| {
        error!("{}", e);
        e
    })?;

    // Build the input configuration
    let input = PieGenerationInput {
        rpc_url: cli.rpc_url.clone(),
        blocks: blocks.clone(),
        chain_config: ChainConfig::new(&cli.chain, &cli.strk_fee_token_address, &cli.eth_fee_token_address, cli.is_l3),
        os_hints_config: OsHintsConfiguration::default_with_is_l3(cli.is_l3),
        output_path: cli.output.clone(),
        layout: cli.layout,
        versioned_constants,
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
    info!(
        "  Versioned constants: {}",
        if input.versioned_constants.is_some() { "provided from file" } else { "auto-detect from block" }
    );

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

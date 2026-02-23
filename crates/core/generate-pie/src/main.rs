//! Main entry point for the generate-pie application.
//!
//! This binary demonstrates how to use the generate-pie library to generate
//! Cairo PIE files from Starknet blocks.

use std::collections::BTreeSet;
use std::str::FromStr;

use cairo_vm::types::layout_name::LayoutName;
use clap::Parser;
use generate_pie::constants::{DEFAULT_SEPOLIA_ETH_FEE_TOKEN, DEFAULT_SEPOLIA_STRK_FEE_TOKEN};
use generate_pie::types::{ChainConfig, OsHintsConfiguration, PieGenerationInput};
use generate_pie::utils::load_versioned_constants;
use generate_pie::{generate_pie, parse_layout, parse_public_key};
use log::{error, info};

/// Represents a range of block numbers (inclusive).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BlockRange {
    start: u64,
    end: u64,
}

impl BlockRange {
    /// Returns an iterator over all block numbers in this range (inclusive).
    fn iter(&self) -> impl Iterator<Item = u64> {
        self.start..=self.end
    }
}

impl FromStr for BlockRange {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (start_raw, end_raw) = s
            .split_once(',')
            .ok_or_else(|| format!("Invalid range format '{}'. Expected format: start,end (e.g., 1,999).", s))?;

        let start: u64 = start_raw
            .trim()
            .parse()
            .map_err(|_| format!("Invalid start value '{}'. Must be a positive integer.", start_raw))?;
        let end: u64 = end_raw
            .trim()
            .parse()
            .map_err(|_| format!("Invalid end value '{}'. Must be a positive integer.", end_raw))?;

        if start > end {
            return Err(format!("Invalid range: start ({}) must be less than or equal to end ({}).", start, end));
        }

        Ok(BlockRange { start, end })
    }
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
    range: Option<BlockRange>,

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

    /// Public keys for OS execution (comma-separated hex values)
    #[arg(long, value_delimiter = ',', value_parser = parse_public_key, env = "SNOS_PUBLIC_KEYS")]
    public_keys: Option<Vec<starknet_types_core::felt::Felt>>,
}

const EMPTY_BLOCK_SELECTION_ERROR: &str = "At least one block number must be provided. Use --blocks and/or --range.";

fn collect_blocks(blocks: Vec<u64>, range: Option<BlockRange>) -> Result<Vec<u64>, &'static str> {
    let mut selected_blocks: BTreeSet<u64> = blocks.into_iter().collect();

    if let Some(range) = range {
        selected_blocks.extend(range.iter());
    }

    if selected_blocks.is_empty() {
        return Err(EMPTY_BLOCK_SELECTION_ERROR);
    }

    Ok(selected_blocks.into_iter().collect())
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

    let mut cli = Cli::parse();

    info!("Starting SNOS PIE generation application");

    if let Some(range) = cli.range {
        info!("Adding blocks from range {} to {} (inclusive)", range.start, range.end);
    }

    let blocks = match collect_blocks(std::mem::take(&mut cli.blocks), cli.range) {
        Ok(blocks) => blocks,
        Err(message) => {
            error!("{message}");
            std::process::exit(1);
        }
    };

    // Load versioned constants from file if provided
    let versioned_constants = load_versioned_constants(cli.versioned_constants_path.as_deref()).map_err(|e| {
        error!("{}", e);
        e
    })?;

    // Build the input configuration
    let input = PieGenerationInput {
        rpc_url: cli.rpc_url.clone(),
        blocks,
        chain_config: ChainConfig::new(&cli.chain, &cli.strk_fee_token_address, &cli.eth_fee_token_address, cli.is_l3),
        os_hints_config: OsHintsConfiguration::default_with_is_l3(cli.is_l3),
        output_path: cli.output.clone(),
        layout: cli.layout,
        versioned_constants,
        public_keys: cli.public_keys,
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
    if let Some(ref public_keys) = input.public_keys {
        info!("  Public keys: {} provided", public_keys.len());
    } else {
        info!("  Public keys: none");
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_range_parses_valid_input() {
        let range = BlockRange::from_str("1,3").expect("valid range should parse");

        assert_eq!(range.start, 1);
        assert_eq!(range.end, 3);
        assert_eq!(range.iter().collect::<Vec<_>>(), vec![1, 2, 3]);
    }

    #[test]
    fn block_range_rejects_invalid_format() {
        let error = BlockRange::from_str("1").expect_err("single value should fail");

        assert_eq!(error, "Invalid range format '1'. Expected format: start,end (e.g., 1,999).");
    }

    #[test]
    fn block_range_rejects_invalid_start() {
        let error = BlockRange::from_str("abc,2").expect_err("non numeric start should fail");

        assert_eq!(error, "Invalid start value 'abc'. Must be a positive integer.");
    }

    #[test]
    fn block_range_rejects_invalid_end() {
        let error = BlockRange::from_str("1,xyz").expect_err("non numeric end should fail");

        assert_eq!(error, "Invalid end value 'xyz'. Must be a positive integer.");
    }

    #[test]
    fn block_range_rejects_start_greater_than_end() {
        let error = BlockRange::from_str("9,2").expect_err("start greater than end should fail");

        assert_eq!(error, "Invalid range: start (9) must be less than or equal to end (2).");
    }

    #[test]
    fn collect_blocks_from_blocks_only_deduplicates_and_sorts() {
        let blocks = collect_blocks(vec![5, 3, 5, 4], None).expect("blocks should be collected");

        assert_eq!(blocks, vec![3, 4, 5]);
    }

    #[test]
    fn collect_blocks_from_range_only() {
        let blocks = collect_blocks(vec![], Some(BlockRange { start: 7, end: 9 })).expect("range should be collected");

        assert_eq!(blocks, vec![7, 8, 9]);
    }

    #[test]
    fn collect_blocks_combines_range_and_blocks() {
        let blocks = collect_blocks(vec![10, 12], Some(BlockRange { start: 11, end: 12 }))
            .expect("range and blocks should be combined");

        assert_eq!(blocks, vec![10, 11, 12]);
    }

    #[test]
    fn collect_blocks_rejects_empty_input() {
        let error = collect_blocks(vec![], None).expect_err("empty input should fail");

        assert_eq!(error, EMPTY_BLOCK_SELECTION_ERROR);
    }

    #[test]
    fn cli_parses_range_argument_into_block_range() {
        let cli = Cli::try_parse_from(["snos", "--rpc-url", "http://localhost:8545", "--range", "4,6"])
            .expect("cli should parse range argument");

        assert_eq!(cli.range, Some(BlockRange { start: 4, end: 6 }));
    }
}

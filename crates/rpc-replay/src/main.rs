use cairo_vm::types::layout_name::LayoutName;
use clap::Parser;
use generate_pie::constants::{DEFAULT_SEPOLIA_ETH_FEE_TOKEN, DEFAULT_SEPOLIA_STRK_FEE_TOKEN};
use generate_pie::error::PieGenerationError;
use generate_pie::types::{ChainConfig, OsHintsConfiguration, PieGenerationInput};
use generate_pie::{generate_pie, parse_layout};
use log::{debug, info, warn};
use rpc_client::RpcClient;
use serde::{Deserialize, Serialize};
use starknet::core::types::BlockId;
use starknet::providers::Provider;
use std::time::Duration;
use std::{error, fs};
use tokio::time::sleep;

// Custom error type to handle both regular errors and panics
#[derive(Debug)]
enum ProcessError {
    Regular(PieGenerationError),
    Panic(String),
}

impl std::fmt::Display for ProcessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProcessError::Regular(e) => write!(f, "Regular error: {}", e),
            ProcessError::Panic(msg) => write!(f, "Panic: {}", msg),
        }
    }
}

impl error::Error for ProcessError {}

/// Structure to parse the JSON file containing block numbers (original format)
#[derive(Deserialize, Serialize, Debug)]
struct BlocksJson {
    #[serde(default)]
    error_blocks: Vec<u64>,
    #[serde(default)]
    total_count: Option<usize>,
    #[serde(default)]
    min_block: Option<u64>,
    #[serde(default)]
    max_block: Option<u64>,
}

/// Structure to parse JSON files from error decoding script
#[derive(Deserialize, Serialize, Debug)]
struct ErrorDecodingJson {
    metadata: ErrorMetadata,
    failing_blocks: Vec<u64>,
    #[serde(default)]
    detailed_info: Vec<serde_json::Value>, // We don't need the detailed info for processing
}

#[derive(Deserialize, Serialize, Debug)]
struct ErrorMetadata {
    error_type: String,
    description: String,
    timestamp: String,
    total_blocks: usize,
}

/// Enum to represent different execution modes
#[derive(Debug)]
enum ExecutionMode {
    /// Start from a specific block and process sequentially
    Sequential { start_block: u64 },
    /// Process specific blocks from a JSON file
    FromJson { blocks: Vec<u64> },
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
/// NOTE: We default for Starknet Sepolia
struct Args {
    /// Starting block number (only used if --json-file is not provided)
    #[arg(long)]
    start_block: Option<u64>,

    #[arg(long, default_value = "1")]
    num_blocks: u64,

    /// JSON file containing block numbers to process
    /// Supports two formats:
    /// 1. Original: {"error_blocks": [1, 2, 3], "total_count": 3}
    /// 2. Error decoding: {"failing_blocks": [1, 2, 3], "metadata": {...}}
    #[arg(long)]
    json_file: Option<String>,

    /// RPC URL to connect to
    #[arg(long, required = true)]
    rpc_url: String,

    /// Layout to be used for SNOS
    #[arg(long, default_value = "all_cairo")]
    layout: String,

    /// Chain to use
    #[arg(long, default_value = "sepolia")]
    chain: String,

    /// STRK fee token address.
    #[arg(long, default_value = DEFAULT_SEPOLIA_STRK_FEE_TOKEN, env = "SNOS_STRK_FEE_TOKEN_ADDRESS")]
    strk_fee_token_address: String,

    /// ETH fee token address
    #[arg(long, default_value = DEFAULT_SEPOLIA_ETH_FEE_TOKEN, env = "SNOS_ETH_FEE_TOKEN_ADDRESS")]
    eth_fee_token_address: String,

    /// Is the chain an L3
    #[arg(long, default_value = "false")]
    is_l3: bool,

    /// Interval between block checks in seconds (default: 1)
    #[arg(long, default_value_t = 1)]
    interval: u64,

    /// Output directory for PIE files (default: current directory)
    #[arg(long)]
    output_dir: Option<String>,

    /// Output directory for Error logs
    #[arg(long)]
    log_dir: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn error::Error + Send + Sync>> {
    env_logger::init();
    let args = Args::parse();

    // Validate arguments and determine execution mode
    let execution_mode = match (&args.start_block, &args.json_file) {
        (Some(start_block), None) => {
            info!("🚀 Starting RPC Replay service in SEQUENTIAL mode");
            ExecutionMode::Sequential { start_block: *start_block }
        }
        (None, Some(json_file)) => {
            info!("🚀 Starting RPC Replay service in JSON mode");
            let blocks = load_blocks_from_json(json_file)?;
            info!("📄 Loaded {} blocks from JSON file", blocks.len());
            ExecutionMode::FromJson { blocks }
        }
        (Some(_), Some(_)) => {
            return Err("Cannot specify both --start-block and --json-file. Choose one mode.".into());
        }
        (None, None) => {
            return Err("Must specify either --start-block for sequential mode or --json-file for JSON mode.".into());
        }
    };

    info!("Configuration:");
    match &execution_mode {
        ExecutionMode::Sequential { start_block } => {
            info!("  Mode: Sequential");
            info!("  Start block: {}", start_block);
        }
        ExecutionMode::FromJson { blocks } => {
            info!("  Mode: JSON file");
            info!("  Total blocks to process: {}", blocks.len());
            if !blocks.is_empty() {
                info!("  Block range: {} to {}", blocks.iter().min().unwrap(), blocks.iter().max().unwrap());
            }
        }
    }
    info!("  RPC URL: {}", args.rpc_url);
    info!("  Check interval: {} seconds", args.interval);
    info!("  Error Log directory: {}", args.log_dir);

    fs::create_dir_all(&args.log_dir)?;

    // Initialize RPC client for block checking
    // let rpc_client = RpcClient::new(&args.rpc_url);
    let rpc_client = RpcClient::try_new(&args.rpc_url)
        .map_err(|e| PieGenerationError::RpcClient(format!("Failed to initialize RPC client: {:?}", e)))?;

    info!("🔄 Starting block processing");

    match execution_mode {
        ExecutionMode::Sequential { start_block } => process_sequential_mode(&args, &rpc_client, start_block).await,
        ExecutionMode::FromJson { blocks } => process_json_mode(&args, &rpc_client, blocks).await,
    }
}

/// Process blocks in sequential mode (original behavior)
async fn process_sequential_mode(
    args: &Args,
    rpc_client: &RpcClient,
    start_block: u64,
) -> Result<(), Box<dyn error::Error + Send + Sync>> {
    let mut current_block = start_block;

    info!("🔄 Starting infinite sequential block processing loop");

    loop {
        let block_set: Vec<u64> = (current_block..current_block + args.num_blocks).collect();
        info!("📋 Processing block set: {:?}", block_set);

        // Check if all blocks exist
        match check_blocks_exist(rpc_client, &block_set).await {
            Ok(true) => {
                debug!("All blocks in set {:?} exist, proceeding with PIE generation", block_set);

                // Generate PIE for this block set
                match process_block_set(args, &block_set).await {
                    Ok(output_path) => {
                        info!("Successfully generated PIE for blocks {:?} -> {}", block_set, output_path);
                        current_block += args.num_blocks;
                    }
                    Err(e) => {
                        log::error!("Failed to generate PIE for blocks {:?}: {}", block_set, e);

                        // Write error to the file
                        let error_file = format!("{}/error_blocks_{}.txt", args.log_dir, block_set[0]);
                        write_error_to_file(&error_file, &block_set, &e).await?;

                        // Move to the next set anyway to avoid getting stuck
                        current_block += args.num_blocks;
                    }
                }
            }
            Ok(false) => {
                info!("Not all blocks in set {:?} exist yet, waiting {} seconds", block_set, args.interval);
                sleep(Duration::from_secs(args.interval)).await;
            }
            Err(e) => {
                warn!("Error checking blocks {:?}: {}, retrying in {} seconds", block_set, e, args.interval);
                sleep(Duration::from_secs(args.interval)).await;
            }
        }
    }
}

/// Process blocks from a JSON file (one at a time)
async fn process_json_mode(
    args: &Args,
    rpc_client: &RpcClient,
    mut blocks: Vec<u64>,
) -> Result<(), Box<dyn error::Error + Send + Sync>> {
    // Sort blocks to process them in order
    blocks.sort();

    let total_blocks = blocks.len();
    let mut processed_count = 0;
    let mut failed_count = 0;

    info!("🔄 Starting JSON mode block processing for {} blocks", total_blocks);

    // Process each block individually
    for (index, &block_number) in blocks.iter().enumerate() {
        let progress = index + 1;

        info!("📦 Processing block {}/{}: {}", progress, total_blocks, block_number);

        let block_set = [block_number];

        // Check if this block exists
        match check_blocks_exist(rpc_client, &block_set).await {
            Ok(true) => {
                debug!("Block {} exists, proceeding with PIE generation", block_number);

                // Process this block using the existing process_block_set function
                match process_block_set(args, &block_set).await {
                    Ok(output_path) => {
                        info!(
                            "✅ Successfully generated PIE for block {} ({}/{}) -> {}",
                            block_number, progress, total_blocks, output_path
                        );
                        processed_count += 1;
                    }
                    Err(e) => {
                        log::error!(
                            "❌ Failed to generate PIE for block {} ({}/{}): {}",
                            block_number,
                            progress,
                            total_blocks,
                            e
                        );

                        // Write error to the file for this block
                        let error_file = format!("{}/error_blocks_{}.txt", args.log_dir, block_number);

                        if let Err(write_err) = write_error_to_file(&error_file, &block_set, &e).await {
                            log::error!("Failed to write error file {}: {}", error_file, write_err);
                        }

                        failed_count += 1;
                    }
                }
            }
            Ok(false) => {
                warn!("Block {} does not exist yet, skipping", block_number);
                failed_count += 1;
            }
            Err(e) => {
                warn!("Error checking block {}: {}, skipping", block_number, e);
                failed_count += 1;
            }
        }

        // Progress update every 10 blocks or on the last block
        if progress % 10 == 0 || progress == total_blocks {
            info!(
                "📊 Progress: {}/{} blocks processed ({} successful, {} failed)",
                progress, total_blocks, processed_count, failed_count
            );
        }
    }

    info!("🎯 JSON mode processing completed!");
    info!("📈 Final results:");
    info!("  Total blocks: {}", total_blocks);
    info!("  Successfully processed: {}", processed_count);
    info!("  Failed: {}", failed_count);
    info!("  Success rate: {:.1}%", (processed_count as f64 / total_blocks as f64) * 100.0);

    Ok(())
}

/// Load blocks from the JSON file (supports both formats)
fn load_blocks_from_json(file_path: &str) -> Result<Vec<u64>, Box<dyn error::Error + Send + Sync>> {
    let file_content =
        fs::read_to_string(file_path).map_err(|e| format!("Failed to read JSON file {}: {}", file_path, e))?;

    // First, try to parse as the new error decoding format
    if let Ok(error_decoding_json) = serde_json::from_str::<ErrorDecodingJson>(&file_content) {
        if error_decoding_json.failing_blocks.is_empty() {
            return Err("JSON file contains no blocks to process".into());
        }

        info!(
            "📄 Loaded blocks from {} (error decoding format): {:?}",
            file_path,
            if error_decoding_json.failing_blocks.len() <= 10 {
                format!("{:?}", error_decoding_json.failing_blocks)
            } else {
                format!(
                    "{:?}... and {} more",
                    &error_decoding_json.failing_blocks[..10],
                    error_decoding_json.failing_blocks.len() - 10
                )
            }
        );

        info!(
            "📋 Error type: {} - {}",
            error_decoding_json.metadata.error_type, error_decoding_json.metadata.description
        );

        return Ok(error_decoding_json.failing_blocks);
    }

    // If that fails, try the original format
    let blocks_json: BlocksJson = serde_json::from_str(&file_content)
        .map_err(|e| format!("Failed to parse JSON file {} as either format: {}", file_path, e))?;

    if blocks_json.error_blocks.is_empty() {
        return Err("JSON file contains no blocks to process".into());
    }

    info!(
        "📄 Loaded blocks from {} (original format): {:?}",
        file_path,
        if blocks_json.error_blocks.len() <= 10 {
            format!("{:?}", blocks_json.error_blocks)
        } else {
            format!("{:?}... and {} more", &blocks_json.error_blocks[..10], blocks_json.error_blocks.len() - 10)
        }
    );

    Ok(blocks_json.error_blocks)
}

/// Check if all blocks in the set exist
async fn check_blocks_exist(
    rpc_client: &RpcClient,
    blocks: &[u64],
) -> Result<bool, Box<dyn error::Error + Send + Sync>> {
    for &block_num in blocks {
        match rpc_client.starknet_rpc().get_block_with_tx_hashes(BlockId::Number(block_num)).await {
            Ok(_) => {
                // Block exists, continue checking
                continue;
            }
            Err(e) => {
                // Check if it's a "block not found" error
                let error_str = format!("{:?}", e);
                return if error_str.contains("BlockNotFound") || error_str.contains("block not found") {
                    debug!("Block {} not found yet", block_num);
                    Ok(false)
                } else {
                    // Other error, propagate it
                    Err(e.into())
                };
            }
        }
    }
    Ok(true)
}

/// Process a set of 1 block and generate PIE (keeping the original signature)
async fn process_block_set(args: &Args, blocks: &[u64]) -> Result<String, ProcessError> {
    let output_filename = format!("cairo_pie_blocks_{}.zip", blocks[0]);

    let input = PieGenerationInput {
        rpc_url: args.rpc_url.clone(),
        blocks: blocks.to_vec(),
        chain_config: ChainConfig::new(
            &args.chain,
            &args.strk_fee_token_address,
            &args.eth_fee_token_address,
            args.is_l3,
        ),
        os_hints_config: OsHintsConfiguration::default_with_is_l3(args.is_l3),
        output_path: args.output_dir.clone(),
        layout: parse_layout(&args.layout)
            .map_err(|e| ProcessError::Panic(format!("Failed to parse layout: {}", e)))?,
    };

    debug!("Starting PIE generation for blocks {:?}", blocks);

    // Use tokio::task::spawn_blocking to handle potential panics in async context
    let result = tokio::task::spawn_blocking(move || {
        // This will run in a separate thread and catch panics
        std::panic::catch_unwind(|| {
            // We need to block on the async function here
            tokio::runtime::Handle::current().block_on(generate_pie(input))
        })
    })
    .await;

    match result {
        Ok(Ok(Ok(output))) => {
            info!("PIE generation completed for blocks {:?}", output.blocks_processed);
            Ok(output_filename)
        }
        Ok(Ok(Err(e))) => {
            log::error!("PIE generation failed for blocks {:?}: {}", blocks, e);
            Err(ProcessError::Regular(e))
        }
        Ok(Err(panic_payload)) => {
            let panic_msg = if let Some(s) = panic_payload.downcast_ref::<String>() {
                s.clone()
            } else if let Some(s) = panic_payload.downcast_ref::<&str>() {
                s.to_string()
            } else {
                format!("Unknown panic: {:?}", panic_payload)
            };

            let error_msg = format!("Panic during PIE generation: {}", panic_msg);
            log::error!("PIE generation panicked for blocks {:?}: {}", blocks, error_msg);
            Err(ProcessError::Panic(error_msg))
        }
        Err(join_err) => {
            let error_msg = format!("Task join error during PIE generation: {}", join_err);
            log::error!("PIE generation task failed for blocks {:?}: {}", blocks, error_msg);
            Err(ProcessError::Panic(error_msg))
        }
    }
}

/// Write error details to a file
async fn write_error_to_file(
    file_path: &str,
    blocks: &[u64],
    error: &ProcessError,
) -> Result<(), Box<dyn error::Error + Send + Sync>> {
    use chrono::Utc;

    let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
    let error_content = format!(
        "Error Report\n\
         ============\n\
         Timestamp: {}\n\
         Blocks: {:?}\n\
         Error: {}\n\
         Error Debug: {:?}\n\n",
        timestamp, blocks, error, error
    );

    fs::write(file_path, error_content)?;
    log::error!("Error details written to: {}", file_path);
    Ok(())
}

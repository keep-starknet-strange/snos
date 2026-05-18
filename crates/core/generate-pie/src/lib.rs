//! # Generate PIE - Starknet OS PIE Generation Library
//!
//! This library provides functionality to generate Cairo PIE (Program Input/Output) files
//! from Starknet blocks. It processes blocks from a Starknet RPC endpoint and generates
//! the necessary inputs for the Starknet OS (Operating System) to execute and produce
//! a Cairo PIE file.
//!
//! ## Features
//!
//! - **Block Processing**: Process multiple Starknet blocks in sequence
//! - **State Management**: Handle cached state and contract class management
//! - **RPC Integration**: Seamless integration with Starknet RPC endpoints
//! - **OS Execution**: Execute the Starknet OS to generate Cairo PIE files
//! - **Configurable**: Support for different chain configurations and OS hints
//! - **Error Handling**: Comprehensive error handling with detailed error types
//!
//! ## Architecture
//!
//! The library follows a modular architecture with the following key parts:
//!
//! - **Block Processor**: Handles individual block processing and transaction execution
//! - **State Management**: Manages cached state and contract class storage
//! - **RPC Utils**: Utilities for interacting with Starknet RPC endpoints
//! - **Context Builder**: Builds execution contexts for block processing
//! - **Commitment Utils**: Handles commitment calculations and formatting
//!
//! ## Usage
//!
//! ```rust
//! use generate_pie::{generate_pie, ChainConfig, OsHintsConfiguration, PieGenerationInput};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let input = PieGenerationInput {
//!         rpc_url: "https://your-starknet-node.com".to_string(),
//!         blocks: vec![12345, 12346],
//!         chain_config: ChainConfig::default(),
//!         os_hints_config: OsHintsConfiguration::default(),
//!         output_path: Some("output.pie".to_string()),
//!     };
//!
//!     let result = generate_pie(input).await?;
//!     println!("PIE generated successfully for blocks: {:?}", result.blocks_processed);
//!     Ok(())
//! }
//! ```
//!
//! ## Error Handling
//!
//! The library provides comprehensive error handling through the `PieGenerationError` enum,
//! which covers various failure scenarios, including block processing errors, RPC client
//! errors, OS execution errors, and configuration errors.
//!
//! ## Configuration
//!
//! The library supports various configuration options:
//!
//! - **Chain Configuration**: Chain ID, fee token addresses, L3 support
//! - **OS Hints Configuration**: Debug mode, output format, KZG DA support
//! - **Block Selection**: Specify which blocks to process
//! - **Output Options**: Configure output file paths and formats

// Standard library imports
use std::path::Path;
use std::sync::Arc;
// External crate imports
use anyhow::bail;
use cairo_vm::types::layout_name::LayoutName;
use futures::future::join_all;
use log::{info, warn};
use rpc_client::RpcClient;
use starknet_api::core::CompiledClassHash;
use starknet_os::{
    io::os_input::{OsChainInfo, OsHints, OsHintsConfig, StarknetOsInput},
    runner::run_os_stateless,
};
use tokio::sync::Semaphore;
// Local module imports
use crate::constants::{DEFAULT_MAX_PARALLEL_BLOCKS, MAX_EXECUTION_STEPS_WARNING_THRESHOLD};
use block_processor::collect_single_block_info;
use cached_state::generate_cached_state_input;
use error::PieGenerationError;
use types::{PieGenerationInput, PieGenerationResult};
use utils::{serialize_os_hints_to_json, sort_abi_entries_for_deprecated_class};

const MAX_PARALLEL_BLOCKS_ENV: &str = "SNOS_MAX_PARALLEL_BLOCKS";
const DUMP_OS_HINTS_ON_FAILURE_ENV: &str = "SNOS_DUMP_OS_HINTS_ON_FAILURE";

fn read_max_parallel_blocks(default: usize) -> usize {
    std::env::var(MAX_PARALLEL_BLOCKS_ENV)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn should_dump_os_hints_on_failure() -> bool {
    std::env::var(DUMP_OS_HINTS_ON_FAILURE_ENV)
        .ok()
        .map(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

fn os_hints_dump_path(output_path: Option<&str>, blocks: &[u64]) -> String {
    if let Some(output_path) = output_path {
        let output_path = Path::new(output_path);
        let stem = output_path.file_stem().and_then(|stem| stem.to_str()).unwrap_or("cairo_pie");
        return output_path.with_file_name(format!("{}.os_hints.json", stem)).to_string_lossy().into_owned();
    }

    let first_block = blocks.first().copied().unwrap_or_default();
    let last_block = blocks.last().copied().unwrap_or(first_block);
    format!("snos_os_hints_{}_{}.json", first_block, last_block)
}

fn log_os_hints_summary(os_hints: &OsHints) {
    for (index, block_input) in os_hints.os_input.os_block_inputs.iter().enumerate() {
        let cached_state_input = os_hints.os_input.cached_state_inputs.get(index);
        let cached_state_contracts = cached_state_input.map(|input| input.storage.len()).unwrap_or_default();
        let cached_state_keys = cached_state_input
            .map(|input| input.storage.values().map(std::collections::HashMap::len).sum::<usize>())
            .unwrap_or_default();
        let storage_commitment_fact_count = block_input
            .address_to_storage_commitment_info
            .values()
            .map(|commitment_info| commitment_info.commitment_facts.len())
            .sum::<usize>();

        info!(
            "OS input summary for block {}: txs={} storage_commitment_contracts={} storage_commitment_facts={} cached_state_contracts={} cached_state_keys={} declared_class_component_hashes={} migrated_classes={}",
            block_input.block_info.block_number.0,
            block_input.transactions.len(),
            block_input.address_to_storage_commitment_info.len(),
            storage_commitment_fact_count,
            cached_state_contracts,
            cached_state_keys,
            block_input.declared_class_hash_to_component_hashes.len(),
            block_input.class_hashes_to_migrate.len()
        );
    }
}

// ================================================================================================
// Module Declarations
// ================================================================================================

mod block_processor;
mod cached_state;
pub mod constants;
mod conversions;
mod state_update;
pub mod utils;

pub mod error;
pub mod types;

// ================================================================================================
// Public API
// ================================================================================================

/// Core function to generate PIE from blocks.
///
/// This function takes the input configuration and processes the specified blocks
/// to generate a Cairo PIE file. It handles all the complexity of block processing,
/// state management, and OS execution.
///
/// # Arguments
///
/// * `input` - The configuration and parameters for PIE generation
///
/// # Returns
///
/// Returns a `PieGenerationResult` containing the generated PIE and metadata,
/// or an error if the generation process fails.
///
/// # Errors
///
/// This function can return various errors including
/// - `PieGenerationError::InvalidConfig` if the input configuration is invalid
/// - `PieGenerationError::RpcClient` if there are issues with the RPC connection
/// - `PieGenerationError::BlockProcessing` if block processing fails
/// - `PieGenerationError::StateProcessing` if state processing fails
/// - `PieGenerationError::OsExecution` if OS execution fails
///
/// # Examples
///
/// ```rust
/// use generate_pie::{generate_pie, PieGenerationInput, ChainConfig, OsHintsConfiguration};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let input = PieGenerationInput {
///         rpc_url: "https://your-starknet-node.com".to_string(),
///         blocks: vec![12345],
///         chain_config: ChainConfig::default(),
///         os_hints_config: OsHintsConfiguration::default(),
///         output_path: Some("output.pie".to_string()),
///     };
///
///     let result = generate_pie(input).await?;
///     println!("PIE generated successfully!");
///     Ok(())
/// }
/// ```
pub async fn generate_pie(input: PieGenerationInput) -> Result<PieGenerationResult, PieGenerationError> {
    info!("Starting PIE generation for {} blocks: {:?}", input.blocks.len(), input.blocks);

    // Validate input configuration
    input.validate()?;
    info!("Input configuration validated successfully");

    // Initialize RPC client
    let rpc_client = RpcClient::try_new(&input.rpc_url)
        .map_err(|e| PieGenerationError::RpcClient(format!("Failed to initialize RPC client: {:?}", e)))?;
    info!("RPC client initialized for {}", input.rpc_url);

    // Create semaphore to limit parallel execution to available CPU cores
    let default_max_parallel_blocks =
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(DEFAULT_MAX_PARALLEL_BLOCKS);
    let max_parallel_blocks = read_max_parallel_blocks(default_max_parallel_blocks);
    let semaphore = Arc::new(Semaphore::new(max_parallel_blocks));
    info!("Processing blocks with max parallelism: {} (CPU cores)", max_parallel_blocks);

    // Process all blocks in parallel using tokio::spawn for true parallelism
    info!("Starting parallel processing of {} blocks", input.blocks.len());
    let block_tasks = input.blocks.iter().enumerate().map(|(index, block_number)| {
        let block_number = *block_number;
        let rpc_client = rpc_client.clone();
        let is_l3 = input.chain_config.is_l3;
        let strk_fee_token_address = input.chain_config.strk_fee_token_address;
        let eth_fee_token_address = input.chain_config.eth_fee_token_address;
        let versioned_constants = input.versioned_constants.clone();
        let total_blocks = input.blocks.len();
        let sem = semaphore.clone();

        tokio::spawn(async move {
            // Acquire semaphore permit to limit concurrent execution
            let _permit = sem.acquire().await.expect("Failed to acquire semaphore permit");
            info!("=== Processing block {} ({}/{}) ===", block_number, index + 1, total_blocks);

            // Collect block information
            info!("Starting to collect block info for block {}", block_number);
            let block_info = collect_single_block_info(
                block_number,
                is_l3,
                &strk_fee_token_address,
                &eth_fee_token_address,
                versioned_constants,
                rpc_client.clone(),
            )
            .await
            .map_err(|e| PieGenerationError::BlockProcessing { block_number, source: Box::new(e) })?;

            info!("Block info collection completed for block {}", block_number);
            info!(
                "Block {}, accessed classes={}, accessed addresses={}",
                block_number,
                block_info.accessed_classes.len(),
                block_info.accessed_addresses.len()
            );

            // Generate cached state input (migrated classes use v1 hash since cached state is previous block)
            info!("Generating cached state input for block {}", block_number);
            let cached_state_input = generate_cached_state_input(
                &rpc_client,
                &block_number,
                &block_info.accessed_addresses,
                &block_info.accessed_classes,
                &block_info.accessed_keys_by_address,
                &block_info.migrated_class_hashes(),
            )
            .await
            .map_err(|e| {
                PieGenerationError::StateProcessing(format!(
                    "Failed to generate cached state input for block {}: {:?}",
                    block_number, e
                ))
            })?;

            info!("Cached state input generated successfully for block {}", block_number);

            Ok::<_, PieGenerationError>((
                block_info.os_block_input,
                block_info.compiled_classes,
                block_info.deprecated_compiled_classes,
                cached_state_input,
            ))
            // Permit is automatically released when _permit is dropped
        })
    });

    // Wait for all block processing tasks to complete
    let results = join_all(block_tasks).await;

    // Collect and merge results from all blocks
    let mut os_block_inputs = Vec::new();
    let mut cached_state_inputs = Vec::new();
    let mut compiled_classes = std::collections::BTreeMap::new();
    let mut deprecated_compiled_classes = std::collections::BTreeMap::new();

    for result in results {
        // First unwrap the JoinHandle, then unwrap the inner Result
        let (block_input, block_compiled_classes, block_deprecated_compiled_classes, mut cached_state_input) =
            result.map_err(|e| PieGenerationError::RpcClient(format!("Task join error: {:?}", e)))??;

        // Add block input to our collection
        os_block_inputs.push(block_input);

        // Merge compiled classes (these are shared across blocks)
        compiled_classes.extend(block_compiled_classes);
        deprecated_compiled_classes.extend(block_deprecated_compiled_classes);

        // Remove deprecated compiled classes from cached state input
        cached_state_input
            .class_hash_to_compiled_class_hash
            .retain(|class_hash, _| !deprecated_compiled_classes.contains_key(&CompiledClassHash(class_hash.0)));

        cached_state_inputs.push(cached_state_input);
    }

    info!("All {} blocks processed successfully in parallel", input.blocks.len());

    // Sort ABI entries for all deprecated compiled classes
    info!("Sorting ABI entries for deprecated compiled classes");
    for (class_hash, compiled_class) in deprecated_compiled_classes.iter_mut() {
        if let Err(e) = sort_abi_entries_for_deprecated_class(compiled_class) {
            warn!("Failed to sort ABI entries for class {:?}: {}", class_hash, e);
        }
    }

    info!("=== Finalizing multi-block processing ===");
    info!(
        "OS inputs prepared with {} block inputs and {} cached state inputs",
        os_block_inputs.len(),
        cached_state_inputs.len()
    );

    // Build OS hints configuration
    info!("Building OS hints configuration for multi-block processing");
    let os_hints = OsHints {
        os_hints_config: OsHintsConfig {
            debug_mode: input.os_hints_config.debug_mode,
            full_output: input.os_hints_config.full_output,
            use_kzg_da: input.os_hints_config.use_kzg_da,
            chain_info: OsChainInfo {
                chain_id: input.chain_config.chain_id,
                strk_fee_token_address: input.chain_config.strk_fee_token_address,
            },
            public_keys: input.public_keys.clone(),
            rng_seed_salt: None,
        },
        os_input: StarknetOsInput {
            os_block_inputs,
            cached_state_inputs,
            deprecated_compiled_classes,
            compiled_classes,
        },
    };
    info!("OS hints configuration built successfully for {} blocks", input.blocks.len());
    log_os_hints_summary(&os_hints);
    let os_hints_dump_path = if should_dump_os_hints_on_failure() {
        let dump_path = os_hints_dump_path(input.output_path.as_deref(), &input.blocks);
        match serialize_os_hints_to_json(&os_hints, &dump_path) {
            Ok(()) => info!("Pre-serialized OS hints snapshot to {}", dump_path),
            Err(dump_error) => warn!("Failed to pre-serialize OS hints snapshot to {}: {}", dump_path, dump_error),
        }
        Some(dump_path)
    } else {
        None
    };

    // Execute the Starknet OS
    info!("Starting OS execution for multi-block processing");
    let output = match run_os_stateless(input.layout, os_hints) {
        Ok(output) => output,
        Err(e) => {
            warn!("OS execution failed for blocks {:?}: {:?}", input.blocks, e);
            if let Some(dump_path) = os_hints_dump_path.as_ref() {
                warn!("OS hints snapshot is available at {}", dump_path);
            }
            return Err(PieGenerationError::OsExecution(format!("OS execution failed: {:?}", e)));
        }
    };
    info!("Multi-block output generated successfully!");

    // Check execution steps and warn if exceeding threshold
    let steps_count = output.cairo_pie.execution_resources.n_steps;
    if steps_count > MAX_EXECUTION_STEPS_WARNING_THRESHOLD {
        warn!(
            "CairoPIE execution steps ({}) exceeds threshold ({})",
            steps_count, MAX_EXECUTION_STEPS_WARNING_THRESHOLD
        );
    }

    // Validate the generated PIE
    info!("Validating generated Cairo PIE");
    output
        .cairo_pie
        .run_validity_checks()
        .map_err(|e| PieGenerationError::OsExecution(format!("PIE validation failed: {:?}", e)))?;
    info!("Cairo PIE validation completed successfully");

    // Save to file if a path is specified
    if let Some(output_path) = &input.output_path {
        info!("Writing PIE to file: {}", output_path);
        output.cairo_pie.write_zip_file(Path::new(output_path), true).map_err(|e| {
            PieGenerationError::Io(std::io::Error::other(format!(
                "Failed to write PIE to file {}: {:?}",
                output_path, e
            )))
        })?;
        info!("PIE written to file successfully: {}", output_path);
    }

    info!("PIE generation completed successfully for blocks {:?}", input.blocks);

    Ok(PieGenerationResult { output, blocks_processed: input.blocks.clone(), output_path: input.output_path.clone() })
}

pub fn parse_layout(layout: &str) -> anyhow::Result<LayoutName> {
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

pub fn parse_public_key(key: &str) -> anyhow::Result<starknet_types_core::felt::Felt> {
    let trimmed = key.trim();
    Ok(starknet_types_core::felt::Felt::from_hex_unchecked(trimmed))
}

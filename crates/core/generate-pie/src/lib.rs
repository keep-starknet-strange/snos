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

// External crate imports
use log::{info, warn};
use rpc_client::RpcClient;
use starknet_api::core::CompiledClassHash;
use starknet_os::{
    io::os_input::{OsChainInfo, OsHints, OsHintsConfig, StarknetOsInput},
    runner::run_os_stateless,
};

// Local module imports
use block_processor::collect_single_block_info;
use cached_state::generate_cached_state_input;
use error::PieGenerationError;
use types::{PieGenerationInput, PieGenerationResult};
use utils::sort_abi_entries_for_deprecated_class;

// ================================================================================================
// Module Declarations
// ================================================================================================

mod block_processor;
mod cached_state;
pub mod constants;
mod conversions;
mod state_update;
mod utils;

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

    let mut os_block_inputs = Vec::new();
    let mut cached_state_inputs = Vec::new();
    let mut compiled_classes = std::collections::BTreeMap::new();
    let mut deprecated_compiled_classes = std::collections::BTreeMap::new();

    // Process each block
    for (index, block_number) in input.blocks.iter().enumerate() {
        info!("=== Processing block {} ({}/{}) ===", block_number, index + 1, input.blocks.len());

        // Collect block information
        info!("Starting to collect block info for block {}", block_number);
        let block_info_result = collect_single_block_info(
            *block_number,
            input.chain_config.is_l3,
            &input.strk_fee_token_address,
            &input.eth_fee_token_address,
            rpc_client.clone(),
        )
        .await
        .map_err(|e| PieGenerationError::BlockProcessing { block_number: *block_number, source: Box::new(e) })?;

        let (
            block_input,
            block_compiled_classes,
            block_deprecated_compiled_classes,
            block_accessed_addresses,
            block_accessed_classes,
            block_accessed_keys_by_address,
        ) = (
            block_info_result.os_block_input,
            block_info_result.compiled_classes,
            block_info_result.deprecated_compiled_classes,
            block_info_result.accessed_addresses,
            block_info_result.accessed_classes,
            block_info_result.accessed_keys_by_address,
        );

        info!("Block info collection completed for block {}", block_number);
        info!(
            "Block {}, accessed classes={}, accessed addresses={}",
            block_number,
            block_accessed_classes.len(),
            block_accessed_addresses.len()
        );

        // Add block input to our collection and merge compiled classes (these are shared across blocks)
        os_block_inputs.push(block_input);
        compiled_classes.extend(block_compiled_classes);
        deprecated_compiled_classes.extend(block_deprecated_compiled_classes);

        // Generate cached state input
        info!("Generating cached state input for block {}", block_number);
        let mut cached_state_input = generate_cached_state_input(
            &rpc_client,
            &block_number,
            &block_accessed_addresses,
            &block_accessed_classes,
            &block_accessed_keys_by_address,
        )
        .await
        .map_err(|e| {
            PieGenerationError::StateProcessing(format!(
                "Failed to generate cached state input for block {}: {:?}",
                block_number, e
            ))
        })?;
        // Remove deprecated compiled classes from cached state input
        cached_state_input
            .class_hash_to_compiled_class_hash
            .retain(|class_hash, _| !deprecated_compiled_classes.contains_key(&CompiledClassHash(class_hash.0)));

        info!("Cached state input generated successfully for block {}", block_number);

        cached_state_inputs.push(cached_state_input);
        info!("Block {} processed successfully", block_number);
    }

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
            public_keys: None,
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

    // Execute the Starknet OS
    info!("Starting OS execution for multi-block processing");
    let output = run_os_stateless(input.layout, os_hints)
        .map_err(|e| PieGenerationError::OsExecution(format!("OS execution failed: {:?}", e)))?;
    info!("Multi-block output generated successfully!");

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

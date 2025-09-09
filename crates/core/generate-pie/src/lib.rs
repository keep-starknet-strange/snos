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

use cairo_vm::types::layout_name::LayoutName;
use rpc_client::state_reader::AsyncRpcStateReader;
use rpc_client::RpcClient;
use starknet::core::types::BlockId;
use starknet_api::core::{ChainId, ContractAddress};
use starknet_os::io::os_output::StarknetOsRunnerOutput;
use starknet_os::{
    io::os_input::{OsChainInfo, OsHints, OsHintsConfig, StarknetOsInput},
    runner::run_os_stateless,
};
use starknet_types_core::felt::Felt;
use std::path::Path;

/// Default timeout for RPC requests in seconds.
pub const DEFAULT_RPC_TIMEOUT_SECONDS: u64 = 30;

/// Maximum number of blocks that can be processed in a single PIE generation.
pub const MAX_BLOCKS_PER_PIE: usize = 100;

/// Default layout name for Cairo execution.
pub const DEFAULT_CAIRO_LAYOUT: &str = "all_cairo";

/// Default Sepolia STRK fee token address.
pub const DEFAULT_SEPOLIA_STRK_FEE_TOKEN: &str = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";

mod api_to_blockifier_conversion;
mod block_processor;
mod cached_state;
mod commitment_utils;
mod context_builder;
mod error;
mod rpc_utils;
mod state_processing;
mod state_update;

use block_processor::collect_single_block_info;
use cached_state::generate_cached_state_input;

/// Configuration for chain-specific settings.
///
/// This struct contains all the chain-specific configuration needed for PIE generation,
/// including the chain ID, fee token addresses, and whether the chain is an L3.
///
/// # Examples
///
/// ```rust
/// use generate_pie::ChainConfig;
/// use starknet_api::core::ChainId;
///
/// // Use default Sepolia configuration
/// let config = ChainConfig::default();
///
/// // Create custom configuration
/// let custom_config = ChainConfig {
///     chain_id: ChainId::Mainnet,
///     strk_fee_token_address: ContractAddress::try_from(Felt::from_hex_unchecked("0x123...")).unwrap(),
///     is_l3: true,
/// };
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct ChainConfig {
    /// The chain ID for the target Starknet network.
    pub chain_id: ChainId,
    /// The address of the STRK fee token contract.
    pub strk_fee_token_address: ContractAddress,
    /// Whether this is an L3 chain (true) or L2 chain (false).
    pub is_l3: bool,
}

impl Default for ChainConfig {
    /// Creates a default configuration for Sepolia testnet.
    ///
    /// # Returns
    ///
    /// A `ChainConfig` instance with Sepolia defaults:
    /// - Chain ID: Sepolia
    /// - STRK fee token: Sepolia STRK token address
    /// - L3: false (L2 chain)
    fn default() -> Self {
        Self {
            chain_id: ChainId::Sepolia,
            strk_fee_token_address: ContractAddress::try_from(Felt::from_hex_unchecked(DEFAULT_SEPOLIA_STRK_FEE_TOKEN))
                .expect("Valid Sepolia STRK fee token address"),
            is_l3: false,
        }
    }
}

impl ChainConfig {
    /// Validates the chain configuration.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the configuration is valid, or an error if validation fails.
    ///
    /// # Errors
    ///
    /// Returns a `PieGenerationError::InvalidConfig` if the configuration is invalid.
    pub fn validate(&self) -> Result<(), PieGenerationError> {
        // Validate that the STRK fee token address is not zero
        if self.strk_fee_token_address == ContractAddress::default() {
            return Err(PieGenerationError::InvalidConfig("STRK fee token address cannot be zero".to_string()));
        }

        Ok(())
    }
}

/// Configuration for OS hints and execution parameters.
///
/// This struct controls various aspects of the Starknet OS execution, including
/// debug mode, output verbosity, and data availability mode.
///
/// # Examples
///
/// ```rust
/// use generate_pie::OsHintsConfiguration;
///
/// // Use default configuration
/// let config = OsHintsConfiguration::default();
///
/// // Create custom configuration for debugging
/// let debug_config = OsHintsConfiguration {
///     debug_mode: true,
///     full_output: true,
///     use_kzg_da: false,
/// };
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct OsHintsConfiguration {
    /// Whether to enable debug mode for detailed logging and output.
    pub debug_mode: bool,
    /// Whether to generate full output including intermediate states.
    pub full_output: bool,
    /// Whether to use KZG (Kate-Zaverucha-Goldberg) data availability mode.
    pub use_kzg_da: bool,
}

impl Default for OsHintsConfiguration {
    /// Creates a default configuration with sensible defaults.
    ///
    /// # Returns
    ///
    /// A `OsHintsConfiguration` instance with:
    /// - Debug mode: enabled (for better error reporting)
    /// - Full output: disabled (for performance)
    /// - KZG DA: enabled (modern data availability)
    fn default() -> Self {
        Self { debug_mode: true, full_output: false, use_kzg_da: true }
    }
}

impl OsHintsConfiguration {
    /// Validates the OS hints configuration.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the configuration is valid, or an error if validation fails.
    ///
    /// # Errors
    ///
    /// Returns a `PieGenerationError::InvalidConfig` if the configuration is invalid.
    pub fn validate(&self) -> Result<(), PieGenerationError> {
        // Currently no validation needed, but this provides a place for future validation
        Ok(())
    }
}

/// Input configuration for PIE generation.
///
/// This struct contains all the necessary configuration and parameters needed to
/// generate a Cairo PIE file from Starknet blocks.
///
/// # Examples
///
/// ```rust
/// use generate_pie::{PieGenerationInput, ChainConfig, OsHintsConfiguration};
///
/// let input = PieGenerationInput {
///     rpc_url: "https://your-starknet-node.com".to_string(),
///     blocks: vec![12345, 12346],
///     chain_config: ChainConfig::default(),
///     os_hints_config: OsHintsConfiguration::default(),
///     output_path: Some("output.pie".to_string()),
/// };
/// ```
#[derive(Debug, Clone)]
pub struct PieGenerationInput {
    /// The RPC URL of the Starknet node to connect to.
    pub rpc_url: String,
    /// The list of block numbers to process for PIE generation.
    pub blocks: Vec<u64>,
    /// Chain-specific configuration settings.
    pub chain_config: ChainConfig,
    /// OS hints and execution configuration.
    pub os_hints_config: OsHintsConfiguration,
    /// Optional output file path for the generated PIE file.
    pub output_path: Option<String>,
}

impl PieGenerationInput {
    /// Validates the PIE generation input configuration.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the input is valid, or an error if validation fails.
    ///
    /// # Errors
    ///
    /// Returns a `PieGenerationError::InvalidConfig` if the input is invalid.
    pub fn validate(&self) -> Result<(), PieGenerationError> {
        // Validate RPC URL
        if self.rpc_url.trim().is_empty() {
            return Err(PieGenerationError::InvalidConfig("RPC URL cannot be empty".to_string()));
        }

        // Validate blocks
        if self.blocks.is_empty() {
            return Err(PieGenerationError::InvalidConfig("At least one block must be specified".to_string()));
        }

        // Validate maximum number of blocks
        if self.blocks.len() > MAX_BLOCKS_PER_PIE {
            return Err(PieGenerationError::InvalidConfig(format!(
                "Too many blocks specified: {} (maximum: {})",
                self.blocks.len(),
                MAX_BLOCKS_PER_PIE
            )));
        }

        // Validate that blocks are in ascending order
        let mut sorted_blocks = self.blocks.clone();
        sorted_blocks.sort();
        if sorted_blocks != self.blocks {
            return Err(PieGenerationError::InvalidConfig("Blocks must be specified in ascending order".to_string()));
        }

        // Validate chain configuration
        self.chain_config.validate()?;

        // Validate OS hints configuration
        self.os_hints_config.validate()?;

        Ok(())
    }
}

/// Result containing the generated PIE and metadata.
///
/// This struct contains the output of the PIE generation process, including
/// the generated Cairo PIE, information about processed blocks, and the output path.
pub struct PieGenerationResult {
    /// The output from the Starknet OS execution containing the Cairo PIE.
    pub output: StarknetOsRunnerOutput,
    /// The list of block numbers that were successfully processed.
    pub blocks_processed: Vec<u64>,
    /// The output file path where the PIE was saved (if specified).
    pub output_path: Option<String>,
}

/// Main error type for PIE generation.
///
/// This enum represents all possible errors that can occur during the PIE generation
/// process, including block processing errors, RPC client errors, OS execution errors,
/// and configuration errors.
#[derive(thiserror::Error, Debug)]
pub enum PieGenerationError {
    /// Block processing failed for a specific block.
    #[error("Block processing failed for block {block_number}: {source}")]
    BlockProcessing {
        /// The block number that failed to process.
        block_number: u64,
        /// The underlying error that caused the failure.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// RPC client-related error.
    #[error("RPC client error: {0}")]
    RpcClient(String),

    /// OS execution related error.
    #[error("OS execution error: {0}")]
    OsExecution(String),

    /// I/O error during file operations.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Invalid configuration error.
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// State processing error.
    #[error("State processing error: {0}")]
    StateProcessing(String),

    /// Contract class processing error.
    #[error("Contract class processing error: {0}")]
    ContractClassProcessing(String),
}

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
    log::info!("Starting PIE generation for {} blocks: {:?}", input.blocks.len(), input.blocks);

    // Validate input configuration
    input.validate()?;
    log::debug!("Input configuration validated successfully");

    // Initialize RPC client
    let rpc_client = RpcClient::try_new(&input.rpc_url)
        .map_err(|e| PieGenerationError::RpcClient(format!("Failed to initialize RPC client: {:?}", e)))?;
    log::info!("RPC client initialized for {}", input.rpc_url);

    let mut os_block_inputs = Vec::new();
    let mut cached_state_inputs = Vec::new();
    let mut all_compiled_classes = std::collections::BTreeMap::new();
    let mut all_deprecated_compiled_classes = std::collections::BTreeMap::new();

    // Process each block
    for (index, block_number) in input.blocks.iter().enumerate() {
        log::info!("=== Processing block {} ({}/{}) ===", block_number, index + 1, input.blocks.len());

        // Create a state reader for the current block
        let _blockifier_state_reader = AsyncRpcStateReader::new(rpc_client.clone(), BlockId::Number(*block_number));
        log::debug!("State reader created for block {}", block_number);

        // Collect block information
        log::info!("Starting to collect block info for block {}", block_number);
        let block_info_result = collect_single_block_info(*block_number, input.chain_config.is_l3, rpc_client.clone())
            .await
            .map_err(|e| PieGenerationError::BlockProcessing { block_number: *block_number, source: Box::new(e) })?;

        let (
            block_input,
            compiled_classes,
            deprecated_compiled_classes,
            accessed_addresses,
            accessed_classes,
            accessed_keys_by_address,
            _previous_block_id,
        ) = (
            block_info_result.os_block_input,
            block_info_result.compiled_classes,
            block_info_result.deprecated_compiled_classes,
            block_info_result.accessed_addresses,
            block_info_result.accessed_classes,
            block_info_result.accessed_keys_by_address,
            block_info_result.previous_block_id,
        );
        log::info!("Block info collection completed for block {}", block_number);

        // Add block input to our collection
        os_block_inputs.push(block_input);

        // Merge compiled classes (these are shared across blocks)
        all_compiled_classes.extend(compiled_classes);
        all_deprecated_compiled_classes.extend(deprecated_compiled_classes);

        // Generate cached state input
        log::info!("Generating cached state input for block {}", block_number);
        let cached_state_input = generate_cached_state_input(
            &rpc_client,
            BlockId::Number(block_number - 1),
            &accessed_addresses,
            &accessed_classes,
            &accessed_keys_by_address,
        )
        .await
        .map_err(|e| {
            PieGenerationError::StateProcessing(format!(
                "Failed to generate cached state input for block {}: {:?}",
                block_number, e
            ))
        })?;

        cached_state_inputs.push(cached_state_input);
        log::info!("Block {} processed successfully", block_number);
    }

    log::info!("=== Finalizing multi-block processing ===");
    log::info!(
        "OS inputs prepared with {} block inputs and {} cached state inputs",
        os_block_inputs.len(),
        cached_state_inputs.len()
    );

    // Build OS hints configuration
    log::info!("Building OS hints configuration for multi-block processing");
    let os_hints = OsHints {
        os_hints_config: OsHintsConfig {
            debug_mode: input.os_hints_config.debug_mode,
            full_output: input.os_hints_config.full_output,
            use_kzg_da: input.os_hints_config.use_kzg_da,
            chain_info: OsChainInfo {
                chain_id: input.chain_config.chain_id,
                strk_fee_token_address: input.chain_config.strk_fee_token_address,
            },
        },
        os_input: StarknetOsInput {
            os_block_inputs,
            cached_state_inputs,
            deprecated_compiled_classes: all_deprecated_compiled_classes,
            compiled_classes: all_compiled_classes,
        },
    };
    log::info!("OS hints configuration built successfully for {} blocks", input.blocks.len());

    // Execute the Starknet OS
    log::info!("Starting OS execution for multi-block processing");
    log::info!("Using layout: {:?}", LayoutName::all_cairo);
    let output = run_os_stateless(LayoutName::all_cairo, os_hints)
        .map_err(|e| PieGenerationError::OsExecution(format!("OS execution failed: {:?}", e)))?;
    log::info!("Multi-block output generated successfully!");

    // Validate the generated PIE
    log::info!("Validating generated Cairo PIE");
    output
        .cairo_pie
        .run_validity_checks()
        .map_err(|e| PieGenerationError::OsExecution(format!("PIE validation failed: {:?}", e)))?;
    log::info!("Cairo PIE validation completed successfully");

    // Save to file if a path is specified
    if let Some(output_path) = &input.output_path {
        log::info!("Writing PIE to file: {}", output_path);
        output.cairo_pie.write_zip_file(Path::new(output_path), true).map_err(|e| {
            PieGenerationError::Io(std::io::Error::other(format!(
                "Failed to write PIE to file {}: {:?}",
                output_path, e
            )))
        })?;
        log::info!("PIE written to file successfully: {}", output_path);
    }

    log::info!("PIE generation completed successfully for blocks {:?}", input.blocks);

    Ok(PieGenerationResult { output, blocks_processed: input.blocks.clone(), output_path: input.output_path.clone() })
}

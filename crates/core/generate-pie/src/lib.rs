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

/// Configuration for chain-specific settings
#[derive(Debug, Clone)]
pub struct ChainConfig {
    pub chain_id: ChainId,
    pub strk_fee_token_address: ContractAddress,
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            chain_id: ChainId::Sepolia,
            strk_fee_token_address: ContractAddress::try_from(Felt::from_hex_unchecked(
                "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
            ))
            .expect("Valid contract address"),
        }
    }
}

/// Configuration for OS hints
#[derive(Debug, Clone)]
pub struct OsHintsConfiguration {
    pub debug_mode: bool,
    pub full_output: bool,
    pub use_kzg_da: bool,
}

impl Default for OsHintsConfiguration {
    fn default() -> Self {
        Self { debug_mode: true, full_output: false, use_kzg_da: true }
    }
}

/// Input configuration for PIE generation
#[derive(Debug, Clone)]
pub struct PieGenerationInput {
    pub rpc_url: String,
    pub blocks: Vec<u64>,
    pub chain_config: ChainConfig,
    pub os_hints_config: OsHintsConfiguration,
    pub output_path: Option<String>,
}

/// Result containing the generated PIE and metadata
pub struct PieGenerationResult {
    pub output: StarknetOsRunnerOutput,
    pub blocks_processed: Vec<u64>,
    pub output_path: Option<String>,
}

/// Main error type for PIE generation
#[derive(thiserror::Error, Debug)]
pub enum PieGenerationError {
    #[error("Block processing failed for block {block_number}: {source}")]
    BlockProcessing {
        block_number: u64,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("RPC client error: {0}")]
    RpcClient(String),

    #[error("OS execution error: {0}")]
    OsExecution(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

/// Core function to generate PIE from blocks
///
/// This function takes the input configuration and processes the specified blocks
/// to generate a Cairo PIE file. It handles all the complexity of block processing,
/// state management, and OS execution.
pub async fn generate_pie(input: PieGenerationInput) -> Result<PieGenerationResult, PieGenerationError> {
    log::info!("Starting PIE generation for {} blocks: {:?}", input.blocks.len(), input.blocks);

    // Initialize RPC client
    let rpc_client = RpcClient::new(&input.rpc_url);
    log::info!("RPC client initialized for {}", input.rpc_url);

    let mut os_block_inputs = Vec::new();
    let mut cached_state_inputs = Vec::new();
    let mut all_compiled_classes = std::collections::BTreeMap::new();
    let mut all_deprecated_compiled_classes = std::collections::BTreeMap::new();

    // Process each block
    for (index, block_number) in input.blocks.iter().enumerate() {
        log::info!("=== Processing block {} ({}/{}) ===", block_number, index + 1, input.blocks.len());

        let _blockifier_state_reader = AsyncRpcStateReader::new(rpc_client.clone(), BlockId::Number(*block_number));
        log::info!("State reader created for block {}", block_number);

        log::info!("Starting to collect block info for block {}", block_number);
        let (
            block_input,
            compiled_classes,
            deprecated_compiled_classes,
            accessed_addresses,
            accessed_classes,
            accessed_keys_by_address,
            _previous_block_id,
        ) = collect_single_block_info(*block_number, rpc_client.clone()).await;
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
        .map_err(|e| PieGenerationError::BlockProcessing {
            block_number: *block_number,
            source: Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("{:?}", e))),
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

    log::info!("Starting OS execution for multi-block processing");
    log::info!("Using layout: {:?}", LayoutName::all_cairo);
    let output = run_os_stateless(LayoutName::all_cairo, os_hints)
        .map_err(|e| PieGenerationError::OsExecution(format!("{:?}", e)))?;
    log::info!("Multi-block output generated successfully!");

    // Validate the PIE
    let _ = output.cairo_pie.run_validity_checks();
    log::info!("Cairo pie validation done!!");

    // Save to file if path is specified
    if let Some(output_path) = &input.output_path {
        log::info!("Writing PIE to file: {}", output_path);
        let _ = output.cairo_pie.write_zip_file(Path::new(output_path), true);
    }

    log::info!("PIE generation completed successfully for blocks {:?}", input.blocks);

    Ok(PieGenerationResult { output, blocks_processed: input.blocks.clone(), output_path: input.output_path.clone() })
}

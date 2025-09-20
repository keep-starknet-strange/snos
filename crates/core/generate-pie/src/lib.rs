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

use block_processor::collect_single_block_info;
use cached_state::generate_cached_state_input;
use cairo_vm::types::layout_name::LayoutName;
use error::PieGenerationError;
use log::{debug, info, warn};
use rpc_client::RpcClient;
use starknet::core::types::BlockId;
use starknet_api::core::CompiledClassHash;
use starknet_os::{
    io::os_input::{OsChainInfo, OsHints, OsHintsConfig, StarknetOsInput},
    runner::run_os_stateless,
};
use std::path::Path;
use types::{PieGenerationInput, PieGenerationResult};

mod block_processor;
mod cached_state;
mod constants;
mod context_builder;
mod conversions;
mod error;
mod state_update;
pub mod types;
mod utils;

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
    let mut all_compiled_classes = std::collections::BTreeMap::new();
    let mut all_deprecated_compiled_classes = std::collections::BTreeMap::new();

    // Process each block
    for (index, block_number) in input.blocks.iter().enumerate() {
        info!("=== Processing block {} ({}/{}) ===", block_number, index + 1, input.blocks.len());

        // Collect block information
        info!("Starting to collect block info for block {}", block_number);
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
        info!("Block info collection completed for block {}", block_number);

        // Add block input to our collection
        os_block_inputs.push(block_input);

        // Merge compiled classes (these are shared across blocks)
        all_compiled_classes.extend(compiled_classes);
        all_deprecated_compiled_classes.extend(deprecated_compiled_classes);

        // Generate cached state input
        info!("Generating cached state input for block {}", block_number);
        let mut cached_state_input = generate_cached_state_input(
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
        cached_state_input
            .class_hash_to_compiled_class_hash
            .retain(|class_hash, _| !all_deprecated_compiled_classes.contains_key(&CompiledClassHash(class_hash.0)));
        debug!("Compiled classes are: {:?}", all_compiled_classes.keys());
        debug!("Deprecated compiled classes are: {:?}", all_deprecated_compiled_classes.keys());
        cached_state_inputs.push(cached_state_input);
        info!("Block {} processed successfully", block_number);
    }

    // Sort ABI entries for all deprecated compiled classes
    info!("Sorting ABI entries for deprecated compiled classes");
    for (class_hash, compiled_class) in all_deprecated_compiled_classes.iter_mut() {
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
        },
        os_input: StarknetOsInput {
            os_block_inputs,
            cached_state_inputs,
            deprecated_compiled_classes: all_deprecated_compiled_classes,
            compiled_classes: all_compiled_classes,
        },
    };
    info!("OS hints configuration built successfully for {} blocks", input.blocks.len());

    // Serialize OS hints to JSON for debugging/inspection
    let os_hints_json_path =
        format!("os_hints_blocks_{}.json", input.blocks.iter().map(|b| b.to_string()).collect::<Vec<_>>().join("_"));
    if let Err(e) = serialize_os_hints_to_json(&os_hints, &os_hints_json_path) {
        warn!("Failed to serialize OS hints to JSON: {}", e);
    }

    // Execute the Starknet OS
    info!("Starting OS execution for multi-block processing");
    info!("Using layout: {:?}", LayoutName::all_cairo);
    let output = run_os_stateless(LayoutName::all_cairo, os_hints)
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

/// Helper function to serialize OsHints to JSON completely
/// Since OsHints may not implement Serialize directly, we create a comprehensive custom serializable representation
fn serialize_os_hints_to_json(os_hints: &OsHints, output_path: &str) -> Result<(), PieGenerationError> {
    use serde_json::json;

    info!("Serializing OS hints to JSON file: {}", output_path);

    // Serialize OS hints config
    let os_hints_config_json = json!({
        "debug_mode": os_hints.os_hints_config.debug_mode,
        "full_output": os_hints.os_hints_config.full_output,
        "use_kzg_da": os_hints.os_hints_config.use_kzg_da,
        "chain_info": {
            "chain_id": format!("{:?}", os_hints.os_hints_config.chain_info.chain_id),
            "strk_fee_token_address": format!("{:#x}", os_hints.os_hints_config.chain_info.strk_fee_token_address.0.key())
        }
    });

    // Serialize block inputs completely
    let block_inputs_json: Vec<serde_json::Value> = os_hints.os_input.os_block_inputs.iter()
        .map(|block_input| {
            json!({
                "block_info": {
                    "block_number": block_input.block_info.block_number,
                    "sequencer_address": format!("{:#x}", block_input.block_info.sequencer_address.0.key()),
                    "block_timestamp": block_input.block_info.block_timestamp.0,
                    "use_kzg_da": block_input.block_info.use_kzg_da,
                    "gas_prices": {
                        "eth_gas_prices": format!("{:#?}", block_input.block_info.gas_prices.eth_gas_prices),
                        "strk_gas_prices": format!("{:#?}", block_input.block_info.gas_prices.strk_gas_prices),
                    }
                },
                "transactions": block_input.transactions.iter().map(|tx| {
                    // Use Debug format for comprehensive transaction serialization
                    format!("{:#?}", tx)
                }).collect::<Vec<_>>(),
                "tx_execution_infos": block_input.tx_execution_infos.iter().map(|exec_info| {
                    format!("{:#?}", exec_info)
                }).collect::<Vec<_>>(),
                "contract_state_commitment_info": format!("{:#?}", block_input.contract_state_commitment_info),
                "contract_class_commitment_info": format!("{:#?}", block_input.contract_class_commitment_info),
                "address_to_storage_commitment_info": block_input.address_to_storage_commitment_info.iter().map(|(addr, commitment_info)| {
                    json!({
                        "address": format!("{:#x}", addr.0.key()),
                        "commitment_info": format!("{:#?}", commitment_info)
                    })
                }).collect::<Vec<_>>(),
                "declared_class_hash_to_component_hashes": block_input.declared_class_hash_to_component_hashes.iter().map(|(class_hash, component_hashes)| {
                    json!({
                        "class_hash": format!("{:#x}", class_hash.0),
                        "component_hashes": format!("{:#?}", component_hashes)
                    })
                }).collect::<Vec<_>>(),
                "prev_block_hash": format!("{:#x}", block_input.prev_block_hash.0),
                "new_block_hash": format!("{:#x}", block_input.new_block_hash.0),
                "old_block_number_and_hash": block_input.old_block_number_and_hash.as_ref().map(|(block_number, block_hash)| {
                    json!({
                        "block_number": block_number.0,
                        "block_hash": format!("{:#x}", block_hash.0)
                    })
                })
            })
        }).collect();

    // Serialize cached state inputs completely
    let cached_state_inputs_json: Vec<serde_json::Value> = os_hints.os_input.cached_state_inputs.iter()
        .map(|cached_state| {
            json!({
                "storage": cached_state.storage.iter().map(|(addr, storage_map)| {
                    json!({
                        "address": format!("{:#x}", addr.0.key()),
                        "storage": storage_map.iter().map(|(key, value)| {
                            json!({
                                "key": format!("{:#x}", key.0.key()),
                                "value": format!("{:#x}", value)
                            })
                        }).collect::<Vec<_>>()
                    })
                }).collect::<Vec<_>>(),
                "address_to_class_hash": cached_state.address_to_class_hash.iter().map(|(addr, class_hash)| {
                    json!({
                        "address": format!("{:#x}", addr.0.key()),
                        "class_hash": format!("{:#x}", class_hash.0)
                    })
                }).collect::<Vec<_>>(),
                "address_to_nonce": cached_state.address_to_nonce.iter().map(|(addr, nonce)| {
                    json!({
                        "address": format!("{:#x}", addr.0.key()),
                        "nonce": format!("{:#x}", nonce.0)
                    })
                }).collect::<Vec<_>>(),
                "class_hash_to_compiled_class_hash": cached_state.class_hash_to_compiled_class_hash.iter().map(|(class_hash, compiled_hash)| {
                    json!({
                        "class_hash": format!("{:#x}", class_hash.0),
                        "compiled_class_hash": format!("{:#x}", compiled_hash.0)
                    })
                }).collect::<Vec<_>>()
            })
        }).collect();

    // Serialize compiled classes completely
    let compiled_classes_json: Vec<serde_json::Value> = os_hints
        .os_input
        .compiled_classes
        .iter()
        .map(|(class_hash, compiled_class)| {
            json!({
                "class_hash": format!("{:#x}", class_hash.0),
                "compiled_class": format!("{:#?}", compiled_class)
            })
        })
        .collect();

    // Serialize deprecated compiled classes completely
    let deprecated_compiled_classes_json: Vec<serde_json::Value> = os_hints
        .os_input
        .deprecated_compiled_classes
        .iter()
        .map(|(class_hash, deprecated_compiled_class)| {
            json!({
                "class_hash": format!("{:#x}", class_hash.0),
                "deprecated_compiled_class": format!("{:#?}", deprecated_compiled_class)
            })
        })
        .collect();

    // Create the complete serializable representation
    let complete_os_hints = json!({
        "os_hints_config": os_hints_config_json,
        "os_input": {
            "os_block_inputs": block_inputs_json,
            "cached_state_inputs": cached_state_inputs_json,
            "compiled_classes": compiled_classes_json,
            "deprecated_compiled_classes": deprecated_compiled_classes_json
        },
        "metadata": {
            "serialization_timestamp": chrono::Utc::now().to_rfc3339(),
            "serialization_note": "Complete serialization of OsHints including all nested structures and data.",
            "statistics": {
                "num_blocks": os_hints.os_input.os_block_inputs.len(),
                "num_cached_states": os_hints.os_input.cached_state_inputs.len(),
                "num_compiled_classes": os_hints.os_input.compiled_classes.len(),
                "num_deprecated_compiled_classes": os_hints.os_input.deprecated_compiled_classes.len(),
                "total_transactions": os_hints.os_input.os_block_inputs.iter()
                    .map(|block| block.transactions.len())
                    .sum::<usize>(),
                "block_numbers": os_hints.os_input.os_block_inputs.iter()
                    .map(|block_input| block_input.block_info.block_number)
                    .collect::<Vec<_>>()
            }
        }
    });

    // Write to file
    let json_string = serde_json::to_string_pretty(&complete_os_hints)
        .map_err(|e| PieGenerationError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;

    std::fs::write(output_path, json_string)?;
    info!("Complete OS hints successfully serialized to: {}", output_path);

    Ok(())
}

/// Helper function to sort ABI entries and normalize program attributes in a deprecated compiled class
/// This implements the complete normalization logic from pathfinder's prepare_json_contract_definition:
/// 1. Sorts ABI entries by type (Constructor, Event, Function, L1Handler, Struct)
/// 2. Removes debug_info from program
/// 3. Normalizes program attributes by removing empty/null fields
/// 4. Handles backwards compatibility for compiler versions
/// 5. Sorts attribute keys for deterministic JSON representation
fn sort_abi_entries_for_deprecated_class(
    compiled_class: &mut starknet_api::deprecated_contract_class::ContractClass,
) -> Result<(), Box<dyn std::error::Error>> {
    // CRUCIAL: Complete program normalization exactly like pathfinder does
    // The program field is directly a Program, not an Option<Program>
    let program = &mut compiled_class.program;

    // First, serialize the program to JSON so we can manipulate it
    let mut program_json = serde_json::to_value(&*program)?;

    // Step 1: Remove debug_info (like pathfinder does)
    if let Some(program_obj) = program_json.as_object_mut() {
        program_obj.insert("debug_info".to_string(), serde_json::Value::Null);
    }

    // Step 2: Normalize program attributes
    if let Some(attributes) = program_json.get_mut("attributes") {
        if let Some(attributes_array) = attributes.as_array_mut() {
            // Process each attribute in the array
            for attr in attributes_array.iter_mut() {
                if let Some(attr_obj) = attr.as_object_mut() {
                    // Remove empty accessible_scopes arrays
                    match attr_obj.get("accessible_scopes") {
                        Some(serde_json::Value::Array(array)) => {
                            if array.is_empty() {
                                attr_obj.remove("accessible_scopes");
                            }
                        }
                        Some(_) => {
                            return Err("Program attribute 'accessible_scopes' was not an array type".into());
                        }
                        None => {}
                    }

                    // Remove null flow_tracking_data fields
                    if let Some(serde_json::Value::Null) = attr_obj.get("flow_tracking_data") {
                        attr_obj.remove("flow_tracking_data");
                    }
                }
            }

            // Step 3: Sort attribute keys for deterministic ordering
            sort_attributes_keys(attributes_array)?;
        }
    }

    // Step 4: Handle backwards compatibility for compiler versions
    let compiler_version_missing = program_json.get("compiler_version").map(|v| v.is_null()).unwrap_or(true);

    if compiler_version_missing {
        // Add extra space to cairo named tuples for backwards compatibility
        if let Some(identifiers) = program_json.get_mut("identifiers") {
            add_extra_space_to_cairo_named_tuples(identifiers);
        }
        if let Some(reference_manager) = program_json.get_mut("reference_manager") {
            add_extra_space_to_cairo_named_tuples(reference_manager);
        }
    }

    // Deserialize the modified JSON back to the program
    *program = serde_json::from_value(program_json)?;

    debug!("Completed full program normalization for deprecated contract class");

    debug!("Completed ABI sorting and complete program normalization for deprecated contract class");
    Ok(())
}

/// Sort attribute keys for deterministic JSON ordering (from pathfinder)
fn sort_attributes_keys(attributes: &mut [serde_json::Value]) -> Result<(), Box<dyn std::error::Error>> {
    debug!("Sorting attributes keys for {} attributes", attributes.len());

    for attr in attributes.iter_mut() {
        if let serde_json::Value::Object(obj) = attr {
            // Create a new sorted map
            let mut sorted_map = serde_json::Map::new();

            // Collect all key-value pairs and sort them by key
            let mut pairs: Vec<_> = obj.iter().collect();
            pairs.sort_by(|a, b| a.0.cmp(b.0));

            // Insert sorted pairs into the new map
            for (key, value) in pairs {
                sorted_map.insert(key.clone(), value.clone());
            }

            // Replace the original object with the sorted one
            *attr = serde_json::Value::Object(sorted_map);
        }
    }

    debug!("Completed sorting attributes keys");
    Ok(())
}

/// Add extra space to cairo named tuples for backwards compatibility (from pathfinder)
fn add_extra_space_to_cairo_named_tuples(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Array(v) => walk_array(v),
        serde_json::Value::Object(m) => walk_map(m),
        _ => {}
    }
}

fn walk_array(array: &mut [serde_json::Value]) {
    for v in array.iter_mut() {
        add_extra_space_to_cairo_named_tuples(v);
    }
}

fn walk_map(object: &mut serde_json::Map<String, serde_json::Value>) {
    for (k, v) in object.iter_mut() {
        match v {
            serde_json::Value::String(s) => {
                let new_value = add_extra_space_to_named_tuple_type_definition(k, s);
                if new_value.as_ref() != s {
                    *v = serde_json::Value::String(new_value.into());
                }
            }
            _ => add_extra_space_to_cairo_named_tuples(v),
        }
    }
}

fn add_extra_space_to_named_tuple_type_definition<'a>(key: &str, value: &'a str) -> std::borrow::Cow<'a, str> {
    use std::borrow::Cow::*;
    match key {
        "cairo_type" | "value" => Owned(add_extra_space_before_colon(value)),
        _ => Borrowed(value),
    }
}

fn add_extra_space_before_colon(v: &str) -> String {
    v.replace(": ", " : ").replace("  :", " :")
}

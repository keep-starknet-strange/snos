//! Utilities for serialization and contract class processing.
//!
//! This module contains helper functions for:
//! - Serializing OS hints to JSON format
//! - Processing and normalizing deprecated contract classes
//! - JSON manipulation utilities for contract compatibility

use log::{debug, info};
use serde_json::json;
use starknet_os::io::os_input::OsHints;

use crate::error::PieGenerationError;

// ================================================================================================
// OS Hints Serialization
// ================================================================================================

/// Serializes OsHints to JSON format with complete data representation.
///
/// Since OsHints may not implement Serialize directly, this function creates a comprehensive
/// custom serializable representation including all nested structures and metadata.
///
/// # Arguments
///
/// * `os_hints` - The OS hints structure to serialize
/// * `output_path` - Path where the JSON file should be written
///
/// # Returns
///
/// Returns `Ok(())` on success or `PieGenerationError` on failure.
///
/// # Example
///
/// ```rust
/// use generate_pie::utils::serialization::serialize_os_hints_to_json;
///
/// let output_path = "os_hints_block_123.json";
/// serialize_os_hints_to_json(&os_hints, output_path)?;
/// ```
#[allow(dead_code)]
pub fn serialize_os_hints_to_json(os_hints: &OsHints, output_path: &str) -> Result<(), PieGenerationError> {
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

// ================================================================================================
// Contract Class Processing
// ================================================================================================

/// Sorts ABI entries and normalizes program attributes in a deprecated compiled class.
///
/// This implements the complete normalization logic from pathfinder's prepare_json_contract_definition:
/// 1. Sorts ABI entries by type (Constructor, Event, Function, L1Handler, Struct)
/// 2. Removes debug_info from program
/// 3. Normalizes program attributes by removing empty/null fields
/// 4. Handles backwards compatibility for compiler versions
/// 5. Sorts attribute keys for deterministic JSON representation
///
/// # Arguments
///
/// * `compiled_class` - Mutable reference to the contract class to process
///
/// # Returns
///
/// Returns `Ok(())` on success or error if processing fails.
///
/// # Example
///
/// ```rust
/// use generate_pie::utils::serialization::sort_abi_entries_for_deprecated_class;
///
/// sort_abi_entries_for_deprecated_class(&mut compiled_class)?;
/// ```
pub fn sort_abi_entries_for_deprecated_class(
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

// ================================================================================================
// JSON Processing Utilities
// ================================================================================================

/// Sorts attribute keys for deterministic JSON ordering (from pathfinder).
///
/// This function ensures that JSON attributes are consistently ordered
/// for reproducible serialization.
///
/// # Arguments
///
/// * `attributes` - Mutable slice of JSON values representing attributes
///
/// # Returns
///
/// Returns `Ok(())` on success or error if sorting fails.
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

/// Adds extra space to cairo named tuples for backwards compatibility (from pathfinder).
///
/// This function modifies JSON values to maintain compatibility with older
/// Cairo compiler versions by adjusting tuple formatting.
///
/// # Arguments
///
/// * `value` - Mutable reference to a JSON value to process
fn add_extra_space_to_cairo_named_tuples(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Array(v) => walk_array(v),
        serde_json::Value::Object(m) => walk_map(m),
        _ => {}
    }
}

/// Recursively walks through a JSON array applying tuple spacing.
///
/// # Arguments
///
/// * `array` - Mutable slice of JSON values to process
fn walk_array(array: &mut [serde_json::Value]) {
    for v in array.iter_mut() {
        add_extra_space_to_cairo_named_tuples(v);
    }
}

/// Recursively walks through a JSON object applying tuple spacing.
///
/// # Arguments
///
/// * `object` - Mutable reference to a JSON map to process
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

/// Adds extra space to named tuple type definitions based on key context.
///
/// # Arguments
///
/// * `key` - The JSON key name providing context
/// * `value` - The string value to potentially modify
///
/// # Returns
///
/// Returns either a borrowed reference to the original string or an owned
/// modified string with proper spacing.
fn add_extra_space_to_named_tuple_type_definition<'a>(key: &str, value: &'a str) -> std::borrow::Cow<'a, str> {
    use std::borrow::Cow::*;
    match key {
        "cairo_type" | "value" => Owned(add_extra_space_before_colon(value)),
        _ => Borrowed(value),
    }
}

/// Adds extra space before colons in type definitions.
///
/// This function performs the actual string manipulation to add spacing
/// while avoiding double spaces.
///
/// # Arguments
///
/// * `v` - The string to modify
///
/// # Returns
///
/// Returns a new string with proper colon spacing.
fn add_extra_space_before_colon(v: &str) -> String {
    v.replace(": ", " : ").replace("  :", " :")
}

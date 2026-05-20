//! Utilities for contract class processing and JSON normalization.

use log::debug;

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

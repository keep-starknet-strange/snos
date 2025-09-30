use log::info;
use num_traits::cast::ToPrimitive;
use serde::Serialize;
use starknet_api::block::{GasPrice, GasPriceVector, NonzeroGasPrice};
use std::fs::File;
use std::io::Write;
use std::path::Path;

use crate::error::FeltConversionError;
use starknet_types_core::felt::Felt;

pub fn build_gas_price_vector(
    l1_gas_price: &Felt,
    l1_data_gas_price: &Felt,
    l2_gas_price: &Felt,
) -> Result<GasPriceVector, FeltConversionError> {
    Ok(GasPriceVector {
        l1_gas_price: NonzeroGasPrice::new(GasPrice(felt_to_u128(l1_gas_price)?))
            .map_err(|e| FeltConversionError::new_custom(format!("Invalid STRK L1 gas price: {}", e)))?,
        l1_data_gas_price: NonzeroGasPrice::new(GasPrice(felt_to_u128(l1_data_gas_price)?))
            .map_err(|e| FeltConversionError::new_custom(format!("Invalid STRK L1 data gas price: {}", e)))?,
        l2_gas_price: NonzeroGasPrice::new(GasPrice(felt_to_u128(l2_gas_price)?))
            .map_err(|e| FeltConversionError::new_custom(format!("Invalid STRK L2 gas price: {}", e)))?,
    })
}

pub fn felt_to_u128(felt: &Felt) -> Result<u128, FeltConversionError> {
    felt.to_u128().ok_or(FeltConversionError::OverflowError)
}

/// Generic function to serialize any serializable object and write it to a file
///
/// # Arguments
/// * `object` - Any object that implements the Serialize trait
/// * `file_path` - Path where the file should be written
/// * `format` - Optional format specification ("json", "yaml", etc.). Defaults to JSON.
///
/// # Returns
/// * `Result<(), Box<dyn std::error::Error>>` - Ok(()) on success, error on failure
///
/// # Examples
/// ```
/// let data = vec![1, 2, 3, 4, 5];
/// write_serializable_to_file(&data, "output/numbers.json", Some("json"))?;
///
/// let traces = get_transaction_traces();
/// write_serializable_to_file(&traces, "debug/traces.json", None)?;
/// ```
#[allow(dead_code)]
pub fn write_serializable_to_file<T>(
    object: &T,
    file_path: &str,
    format: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>>
where
    T: Serialize,
{
    // Create a directory if it doesn't exist
    if let Some(parent) = Path::new(file_path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut file = File::create(file_path)?;

    match format.unwrap_or("json") {
        "json" => {
            let json_string = serde_json::to_string_pretty(object)?;
            file.write_all(json_string.as_bytes())?;
        }
        "json-compact" => {
            let json_string = serde_json::to_string(object)?;
            file.write_all(json_string.as_bytes())?;
        }
        #[cfg(feature = "yaml")]
        "yaml" => {
            let yaml_string = serde_yaml::to_string(object)?;
            file.write_all(yaml_string.as_bytes())?;
        }
        _ => {
            return Err(format!("Unsupported format: {}", format.unwrap_or("json")).into());
        }
    }

    file.flush()?;
    info!("Successfully wrote serialized data to: {}", file_path);
    Ok(())
}

use log::info;
use num_traits::cast::ToPrimitive;
use starknet_api::block::{GasPrice, GasPriceVector, NonzeroGasPrice};
use std::path::Path;

use crate::error::FeltConversionError;
use blockifier::blockifier_versioned_constants::VersionedConstants;
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

/// Loads versioned constants from a file path if provided.
///
/// This function handles loading versioned constants from a JSON file.
/// If the path is `None`, it returns `None` (indicating auto-detection should be used).
/// If the path is provided but loading fails, it returns an error.
///
/// # Arguments
/// * `path` - Optional path to a JSON file containing versioned constants
///
/// # Returns
/// * `Result<Option<VersionedConstants>, String>` - Ok(Some(constants)) if loaded successfully,
///   Ok(None) if path is None, or Err(error_message) if loading failed
///
/// # Example
/// ```rust,no_run
/// use generate_pie::utils::load_versioned_constants;
///
/// let constants = load_versioned_constants(None)?;
/// assert!(constants.is_none());
///
/// // Load from file
/// let constants = load_versioned_constants(Some("path/to/constants.json"))?;
/// assert!(constants.is_some());
/// ```
pub fn load_versioned_constants(path: Option<&str>) -> Result<Option<VersionedConstants>, String> {
    match path {
        Some(path_str) => {
            info!("Loading versioned constants from: {}", path_str);
            match VersionedConstants::from_path(Path::new(path_str)) {
                Ok(constants) => {
                    info!("Successfully loaded versioned constants from file");
                    Ok(Some(constants))
                }
                Err(e) => Err(format!("Failed to load versioned constants from {}: {:?}", path_str, e)),
            }
        }
        None => Ok(None),
    }
}

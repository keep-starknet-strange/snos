use num_traits::cast::ToPrimitive;
use starknet_api::block::{GasPrice, GasPriceVector, NonzeroGasPrice};

use crate::error::FeltConversionError;
use starknet_types_core::felt::Felt;

pub fn build_gas_price_vector(
    l1_gas_price: &Felt,
    l1_data_gas_price: &Felt,
    l2_gas_price: &Felt,
) -> Result<GasPriceVector, FeltConversionError> {
    Ok(GasPriceVector {
        l1_gas_price: NonzeroGasPrice::new(GasPrice(
            felt_to_u128(l1_gas_price).map_err(|_| FeltConversionError::OverflowError)?,
        ))
        .map_err(|_| FeltConversionError::new_custom("Invalid STRK L1 gas price"))?,
        l1_data_gas_price: NonzeroGasPrice::new(GasPrice(
            felt_to_u128(l1_data_gas_price).map_err(|_| FeltConversionError::OverflowError)?,
        ))
        .map_err(|_| FeltConversionError::new_custom("Invalid STRK L1 data gas price"))?,
        l2_gas_price: NonzeroGasPrice::new(GasPrice(
            felt_to_u128(l2_gas_price).map_err(|_| FeltConversionError::OverflowError)?,
        ))
        .map_err(|_| FeltConversionError::new_custom("Invalid STRK L2 gas price"))?,
    })
}

pub fn felt_to_u128(felt: &Felt) -> Result<u128, FeltConversionError> {
    felt.to_u128().ok_or(FeltConversionError::OverflowError)
}

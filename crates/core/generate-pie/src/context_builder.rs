//! Context builder utilities for creating block execution contexts.
//!
//! This module provides utilities for building block contexts and converting
//! between different types used in the Starknet execution environment.

use blockifier::blockifier_versioned_constants::VersionedConstants;
use blockifier::bouncer::BouncerConfig;
use blockifier::context::{BlockContext, ChainInfo, FeeTokenAddresses};
use starknet::core::types::{BlockWithTxs, L1DataAvailabilityMode};
use starknet_api::block::{
    BlockInfo, BlockNumber, BlockTimestamp, GasPrice, GasPriceVector, GasPrices, NonzeroGasPrice, StarknetVersion,
};
use starknet_api::contract_address;
use starknet_api::core::ChainId;
use starknet_types_core::felt::Felt;

use crate::api_to_blockifier_conversion::felt_to_u128;
use crate::constants::{
    DEFAULT_ETH_L2_GAS_PRICE, DEFAULT_SEPOLIA_ETH_FEE_TOKEN, DEFAULT_SEPOLIA_STRK_FEE_TOKEN, DEFAULT_STRK_L2_GAS_PRICE,
};
use crate::error::FeltConversionError;

/// Converts a Felt value to a ChainId.
///
/// This function extracts the chain ID from a Felt value by converting it to bytes,
/// skipping leading zeros, and creating a string representation.
///
/// # Arguments
///
/// * `felt` - The Felt value containing the chain ID
///
/// # Returns
///
/// A `ChainId` instance representing the chain ID.
///
/// # Example
///
/// ```rust
/// use generate_pie::context_builder::chain_id_from_felt;
/// use starknet_types_core::felt::Felt;
///
/// let felt = Felt::from_hex("0x534e5f5345504f4c4941").unwrap(); // "SN_SEPOLIA"
/// let chain_id = chain_id_from_felt(felt);
/// ```
pub fn chain_id_from_felt(felt: Felt) -> ChainId {
    // Skip leading zeroes to get the actual chain ID bytes
    let chain_id_bytes: Vec<_> = felt.to_bytes_be().into_iter().skip_while(|byte| *byte == 0u8).collect();
    let chain_id_str = String::from_utf8_lossy(&chain_id_bytes);
    ChainId::from(chain_id_str.into_owned())
}

/// Builds a block context for Starknet execution.
///
/// This function creates a `BlockContext` that contains all the necessary information
/// for executing transactions in a specific block, including gas prices, chain info,
/// and versioned constants.
///
/// # Arguments
///
/// * `chain_id` - The chain ID for the target network
/// * `block` - The block containing transactions to execute
/// * `is_l3` - Whether this is an L3 chain (true) or L2 chain (false)
/// * `_starknet_version` - The Starknet version (currently unused)
///
/// # Returns
///
/// Returns a `BlockContext` if successful, or a `FeltConversionError` if gas price
/// conversion fails.
///
/// # Errors
///
/// Returns a `FeltConversionError` if any gas price conversion fails.
///
/// # Example
///
/// ```rust
/// use generate_pie::context_builder::build_block_context;
/// use starknet_api::core::ChainId;
/// use starknet_api::block::StarknetVersion;
///
/// // Assuming you have a block and chain_id
/// // let context = build_block_context(chain_id, &block, false, StarknetVersion::V0_14_0)?;
/// ```
pub fn build_block_context(
    chain_id: ChainId,
    block: &BlockWithTxs,
    is_l3: bool,
    _starknet_version: StarknetVersion,
) -> Result<BlockContext, FeltConversionError> {
    // Extract sequencer address
    let sequencer_address_hex = block.sequencer_address.to_hex_string();
    let sequencer_address = contract_address!(sequencer_address_hex.as_str());

    // Determine data availability mode
    let use_kzg_da = match block.l1_da_mode {
        L1DataAvailabilityMode::Blob => true,
        L1DataAvailabilityMode::Calldata => false,
    };

    // Build gas prices with proper error handling
    let eth_gas_prices = GasPriceVector {
        l1_gas_price: NonzeroGasPrice::new(GasPrice(
            felt_to_u128(&block.l1_gas_price.price_in_wei).map_err(|_| FeltConversionError::OverflowError)?,
        ))
        .map_err(|_| FeltConversionError::new_custom("Invalid ETH L1 gas price"))?,
        l1_data_gas_price: NonzeroGasPrice::new(GasPrice(
            felt_to_u128(&block.l1_data_gas_price.price_in_wei).map_err(|_| FeltConversionError::OverflowError)?,
        ))
        .map_err(|_| FeltConversionError::new_custom("Invalid ETH L1 data gas price"))?,
        l2_gas_price: NonzeroGasPrice::new(GasPrice(
            felt_to_u128(
                &Felt::from_hex(DEFAULT_ETH_L2_GAS_PRICE)
                    .map_err(|_| FeltConversionError::new_custom("Invalid default ETH L2 gas price"))?,
            )
            .map_err(|_| FeltConversionError::OverflowError)?,
        ))
        .map_err(|_| FeltConversionError::new_custom("Invalid ETH L2 gas price"))?,
    };

    let strk_gas_prices = GasPriceVector {
        l1_gas_price: NonzeroGasPrice::new(GasPrice(
            felt_to_u128(&block.l1_gas_price.price_in_fri).map_err(|_| FeltConversionError::OverflowError)?,
        ))
        .map_err(|_| FeltConversionError::new_custom("Invalid STRK L1 gas price"))?,
        l1_data_gas_price: NonzeroGasPrice::new(GasPrice(
            felt_to_u128(&block.l1_data_gas_price.price_in_fri).map_err(|_| FeltConversionError::OverflowError)?,
        ))
        .map_err(|_| FeltConversionError::new_custom("Invalid STRK L1 data gas price"))?,
        l2_gas_price: NonzeroGasPrice::new(GasPrice(
            felt_to_u128(
                &Felt::from_hex(DEFAULT_STRK_L2_GAS_PRICE)
                    .map_err(|_| FeltConversionError::new_custom("Invalid default STRK L2 gas price"))?,
            )
            .map_err(|_| FeltConversionError::OverflowError)?,
        ))
        .map_err(|_| FeltConversionError::new_custom("Invalid STRK L2 gas price"))?,
    };

    let block_info = BlockInfo {
        block_number: BlockNumber(block.block_number),
        block_timestamp: BlockTimestamp(block.timestamp),
        sequencer_address,
        gas_prices: GasPrices { eth_gas_prices, strk_gas_prices },
        use_kzg_da,
    };

    log::debug!("Block info created: {:?}", block_info);

    // Build chain information
    let chain_info = ChainInfo {
        chain_id,
        // Fee token addresses for Sepolia testnet
        // Reference: https://docs.starknet.io/tools/important-addresses/
        fee_token_addresses: FeeTokenAddresses {
            strk_fee_token_address: contract_address!(DEFAULT_SEPOLIA_STRK_FEE_TOKEN),
            eth_fee_token_address: contract_address!(DEFAULT_SEPOLIA_ETH_FEE_TOKEN),
        },
        is_l3,
    };

    // Get versioned constants for Starknet v0.14.0
    let versioned_constants = VersionedConstants::get(&StarknetVersion::V0_14_0)
        .map_err(|_| FeltConversionError::new_custom("Failed to get versioned constants for v0.14.0"))?;

    // Use maximum bouncer configuration
    let bouncer_config = BouncerConfig::max();

    Ok(BlockContext::new(block_info, chain_info, versioned_constants.clone(), bouncer_config))
}

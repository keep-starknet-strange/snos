//! Context builder utilities for creating block execution contexts.
//!
//! This module provides utilities for building block contexts and converting
//! between different types used in the Starknet execution environment.

use blockifier::blockifier_versioned_constants::VersionedConstants;
use blockifier::bouncer::BouncerConfig;
use blockifier::context::{BlockContext, ChainInfo, FeeTokenAddresses};
use log::debug;
use starknet::core::types::{BlockWithTxs, L1DataAvailabilityMode};
use starknet_api::block::{BlockInfo, BlockNumber, BlockTimestamp, GasPrices, StarknetVersion};
use starknet_api::contract_address;
use starknet_api::core::ChainId;
use starknet_types_core::felt::Felt;

use crate::constants::{
    DEFAULT_ETH_L2_GAS_PRICE, DEFAULT_SEPOLIA_ETH_FEE_TOKEN, DEFAULT_SEPOLIA_STRK_FEE_TOKEN, DEFAULT_STRK_L2_GAS_PRICE,
};
use crate::error::FeltConversionError;
use crate::utils::build_gas_price_vector;

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
    starknet_version: &StarknetVersion,
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
    let eth_gas_prices = build_gas_price_vector(
        &block.l1_gas_price.price_in_wei,
        &block.l1_data_gas_price.price_in_wei,
        &Felt::from_hex(DEFAULT_ETH_L2_GAS_PRICE)
            .map_err(|_| FeltConversionError::new_custom("Invalid default ETH L2 gas price"))?,
    )?;
    let strk_gas_prices = build_gas_price_vector(
        &block.l1_gas_price.price_in_fri,
        &block.l1_data_gas_price.price_in_fri,
        &Felt::from_hex(DEFAULT_STRK_L2_GAS_PRICE)
            .map_err(|_| FeltConversionError::new_custom("Invalid default STRK L2 gas price"))?,
    )?;

    let block_info = BlockInfo {
        block_number: BlockNumber(block.block_number),
        block_timestamp: BlockTimestamp(block.timestamp),
        sequencer_address,
        gas_prices: GasPrices { eth_gas_prices, strk_gas_prices },
        use_kzg_da,
    };

    debug!("Block info created: {:?}", block_info);

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
    let versioned_constants = VersionedConstants::get(starknet_version).map_err(|_| {
        FeltConversionError::new_custom(format!("Failed to get versioned constants for {}", starknet_version))
    })?;

    // Use maximum bouncer configuration
    let bouncer_config = BouncerConfig::max();

    Ok(BlockContext::new(block_info, chain_info, versioned_constants.clone(), bouncer_config))
}

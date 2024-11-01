use std::num::NonZeroU128;

use blockifier::blockifier::block::{BlockInfo, GasPrices};
use blockifier::bouncer::BouncerConfig;
use blockifier::context::{BlockContext, ChainInfo, FeeTokenAddresses};
use blockifier::versioned_constants::VersionedConstants;
use starknet::core::types::{BlockWithTxs, Felt, L1DataAvailabilityMode};
use starknet_api::block::{BlockNumber, BlockTimestamp};
use starknet_api::core::{ChainId, ContractAddress, PatriciaKey};
use starknet_api::{contract_address, felt, patricia_key};

use crate::utils::{felt_to_u128, FeltConversionError};

fn felt_to_gas_price(price: &Felt) -> Result<NonZeroU128, FeltConversionError> {
    // Inspiration taken from Papyrus:
    // https://github.com/starkware-libs/sequencer/blob/7218aa1f7ca3fe21c0a2bede2570820939ffe069/crates/papyrus_execution/src/lib.rs#L363-L371
    if *price == Felt::ZERO {
        return Ok(NonZeroU128::MIN);
    }

    // Catch here if price > U128::MAX
    let gas_price = felt_to_u128(price)?;
    // If felt_to_u128 conversion is ok, it won't fail cause we're catching the zero above
    NonZeroU128::new(gas_price).ok_or(FeltConversionError::CustomError("Gas price cannot be zero".to_string()))
}

pub fn build_block_context(
    chain_id: ChainId,
    block: &BlockWithTxs,
    starknet_version: blockifier::versioned_constants::StarknetVersion,
) -> Result<BlockContext, FeltConversionError> {
    let sequencer_address_hex = block.sequencer_address.to_hex_string();
    let sequencer_address = contract_address!(sequencer_address_hex.as_str());
    let use_kzg_da = match block.l1_da_mode {
        L1DataAvailabilityMode::Blob => true,
        L1DataAvailabilityMode::Calldata => false,
    };

    let block_info = BlockInfo {
        block_number: BlockNumber(block.block_number),
        block_timestamp: BlockTimestamp(block.timestamp),
        sequencer_address,
        gas_prices: GasPrices {
            eth_l1_gas_price: felt_to_gas_price(&block.l1_gas_price.price_in_wei)?,
            strk_l1_gas_price: felt_to_gas_price(&block.l1_gas_price.price_in_fri)?,
            eth_l1_data_gas_price: felt_to_gas_price(&block.l1_data_gas_price.price_in_wei)?,
            strk_l1_data_gas_price: felt_to_gas_price(&block.l1_data_gas_price.price_in_fri)?,
        },
        use_kzg_da,
    };

    let chain_info = ChainInfo {
        chain_id,
        // cf. https://docs.starknet.io/tools/important-addresses/
        fee_token_addresses: FeeTokenAddresses {
            strk_fee_token_address: contract_address!(
                "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d"
            ),
            eth_fee_token_address: contract_address!(
                "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"
            ),
        },
    };

    let versioned_constants = VersionedConstants::get(starknet_version);
    let bouncer_config = BouncerConfig::max();

    Ok(BlockContext::new(block_info, chain_info, versioned_constants.clone(), bouncer_config))
}

#[cfg(test)]
mod tests {

    use starknet::core::types::{Felt, ResourcePrice};
    use starknet_api::core::ChainId;

    use super::*;

    #[test]
    fn test_build_block_context_with_zero_gas_prices() {
        let chain_id = ChainId::Mainnet;
        // We don't really care about most of the fields.
        // What's important here is to set to zero different gas prices
        let block = BlockWithTxs {
            status: starknet::core::types::BlockStatus::AcceptedOnL1,
            block_hash: Felt::ZERO,
            parent_hash: Felt::ZERO,
            block_number: 1,
            new_root: Felt::ZERO,
            timestamp: 0,
            sequencer_address: Felt::ZERO,
            l1_gas_price: ResourcePrice { price_in_wei: Felt::ZERO, price_in_fri: Felt::ZERO },
            l1_data_gas_price: ResourcePrice { price_in_wei: Felt::ZERO, price_in_fri: Felt::ZERO },
            l1_da_mode: L1DataAvailabilityMode::Blob,
            starknet_version: String::from("0.13.2.1"),
            transactions: vec![],
        };

        let starknet_version = blockifier::versioned_constants::StarknetVersion::Latest;

        // Call this function must not fail
        let block_context = build_block_context(chain_id, &block, starknet_version).unwrap();

        // Verify that gas prices were set to NonZeroU128::MIN
        assert_eq!(block_context.block_info().gas_prices.eth_l1_gas_price, NonZeroU128::MIN);
        assert_eq!(block_context.block_info().gas_prices.strk_l1_gas_price, NonZeroU128::MIN);
        assert_eq!(block_context.block_info().gas_prices.eth_l1_data_gas_price, NonZeroU128::MIN);
        assert_eq!(block_context.block_info().gas_prices.strk_l1_data_gas_price, NonZeroU128::MIN);
    }

    #[test]
    fn test_build_block_context_with_custom_gas_prices() {
        let chain_id = ChainId::Mainnet;

        // Expected values for gas price
        let wei_l1_price = 1234;
        let fri_l1_price = 5678;
        let wei_l1_data_price = 9012;
        let fri_l1_data_price = 3456;

        let block = BlockWithTxs {
            status: starknet::core::types::BlockStatus::AcceptedOnL1,
            block_hash: Felt::ZERO,
            parent_hash: Felt::ZERO,
            block_number: 1,
            new_root: Felt::ZERO,
            timestamp: 0,
            sequencer_address: Felt::ZERO,
            l1_gas_price: ResourcePrice {
                price_in_wei: Felt::from(wei_l1_price),
                price_in_fri: Felt::from(fri_l1_price),
            },
            l1_data_gas_price: ResourcePrice {
                price_in_wei: Felt::from(wei_l1_data_price),
                price_in_fri: Felt::from(fri_l1_data_price),
            },
            l1_da_mode: L1DataAvailabilityMode::Blob,
            starknet_version: String::from("0.13.2.1"),
            transactions: vec![],
        };

        let starknet_version = blockifier::versioned_constants::StarknetVersion::Latest;
        let block_context = build_block_context(chain_id, &block, starknet_version).unwrap();

        // Verify that gas prices match our input values
        assert_eq!(block_context.block_info().gas_prices.eth_l1_gas_price, NonZeroU128::new(wei_l1_price).unwrap());
        assert_eq!(block_context.block_info().gas_prices.strk_l1_gas_price, NonZeroU128::new(fri_l1_price).unwrap());
        assert_eq!(
            block_context.block_info().gas_prices.eth_l1_data_gas_price,
            NonZeroU128::new(wei_l1_data_price).unwrap()
        );
        assert_eq!(
            block_context.block_info().gas_prices.strk_l1_data_gas_price,
            NonZeroU128::new(fri_l1_data_price).unwrap()
        );
    }
}

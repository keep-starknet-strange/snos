use blockifier::blockifier::block::{BlockInfo, GasPrices};
use blockifier::bouncer::BouncerConfig;
use blockifier::context::{BlockContext, ChainInfo, FeeTokenAddresses};
use blockifier::versioned_constants::VersionedConstants;
use starknet::core::types::BlockWithTxs;
use starknet_api::block::{BlockNumber, BlockTimestamp};
use starknet_api::core::{ChainId, ContractAddress, PatriciaKey};
use starknet_api::{contract_address, felt, patricia_key};

use crate::utils::felt_to_u128;

pub fn build_block_context(
    chain_id: ChainId,
    block: &BlockWithTxs,
    starknet_version: blockifier::versioned_constants::StarknetVersion,
) -> BlockContext {
    let sequencer_address_hex = block.sequencer_address.to_hex_string();
    let sequencer_address = contract_address!(sequencer_address_hex.as_str());

    let block_info = BlockInfo {
        block_number: BlockNumber(block.block_number),
        block_timestamp: BlockTimestamp(block.timestamp),
        sequencer_address,
        gas_prices: GasPrices {
            eth_l1_gas_price: felt_to_u128(&block.l1_gas_price.price_in_wei).try_into().unwrap(),
            strk_l1_gas_price: felt_to_u128(&block.l1_gas_price.price_in_fri).try_into().unwrap(),
            eth_l1_data_gas_price: felt_to_u128(&block.l1_data_gas_price.price_in_wei).try_into().unwrap(),
            strk_l1_data_gas_price: felt_to_u128(&block.l1_data_gas_price.price_in_fri).try_into().unwrap(),
        },
        use_kzg_da: false,
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

    BlockContext::new(block_info, chain_info, versioned_constants.clone(), bouncer_config)
}

use blockifier::block::{BlockInfo, GasPrices};
use blockifier::context::{BlockContext, ChainInfo, FeeTokenAddresses};
use blockifier::versioned_constants::VersionedConstants;
use starknet::core::types::BlockWithTxs;
use starknet_api::block::{BlockNumber, BlockTimestamp};
use starknet_api::core::{ContractAddress, PatriciaKey};
use starknet_api::hash::StarkHash;
use starknet_api::{contract_address, patricia_key};
use starknet_os::config::{GasPriceBounds, StarknetGeneralConfig, StarknetOsConfig, SN_SEPOLIA};

use crate::utils::{felt_to_u128, felt_vm2api};

pub fn build_block_context(chain_id: String, block: &BlockWithTxs) -> BlockContext {
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
        chain_id: starknet_api::core::ChainId(chain_id),
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

    let versioned_constants = VersionedConstants::latest_constants();

    BlockContext::new_unchecked(&block_info, &chain_info, versioned_constants)
}

pub fn build_starknet_config(chain_id: String, block_context: &BlockContext, block: &BlockWithTxs) -> StarknetGeneralConfig {

    let default_general_config = StarknetGeneralConfig::default();
    let default_gas_price_bounds = default_general_config.gas_price_bounds.clone();

    let general_config = StarknetGeneralConfig {
        starknet_os_config: StarknetOsConfig {
            chain_id: starknet_api::core::ChainId(SN_SEPOLIA.to_string()),
            fee_token_address: block_context.chain_info().fee_token_addresses.strk_fee_token_address,
            deprecated_fee_token_address: block_context.chain_info().fee_token_addresses.eth_fee_token_address,
        },
        sequencer_address: starknet_api::core::ContractAddress(
            PatriciaKey::try_from(felt_vm2api(block.sequencer_address)).unwrap(),
        ),
        gas_price_bounds: GasPriceBounds {
            // TODO: this may not be the correct way to interpret the block data
            min_fri_l1_data_gas_price: block.l1_data_gas_price.price_in_fri.to_biguint().try_into().expect("price should fit in u128"),
            min_fri_l1_gas_price: block.l1_gas_price.price_in_fri.to_biguint().try_into().expect("price should fit in u128"),
            min_wei_l1_data_gas_price: block.l1_data_gas_price.price_in_wei.to_biguint().try_into().expect("price should fit in u128"),
            min_wei_l1_gas_price: block.l1_gas_price.price_in_wei.to_biguint().try_into().expect("price should fit in u128"),
            ..default_gas_price_bounds
        },
        ..default_general_config
    };

    general_config
}

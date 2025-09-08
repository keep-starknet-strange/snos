use crate::api_to_blockifier_conversion::felt_to_u128;
use crate::error::FeltConversionError;
use blockifier::blockifier_versioned_constants::VersionedConstants;
use blockifier::bouncer::BouncerConfig;
use blockifier::context::{BlockContext, ChainInfo, FeeTokenAddresses};
use starknet::core::types::{BlockWithTxs, L1DataAvailabilityMode};
use starknet_api::block::{
    BlockInfo, BlockNumber, BlockTimestamp, GasPrice, GasPriceVector, GasPrices, NonzeroGasPrice,
    StarknetVersion,
};
use starknet_api::contract_address;
use starknet_api::core::ChainId;
use starknet_types_core::felt::Felt;

pub fn chain_id_from_felt(felt: Felt) -> ChainId {
    // Skip leading zeroes
    let chain_id_bytes: Vec<_> = felt
        .to_bytes_be()
        .into_iter()
        .skip_while(|byte| *byte == 0u8)
        .collect();
    let chain_id_str = String::from_utf8_lossy(&chain_id_bytes);
    ChainId::from(chain_id_str.into_owned())
}

pub fn build_block_context(
    chain_id: ChainId,
    block: &BlockWithTxs,
    starknet_version: StarknetVersion,
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
            // eth_l1_gas_price: felt_to_gas_price(&block.l1_gas_price.price_in_wei)?,
            // strk_l1_gas_price: felt_to_gas_price(&block.l1_gas_price.price_in_fri)?,
            // eth_l1_data_gas_price: felt_to_gas_price(&block.l1_data_gas_price.price_in_wei)?,
            // strk_l1_data_gas_price: felt_to_gas_price(&block.l1_data_gas_price.price_in_fri)?,
            eth_gas_prices: GasPriceVector {
                l1_gas_price: NonzeroGasPrice::new(GasPrice(
                    felt_to_u128(&block.l1_gas_price.price_in_wei).unwrap(),
                ))
                .unwrap(),
                l1_data_gas_price: NonzeroGasPrice::new(GasPrice(
                    felt_to_u128(&block.l1_data_gas_price.price_in_wei).unwrap(),
                ))
                .unwrap(),
                l2_gas_price: NonzeroGasPrice::new(GasPrice(
                    felt_to_u128(&Felt::from_hex("0x199fe").unwrap()).unwrap(),
                ))
                .unwrap(),
            }, //TODO: update the gas prices for the right block info
            strk_gas_prices: GasPriceVector {
                l1_gas_price: NonzeroGasPrice::new(GasPrice(
                    felt_to_u128(&block.l1_gas_price.price_in_fri).unwrap(),
                ))
                .unwrap(),
                l1_data_gas_price: NonzeroGasPrice::new(GasPrice(
                    felt_to_u128(&block.l1_data_gas_price.price_in_fri).unwrap(),
                ))
                .unwrap(),
                l2_gas_price: NonzeroGasPrice::new(GasPrice(
                    felt_to_u128(&Felt::from_hex("0xb2d05e00").unwrap()).unwrap(),
                ))
                .unwrap(),
            },
        },
        use_kzg_da,
    };

    println!(
        ">>>>>>>>> printing the block info for the context and for matching the information: {:?}",
        block_info
    );

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

    // let versioned_constants = VersionedConstants::get(&starknet_version).expect("issue while getting version constant");
    let latest_vc = VersionedConstants::get(&StarknetVersion::V0_14_0).unwrap();
    // println!("gas costs here are: {:?}", latest_vc);
    // panic!("temp");

    // let vc = VersionedConstants::from_path(Path::new("/Users/mohit/Desktop/karnot/snos-poc/debug/vc_main_0_14_0.json")).unwrap();
    let bouncer_config = BouncerConfig::max();

    Ok(BlockContext::new(
        block_info,
        chain_info,
        latest_vc.clone(),
        bouncer_config,
    ))
}

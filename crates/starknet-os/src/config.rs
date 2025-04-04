use std::fs::File;
use std::path::PathBuf;

use blockifier::blockifier::block::{BlockInfo, GasPrices};
use blockifier::bouncer::BouncerConfig;
use blockifier::context::{BlockContext, ChainInfo, FeeTokenAddresses};
use blockifier::transaction::objects::FeeType;
use blockifier::versioned_constants::VersionedConstants;
use cairo_vm::types::layout_name::LayoutName;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use starknet_api::block::{BlockNumber, BlockTimestamp};
use starknet_api::core::{ChainId, ContractAddress, PatriciaKey};
use starknet_api::{contract_address, felt, patricia_key};

use crate::error::SnOsError;

pub const fn default_layout() -> LayoutName {
    LayoutName::all_cairo
}

// The following values were taken from general_config.yml from cairo-lang
const VALIDATE_MAX_N_STEPS_OVERRIDE: u32 = 1000000;

const DEFAULT_CONFIG_PATH: &str = "../../cairo-lang/src/starkware/starknet/definitions/general_config.yml";
pub const STORED_BLOCK_HASH_BUFFER: u64 = 10;
pub const BLOCK_HASH_CONTRACT_ADDRESS: u64 = 1;
pub const STARKNET_OS_CONFIG_HASH_VERSION: &str = "StarknetOsConfig1";
pub const DEFAULT_COMPILER_VERSION: &str = "0.12.2";
pub const DEFAULT_STORAGE_TREE_HEIGHT: u64 = 251;
pub const COMPILED_CLASS_HASH_COMMITMENT_TREE_HEIGHT: usize = 251;
pub const CONTRACT_STATES_COMMITMENT_TREE_HEIGHT: usize = 251;
pub const DEFAULT_INNER_TREE_HEIGHT: u64 = 64;
// TODO: update with relevant address
pub const DEFAULT_FEE_TOKEN_ADDR: &str = "7ce4aa542d72a82662cda96b147da9b041ecf8c61f67ef657f3bbb852fc698f";
pub const DEFAULT_DEPRECATED_FEE_TOKEN_ADDR: &str = "5195ba458d98a8d5a390afa87e199566e473d1124c07a3c57bf19813255ac41";
pub const SEQUENCER_ADDR_0_13_3: &str = "0x31c641e041f8d25997985b0efe68d0c5ce89d418ca9a127ae043aebed6851c5";
pub const CONTRACT_ADDRESS_BITS: usize = 251;
pub const CONTRACT_CLASS_LEAF_VERSION: &[u8] = "CONTRACT_CLASS_LEAF_V0".as_bytes();

/// The version of the Starknet global state.
pub const GLOBAL_STATE_VERSION: &[u8] = "STARKNET_STATE_V0".as_bytes();

#[serde_as]
#[derive(Debug, Serialize, Clone, Deserialize, PartialEq)]
pub struct StarknetOsConfig {
    pub chain_id: ChainId,
    pub fee_token_address: ContractAddress,
    pub deprecated_fee_token_address: ContractAddress,
}

#[derive(Debug, Serialize, Clone, Deserialize, PartialEq)]
pub struct GasPriceBounds {
    pub min_wei_l1_gas_price: u128,
    pub min_fri_l1_gas_price: u128,
    pub max_fri_l1_gas_price: u128,
    pub min_wei_l1_data_gas_price: u128,
    pub min_fri_l1_data_gas_price: u128,
    pub max_fri_l1_data_gas_price: u128,
}

const fn default_use_kzg_da() -> bool {
    true
}

#[derive(Debug, Serialize, Clone, Deserialize, PartialEq)]
pub struct StarknetGeneralConfig {
    pub starknet_os_config: StarknetOsConfig,
    pub gas_price_bounds: GasPriceBounds,
    pub validate_max_n_steps_override: u32,
    pub default_eth_price_in_fri: u128,
    pub sequencer_address: ContractAddress,
    pub enforce_l1_handler_fee: bool,
    #[serde(default = "default_use_kzg_da")]
    pub use_kzg_da: bool,
}

impl Default for StarknetGeneralConfig {
    fn default() -> Self {
        Self {
            starknet_os_config: StarknetOsConfig {
                chain_id: ChainId::Sepolia,
                fee_token_address: contract_address!(DEFAULT_FEE_TOKEN_ADDR),
                deprecated_fee_token_address: contract_address!(DEFAULT_DEPRECATED_FEE_TOKEN_ADDR),
            },
            gas_price_bounds: GasPriceBounds {
                max_fri_l1_data_gas_price: 10000000000,
                max_fri_l1_gas_price: 100000000000000,
                min_fri_l1_data_gas_price: 10,
                min_fri_l1_gas_price: 100000000000,
                min_wei_l1_data_gas_price: 100000,
                min_wei_l1_gas_price: 10000000000,
            },
            validate_max_n_steps_override: VALIDATE_MAX_N_STEPS_OVERRIDE,
            default_eth_price_in_fri: 1_000_000_000_000_000_000_000,
            sequencer_address: contract_address!(SEQUENCER_ADDR_0_13_3),
            enforce_l1_handler_fee: true,
            use_kzg_da: false,
        }
    }
}

impl StarknetGeneralConfig {
    pub fn from_file(f: PathBuf) -> Result<StarknetGeneralConfig, SnOsError> {
        let conf = File::open(f).map_err(|e| SnOsError::CatchAll(format!("config - {e}")))?;
        serde_yaml::from_reader(conf).map_err(|e| SnOsError::CatchAll(format!("config - {e}")))
    }
    /// Returns a config from the default config file, if it exists
    pub fn from_default_file() -> Result<StarknetGeneralConfig, SnOsError> {
        StarknetGeneralConfig::from_file(PathBuf::from(DEFAULT_CONFIG_PATH))
    }

    pub fn empty_block_context(&self) -> BlockContext {
        let mut versioned_constants = VersionedConstants::default();

        versioned_constants.max_recursion_depth = 50;

        let block_info = BlockInfo {
            block_number: BlockNumber(0),
            block_timestamp: BlockTimestamp(0),

            sequencer_address: self.sequencer_address,
            gas_prices: GasPrices {
                eth_l1_gas_price: 1u128.try_into().unwrap(), // TODO: update with 4844
                strk_l1_gas_price: 1u128.try_into().unwrap(),
                eth_l1_data_gas_price: 1u128.try_into().unwrap(),
                strk_l1_data_gas_price: 1u128.try_into().unwrap(),
            },
            use_kzg_da: false,
        };

        let chain_info = ChainInfo {
            chain_id: self.starknet_os_config.chain_id.clone(),
            fee_token_addresses: FeeTokenAddresses {
                eth_fee_token_address: self.starknet_os_config.fee_token_address,
                strk_fee_token_address: contract_address!("0x0"),
            },
        };

        let bouncer_config = BouncerConfig::max();

        BlockContext::new(block_info, chain_info, versioned_constants, bouncer_config)
    }
}

impl TryFrom<BlockContext> for StarknetGeneralConfig {
    type Error = SnOsError;

    fn try_from(block_context: BlockContext) -> Result<Self, SnOsError> {
        Ok(Self {
            starknet_os_config: StarknetOsConfig {
                chain_id: block_context.chain_info().chain_id.clone(),
                fee_token_address: block_context.chain_info().fee_token_addresses.get_by_fee_type(&FeeType::Eth),
                deprecated_fee_token_address: block_context
                    .chain_info()
                    .fee_token_addresses
                    .get_by_fee_type(&FeeType::Strk),
            },
            sequencer_address: block_context.block_info().sequencer_address,
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_starknet_config() {
        let expected_seq_addr = contract_address!(SEQUENCER_ADDR_0_13_3);

        let conf = StarknetGeneralConfig::from_default_file().expect("Failed to load default config file");

        assert!(conf.enforce_l1_handler_fee);

        assert_eq!(1000000000000000000000, conf.default_eth_price_in_fri);
        assert_eq!(1000000, conf.validate_max_n_steps_override);

        assert_eq!(expected_seq_addr, conf.sequencer_address);
    }

    #[test]
    fn convert_block_context() {
        let conf = StarknetGeneralConfig::default();
        let ctx: BlockContext = conf.empty_block_context();

        assert_eq!(conf.starknet_os_config.chain_id, ctx.chain_info().chain_id);
        assert_eq!(
            conf.starknet_os_config.fee_token_address,
            ctx.chain_info().fee_token_addresses.get_by_fee_type(&FeeType::Eth)
        );
        assert_eq!(conf.sequencer_address, ctx.block_info().sequencer_address);
    }
}

use std::collections::HashMap;
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;

use blockifier::abi::constants::{MAX_STEPS_PER_TX, N_STEPS_RESOURCE};
use blockifier::block_context::{BlockContext, FeeTokenAddresses, GasPrices};
use blockifier::transaction::objects::FeeType;
use cairo_vm::types::layout_name::LayoutName;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use starknet_api::block::{BlockNumber, BlockTimestamp};
use starknet_api::core::{ChainId, ContractAddress, PatriciaKey};
use starknet_api::hash::{pedersen_hash_array, StarkFelt, StarkHash};
use starknet_api::{contract_address, patricia_key};
use starknet_crypto::FieldElement;

use crate::error::SnOsError;
use crate::utils::ChainIdNum;

pub fn default_layout() -> LayoutName {
    LayoutName::starknet_with_keccak
}

const DEFAULT_CONFIG_PATH: &str = "cairo-lang/src/starkware/starknet/definitions/general_config.yml";
pub const STORED_BLOCK_HASH_BUFFER: u64 = 10;
pub const BLOCK_HASH_CONTRACT_ADDRESS: u64 = 1;
pub const STARKNET_OS_CONFIG_HASH_VERSION: &str = "StarknetOsConfig1";
pub const DEFAULT_COMPILED_OS: &str = "build/os_latest.json";
pub const DEFAULT_INPUT_PATH: &str = "build/input.json";
pub const DEFAULT_COMPILER_VERSION: &str = "0.12.2";
pub const DEFAULT_STORAGE_TREE_HEIGHT: usize = 251;
pub const DEFAULT_INNER_TREE_HEIGHT: u64 = 64;
// TODO: update with relevant address
pub const DEFAULT_FEE_TOKEN_ADDR: &str = "482bc27fc5627bf974a72b65c43aa8a0464a70aab91ad8379b56a4f17a84c3";
pub const DEFAULT_DEPRECATED_FEE_TOKEN_ADDR: &str = "482bc27fc5627bf974a72b65c43aa8a0464a70aab91ad8379b56a4f17a84c3";
pub const SEQUENCER_ADDR_0_13_0: &str = "0x4acb67f8e29379b475ccc408fc8269c116f64b4fe5a625644c507d7df07132";
pub const SN_GOERLI: &str = "534e5f474f45524c49";

#[serde_as]
#[derive(Debug, Serialize, Clone, Deserialize, PartialEq)]
pub struct StarknetOsConfig {
    #[serde_as(as = "ChainIdNum")]
    pub chain_id: ChainId,
    pub fee_token_address: ContractAddress,
    pub deprecated_fee_token_address: ContractAddress,
}

impl StarknetOsConfig {
    pub fn hash(&self) -> StarkHash {
        pedersen_hash_array(&[
            StarkFelt::from(FieldElement::from_byte_slice_be(STARKNET_OS_CONFIG_HASH_VERSION.as_bytes()).unwrap()),
            StarkFelt::from(u128::from_str_radix(&self.chain_id.0, 16).unwrap()),
            *self.fee_token_address.0.key(),
        ])
    }
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

#[derive(Debug, Serialize, Clone, Deserialize, PartialEq)]
pub struct StarknetGeneralConfig {
    pub starknet_os_config: StarknetOsConfig,
    pub gas_price_bounds: GasPriceBounds,
    pub invoke_tx_max_n_steps: u32,
    pub validate_max_n_steps: u32,
    pub default_eth_price_in_fri: u128,
    pub constant_gas_price: bool,
    pub sequencer_address: ContractAddress,
    pub cairo_resource_fee_weights: Arc<HashMap<String, f64>>,
    pub enforce_l1_handler_fee: bool,
    pub use_kzg_da: bool,
}

impl Default for StarknetGeneralConfig {
    fn default() -> Self {
        match StarknetGeneralConfig::from_file(PathBuf::from(DEFAULT_CONFIG_PATH)) {
            Ok(conf) => conf,
            Err(_) => Self {
                starknet_os_config: StarknetOsConfig {
                    chain_id: ChainId(SN_GOERLI.to_string()),
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
                invoke_tx_max_n_steps: MAX_STEPS_PER_TX as u32,
                validate_max_n_steps: MAX_STEPS_PER_TX as u32,
                default_eth_price_in_fri: 1_000_000_000_000_000_000_000,
                constant_gas_price: false,
                sequencer_address: contract_address!(SEQUENCER_ADDR_0_13_0),
                cairo_resource_fee_weights: Arc::new(HashMap::from([(N_STEPS_RESOURCE.to_string(), 1.0)])),
                enforce_l1_handler_fee: true,
                use_kzg_da: false,
            },
        }
    }
}

impl StarknetGeneralConfig {
    pub fn from_file(f: PathBuf) -> Result<StarknetGeneralConfig, SnOsError> {
        let conf = File::open(f).map_err(|e| SnOsError::CatchAll(format!("config - {e}")))?;
        serde_yaml::from_reader(conf).map_err(|e| SnOsError::CatchAll(format!("config - {e}")))
    }
    pub fn empty_block_context(&self) -> BlockContext {
        BlockContext {
            chain_id: self.starknet_os_config.chain_id.clone(),
            block_number: BlockNumber(0),
            block_timestamp: BlockTimestamp(0),
            sequencer_address: self.sequencer_address,
            fee_token_addresses: FeeTokenAddresses {
                eth_fee_token_address: self.starknet_os_config.fee_token_address,
                strk_fee_token_address: contract_address!("0x0"),
            },
            vm_resource_fee_cost: self.cairo_resource_fee_weights.clone(),
            gas_prices: GasPrices {
                eth_l1_gas_price: 1, // TODO: update with 4844
                strk_l1_gas_price: 1,
            },
            invoke_tx_max_n_steps: self.invoke_tx_max_n_steps,
            validate_max_n_steps: self.validate_max_n_steps,
            max_recursion_depth: 50,
        }
    }
}

impl TryFrom<BlockContext> for StarknetGeneralConfig {
    type Error = SnOsError;

    fn try_from(block_context: BlockContext) -> Result<Self, SnOsError> {
        Ok(Self {
            starknet_os_config: StarknetOsConfig {
                chain_id: block_context.chain_id,
                fee_token_address: block_context.fee_token_addresses.get_by_fee_type(&FeeType::Eth),
                deprecated_fee_token_address: block_context.fee_token_addresses.get_by_fee_type(&FeeType::Strk),
            },
            sequencer_address: block_context.sequencer_address,
            cairo_resource_fee_weights: block_context.vm_resource_fee_cost,
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_starknet_config() {
        let expected_seq_addr = contract_address!(SEQUENCER_ADDR_0_13_0);

        let conf = StarknetGeneralConfig::default();

        assert!(!conf.constant_gas_price);
        assert!(conf.enforce_l1_handler_fee);

        assert_eq!(4000000, conf.invoke_tx_max_n_steps);
        assert_eq!(1000000000000000000000, conf.default_eth_price_in_fri);
        assert_eq!(4000000, conf.validate_max_n_steps);

        assert_eq!(expected_seq_addr, conf.sequencer_address);
    }

    #[test]
    fn convert_block_context() {
        let conf = StarknetGeneralConfig::default();
        let ctx: BlockContext = conf.empty_block_context();

        assert_eq!(conf.starknet_os_config.chain_id, ctx.chain_id);
        assert_eq!(conf.starknet_os_config.fee_token_address, ctx.fee_token_addresses.get_by_fee_type(&FeeType::Eth));
        assert_eq!(conf.sequencer_address, ctx.sequencer_address);
        assert_eq!(conf.cairo_resource_fee_weights, ctx.vm_resource_fee_cost);
    }
}

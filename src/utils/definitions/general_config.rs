use serde::{Deserialize, Serialize};
use starknet::core::chain_id::TESTNET;
use starknet::core::types::FieldElement;
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::sync::OnceCell;

use super::constants;

const GENERAL_CONFIG_FILE_NAME: &str = "general_config.yml";
const N_STEPS_RESOURCE: &str = "n_steps";
const DEFAULT_CHAIN_ID: FieldElement = TESTNET;

// Default configuration values.

pub const DEFAULT_VALIDATE_MAX_STEPS: usize = 10usize.pow(6);
pub const DEFAULT_TX_MAX_STEPS: usize = 3 * 10usize.pow(6);
pub const DEFAULT_ENFORCE_L1_FEE: bool = true;

// Given in units of wei
pub const DEFAULT_GAS_PRICE: usize = 10usize.pow(8);

#[derive(Debug, Serialize, Deserialize)]
struct StarknetOsConfig {
    chain_id: FieldElement,
    fee_token_address: FieldElement,
}

impl Default for StarknetOsConfig {
    fn default() -> Self {
        StarknetOsConfig {
            chain_id: DEFAULT_CHAIN_ID,
            fee_token_address: FieldElement::ZERO,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StarknetGeneralConfig {
    starknet_os_config: StarknetOsConfig,
    contract_storage_commitment_tree_height: usize,
    compiled_class_hash_commitment_tree_height: usize,
    global_state_commitment_tree_height: usize,
    invoke_tx_max_n_steps: usize,
    validate_max_n_steps: usize,
    min_gas_price: usize,
    constant_gas_price: bool,
    sequencer_address: FieldElement,
    tx_commitment_tree_height: usize,
    event_commitment_tree_height: usize,
    cairo_resource_fee_weights: HashMap<String, f32>,
    enforce_l1_handler_fee: bool,
}

pub static CONFIG: OnceCell<StarknetGeneralConfig> = OnceCell::const_new();

impl Default for StarknetGeneralConfig {
    fn default() -> Self {
        StarknetGeneralConfig {
            starknet_os_config: StarknetOsConfig::default(),
            contract_storage_commitment_tree_height:
                constants::CONTRACT_STATES_COMMITMENT_TREE_HEIGHT,
            compiled_class_hash_commitment_tree_height:
                constants::COMPILED_CLASS_HASH_COMMITMENT_TREE_HEIGHT,
            global_state_commitment_tree_height: constants::CONTRACT_ADDRESS_BITS,
            invoke_tx_max_n_steps: DEFAULT_TX_MAX_STEPS,
            validate_max_n_steps: DEFAULT_VALIDATE_MAX_STEPS,
            min_gas_price: DEFAULT_GAS_PRICE,
            constant_gas_price: false,
            sequencer_address: FieldElement::ZERO, // TODO: Add real value
            tx_commitment_tree_height: constants::TRANSACTION_COMMITMENT_TREE_HEIGHT,
            event_commitment_tree_height: constants::EVENT_COMMITMENT_TREE_HEIGHT,
            cairo_resource_fee_weights: HashMap::default(), // TODO: Add builtins module
            enforce_l1_handler_fee: DEFAULT_ENFORCE_L1_FEE,
        }
    }
}

impl StarknetGeneralConfig {
    fn chain_id(&self) -> FieldElement {
        self.starknet_os_config.chain_id
    }

    fn fee_token_address(&self) -> FieldElement {
        self.starknet_os_config.fee_token_address
    }
}

#[allow(unused)]
pub fn build_general_config(raw_general_config: HashMap<String, String>) -> StarknetGeneralConfig {
    // ... logic to build the general config ...
    StarknetGeneralConfig::default()
}

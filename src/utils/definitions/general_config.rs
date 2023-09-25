use cairo_felt::Felt252;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::OnceCell;

use super::constants;

const _GENERAL_CONFIG_FILE_NAME: &str = "general_config.yml";
const _N_STEPS_RESOURCE: &str = "n_steps";
// const DEFAULT_CHAIN_ID: Felt252 = Felt252::new(0); // Fix this

// Default configuration values.

pub const DEFAULT_VALIDATE_MAX_STEPS: u64 = 10u64.pow(6);
pub const DEFAULT_TX_MAX_STEPS: u64 = 3 * 10u64.pow(6);
pub const DEFAULT_ENFORCE_L1_FEE: bool = true;

// Given in units of wei
pub const DEFAULT_GAS_PRICE: u64 = 10u64.pow(8);

#[derive(Debug, Default, Serialize, Deserialize)]
struct StarknetOsConfig {
    chain_id: Felt252,
    fee_token_address: Felt252,
}

fn starknet_os_config() -> StarknetOsConfig {
    StarknetOsConfig {
        chain_id: Felt252::new(0),
        fee_token_address: Felt252::new(0),
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct StarknetGeneralConfig {
    starknet_os_config: StarknetOsConfig,
    contract_storage_commitment_tree_height: u64,
    compiled_class_hash_commitment_tree_height: u64,
    global_state_commitment_tree_height: u64,
    invoke_tx_max_n_steps: u64,
    validate_max_n_steps: u64,
    min_gas_price: u64,
    constant_gas_price: bool,
    sequencer_address: Felt252,
    tx_commitment_tree_height: u64,
    event_commitment_tree_height: u64,
    cairo_resource_fee_weights: HashMap<String, f32>,
    enforce_l1_handler_fee: bool,
}

pub static CONFIG: OnceCell<StarknetGeneralConfig> = OnceCell::const_new();

fn starknet_config() -> StarknetGeneralConfig {
    StarknetGeneralConfig {
        starknet_os_config: starknet_os_config(),
        contract_storage_commitment_tree_height: constants::CONTRACT_STATES_COMMITMENT_TREE_HEIGHT,
        compiled_class_hash_commitment_tree_height:
            constants::COMPILED_CLASS_HASH_COMMITMENT_TREE_HEIGHT,
        global_state_commitment_tree_height: constants::CONTRACT_ADDRESS_BITS,
        invoke_tx_max_n_steps: DEFAULT_TX_MAX_STEPS,
        validate_max_n_steps: DEFAULT_VALIDATE_MAX_STEPS,
        min_gas_price: DEFAULT_GAS_PRICE,
        constant_gas_price: false,
        sequencer_address: Felt252::new(0), // TODO: Add real value
        tx_commitment_tree_height: constants::TRANSACTION_COMMITMENT_TREE_HEIGHT,
        event_commitment_tree_height: constants::EVENT_COMMITMENT_TREE_HEIGHT,
        cairo_resource_fee_weights: HashMap::default(), // TODO: Add builtins module
        enforce_l1_handler_fee: DEFAULT_ENFORCE_L1_FEE,
    }
}

impl StarknetGeneralConfig {
    fn _chain_id(&self) -> Felt252 {
        self.starknet_os_config.chain_id.clone()
    }

    fn _fee_token_address(&self) -> Felt252 {
        self.starknet_os_config.fee_token_address.clone()
    }
}

#[allow(unused)]
pub fn build_general_config(raw_general_config: HashMap<String, String>) -> StarknetGeneralConfig {
    // ... logic to build the general config ...
    starknet_config()
}

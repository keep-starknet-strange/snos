use serde::{Deserialize, Serialize};
use starknet::core::chain_id::TESTNET;
use starknet::core::types::FieldElement;
use std::collections::HashMap;
use std::path::PathBuf;

const GENERAL_CONFIG_FILE_NAME: &str = "general_config.yml";
const DOCKER_GENERAL_CONFIG_PATH: PathBuf = PathBuf::from("/").join(GENERAL_CONFIG_FILE_NAME);
const GENERAL_CONFIG_PATH: PathBuf = PathBuf::from(file!()).parent().unwrap().join(GENERAL_CONFIG_FILE_NAME);
const N_STEPS_RESOURCE: &str = "n_steps";

const DEFAULT_CHAIN_ID: FieldElement = TESTNET;

// ... other constants ...

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

#[derive(Debug, Serialize, Deserialize, Default)]
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

impl StarknetGeneralConfig {
    fn chain_id(&self) -> FieldElement {
        self.starknet_os_config.chain_id
    }

    fn fee_token_address(&self) -> FieldElement {
        self.starknet_os_config.fee_token_address
    }
}

fn build_general_config(raw_general_config: HashMap<String, String>) -> StarknetGeneralConfig {
    // ... logic to build the general config ...
    StarknetGeneralConfig::default()
}

// ... other structs and functions ...


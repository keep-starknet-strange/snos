use serde::{Deserialize, Deserializer, Serialize};
use starknet_core::{crypto::compute_hash_on_elements, types::FieldElement};
use std::collections::HashMap;
use std::fs::File;
use std::path::PathBuf;

use crate::error::SnOsError;

const DEFAULT_CONFIG_PATH: &str =
    "cairo-lang/src/starkware/starknet/definitions/general_config.yml";

const SN_OS_CONFIG_V1: &str = "537461726b6e65744f73436f6e66696732"; // StarknetOsConfig2

pub const DEFAULT_VALIDATE_MAX_STEPS: u64 = 10u64.pow(6);
pub const DEFAULT_TX_MAX_STEPS: u64 = 3 * 10u64.pow(6);
pub const DEFAULT_ENFORCE_L1_FEE: bool = true;
pub const DEFAULT_STORAGE_TREE_HEIGHT: u64 = 251;

// Given in units of wei
pub const DEFAULT_L1_GAS_PRICE: u64 = 10u64.pow(8);
pub const DEFAULT_STARK_L1_GAS_PRICE: u64 = 0;

#[derive(Debug, Serialize, Deserialize)]
pub struct StarknetOsConfig {
    pub chain_id: u128,
    #[serde(deserialize_with = "felt_from_hex_string")]
    pub fee_token_address: FieldElement,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StarknetGeneralConfig {
    pub starknet_os_config: StarknetOsConfig,
    pub contract_storage_commitment_tree_height: u64,
    pub compiled_class_hash_commitment_tree_height: u64,
    pub global_state_commitment_tree_height: u64,
    pub invoke_tx_max_n_steps: u64,
    pub validate_max_n_steps: u64,
    pub min_gas_price: u64,
    pub constant_gas_price: bool,
    #[serde(deserialize_with = "felt_from_hex_string")]
    pub sequencer_address: FieldElement,
    pub tx_commitment_tree_height: u64,
    pub event_commitment_tree_height: u64,
    pub cairo_resource_fee_weights: HashMap<String, f32>,
    pub enforce_l1_handler_fee: bool,
}

impl Default for StarknetGeneralConfig {
    fn default() -> Self {
        // Panic if we can't get the default values from cairo-lang submodule
        StarknetGeneralConfig::from_file(PathBuf::from(DEFAULT_CONFIG_PATH)).unwrap()
    }
}

impl StarknetGeneralConfig {
    pub fn from_file(f: PathBuf) -> Result<StarknetGeneralConfig, SnOsError> {
        let conf = File::open(f).map_err(|e| SnOsError::CatchAll(format!("config - {e}")))?;
        serde_yaml::from_reader(conf).map_err(|e| SnOsError::CatchAll(format!("config - {e}")))
    }

    pub fn os_config_hash(&self) -> Result<FieldElement, SnOsError> {
        let config_ver = FieldElement::from_hex_be(SN_OS_CONFIG_V1)
            .map_err(|e| SnOsError::CatchAll(format!("config - {e}")))?;

        Ok(compute_hash_on_elements(&[
            config_ver,
            FieldElement::from(self.starknet_os_config.chain_id),
            self.starknet_os_config.fee_token_address,
            self.starknet_os_config.fee_token_address,
        ]))
    }
}

fn felt_from_hex_string<'de, D>(d: D) -> Result<FieldElement, D::Error>
where
    D: Deserializer<'de>,
{
    let de_str = String::deserialize(d)?;
    FieldElement::from_hex_be(de_str.as_str()).map_err(|e| serde::de::Error::custom(format!("{e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_FEE_TOKEN_ADDR: &str =
        "482bc27fc5627bf974a72b65c43aa8a0464a70aab91ad8379b56a4f17a84c3";

    #[test]
    fn parse_starknet_config() {
        let expected_seq_addr = FieldElement::from_hex_be(
            "6c95526293b61fa708c6cba66fd015afee89309666246952456ab970e9650aa",
        )
        .unwrap();

        let conf = StarknetGeneralConfig::default();

        assert_eq!(251, conf.compiled_class_hash_commitment_tree_height);
        assert_eq!(251, conf.contract_storage_commitment_tree_height);
        assert_eq!(251, conf.global_state_commitment_tree_height);

        assert_eq!(false, conf.constant_gas_price);
        assert_eq!(true, conf.enforce_l1_handler_fee);

        assert_eq!(64, conf.event_commitment_tree_height);
        assert_eq!(64, conf.tx_commitment_tree_height);

        assert_eq!(1000000, conf.invoke_tx_max_n_steps);
        assert_eq!(100000000000, conf.min_gas_price);
        assert_eq!(1000000, conf.validate_max_n_steps);

        assert_eq!(expected_seq_addr, conf.sequencer_address);
    }

    // TODO: swap back to Felt252 and use Hasher
    #[test]
    fn compare_starknet_config_hash() {
        let exp_config_hash = FieldElement::from_hex_be(
            "3691f1b3036bfbfa57956581785222c25ac187cfb3ac0bfc4c637074e1989e7",
        )
        .unwrap();

        let mut conf = StarknetGeneralConfig::default();
        conf.starknet_os_config.fee_token_address =
            FieldElement::from_hex_be(TEST_FEE_TOKEN_ADDR).unwrap();

        let os_hash = conf.os_config_hash().unwrap();

        assert_eq!(exp_config_hash, os_hash);
    }
}

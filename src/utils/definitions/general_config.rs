use cairo_felt::Felt252;
use num_traits::Num;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::path::PathBuf;

const DEFAULT_CONFIG_PATH: &str =
    "cairo-lang/src/starkware/starknet/definitions/general_config.yml";

pub const DEFAULT_VALIDATE_MAX_STEPS: u64 = 10u64.pow(6);
pub const DEFAULT_TX_MAX_STEPS: u64 = 3 * 10u64.pow(6);
pub const DEFAULT_ENFORCE_L1_FEE: bool = true;

// Given in units of wei
pub const DEFAULT_GAS_PRICE: u64 = 10u64.pow(8);

#[derive(Debug, Serialize, Deserialize)]
pub struct StarknetOsConfig {
    pub chain_id: u128,
    #[serde(deserialize_with = "felt_from_hex_string")]
    pub fee_token_address: Felt252,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StarknetGeneralConfig {
    starknet_os_config: StarknetOsConfig,
    contract_storage_commitment_tree_height: u64,
    compiled_class_hash_commitment_tree_height: u64,
    global_state_commitment_tree_height: u64,
    invoke_tx_max_n_steps: u64,
    validate_max_n_steps: u64,
    min_gas_price: u64,
    constant_gas_price: bool,
    #[serde(deserialize_with = "felt_from_hex_string")]
    sequencer_address: Felt252,
    tx_commitment_tree_height: u64,
    event_commitment_tree_height: u64,
    cairo_resource_fee_weights: HashMap<String, f32>,
    enforce_l1_handler_fee: bool,
}

impl Default for StarknetGeneralConfig {
    fn default() -> Self {
        // TODO: handle unwrap
        Self::try_from(PathBuf::from(DEFAULT_CONFIG_PATH)).unwrap()
    }
}

impl TryFrom<PathBuf> for StarknetGeneralConfig {
    type Error = std::io::Error;

    fn try_from(f: PathBuf) -> Result<StarknetGeneralConfig, Self::Error> {
        let conf = File::open(f)?;
        serde_yaml::from_reader(conf)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::Unsupported))
    }
}

fn felt_from_hex_string<'de, D>(d: D) -> Result<Felt252, D::Error>
where
    D: Deserializer<'de>,
{
    let de_str = String::deserialize(d)?;
    let de_str = de_str.trim_start_matches("0x");
    Felt252::from_str_radix(de_str, 16).map_err(|e| serde::de::Error::custom(format!("{e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_starknet_config() {
        let conf = StarknetGeneralConfig::default();

        assert_eq!(conf.compiled_class_hash_commitment_tree_height, 251);
        assert_eq!(conf.contract_storage_commitment_tree_height, 251);
        assert_eq!(conf.global_state_commitment_tree_height, 251);

        assert_eq!(conf.constant_gas_price, false);
        assert_eq!(conf.enforce_l1_handler_fee, true);

        assert_eq!(conf.event_commitment_tree_height, 64);
        assert_eq!(conf.tx_commitment_tree_height, 64);

        assert_eq!(conf.invoke_tx_max_n_steps, 1000000);
        assert_eq!(conf.min_gas_price, 100000000000);
        assert_eq!(conf.validate_max_n_steps, 1000000);

        assert_eq!(
            conf.sequencer_address,
            Felt252::from_str_radix(
                "6c95526293b61fa708c6cba66fd015afee89309666246952456ab970e9650aa",
                16
            )
            .unwrap()
        );
    }
}

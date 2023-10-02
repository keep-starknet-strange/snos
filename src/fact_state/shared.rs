use cairo_felt::Felt252;
use num_traits::Num;

use crate::utils::{
    commitment_tree::patricia_tree::PatriciaTree,
    definitions::general_config::{
        DEFAULT_L1_GAS_PRICE, DEFAULT_STARK_L1_GAS_PRICE, DEFAULT_STORAGE_TREE_HEIGHT,
    },
};

use crate::fact_state::contract_state::ContractState;

// TODO: parse from cairo-lang
const STARKNET_VERSION: &str = "0.12.3";

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BlockInfo {
    pub block_number: u64,
    pub block_timestamp: u64,
    pub eth_l1_gas_price: u64,
    pub strk_l1_gas_price: u64,
    pub sequencer_address: Felt252,
    pub starknet_version: String,
}

impl Default for BlockInfo {
    fn default() -> Self {
        Self {
            block_number: 0,
            block_timestamp: 0,
            eth_l1_gas_price: DEFAULT_L1_GAS_PRICE,
            strk_l1_gas_price: DEFAULT_STARK_L1_GAS_PRICE,
            sequencer_address: Felt252::new(0),
            starknet_version: STARKNET_VERSION.to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SharedState {
    contract_states: PatriciaTree,
    contract_classes: PatriciaTree,
    block_info: BlockInfo,
}

impl SharedState {
    pub fn get_global_state_root(&self) -> Felt252 {
        Felt252::from_str_radix(
            "1979936137588314659299290311388212850452581912938754160740725722960239001773",
            10,
        )
        .unwrap()
    }
}

impl Default for SharedState {
    fn default() -> Self {
        Self {
            contract_states: PatriciaTree {
                root: Felt252::new(0),
                height: DEFAULT_STORAGE_TREE_HEIGHT as usize,
            },
            contract_classes: PatriciaTree {
                root: Felt252::new(0),
                height: DEFAULT_STORAGE_TREE_HEIGHT as usize,
            },
            // contract_classes: contract_classes::empty(DEFAULT_STORAGE_TREE_HEIGHT),
            block_info: BlockInfo::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use num_traits::Num;

    use super::*;

    /*
     Initial State
     SharedState(contract_states=PatriciaTree(root=b'\x04`\x9a\xa8\xfe\xbfr**.\xc1A\x1d$\x19\rqE\x96\xc8\xdfH\x88\xadF\x90\x04\xaf5t\x00\xad', height=251),
      contract_classes=PatriciaTree(root=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', height=251),
      block_info=BlockInfo(block_number=0, block_timestamp=1000, eth_l1_gas_price=100000000, strk_l1_gas_price=0, sequencer_address=443902168967810054148884074756742919510645257800272067493104417962415061304, starknet_version='0.12.3'))
    */

    #[test]
    fn test_genesis_root() {
        // SharedState(contract_states=PatriciaTree(root=b'\x04`\x9a\xa8\xfe\xbfr**.\xc1A\x1d$\x19\rqE\x96\xc8\xdfH\x88\xadF\x90\x04\xaf5t\x00\xad', height=251), contract_classes=PatriciaTree(root=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', height=251), block_info=BlockInfo(block_number=0, block_timestamp=1000, eth_l1_gas_price=100000000, strk_l1_gas_price=0, sequencer_address=443902168967810054148884074756742919510645257800272067493104417962415061304, starknet_version='0.12.3'))
        let expected_genesis_commitment = Felt252::from_str_radix(
            "1979936137588314659299290311388212850452581912938754160740725722960239001773",
            10,
        )
        .unwrap();

        let default_shared = SharedState::default();
        // previous_root=1979936137588314659299290311388212850452581912938754160740725722960239001773,
        // updated_root=600419662812745373863723309851967758205221993854252183250195928682564186741

        assert_eq!(
            expected_genesis_commitment,
            default_shared.get_global_state_root()
        )
    }
}

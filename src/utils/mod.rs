pub mod commitment_tree;
pub mod definitions;
pub mod hasher;

use pathfinder_common::{contract_address_bytes, ContractAddress as PathContractAddress};
use starknet_api::core::{ContractAddress, PatriciaKey};
use starknet_api::hash::StarkHash;
use starknet_api::{contract_address, patricia_key};

pub fn sn_to_path_address(sn_addr: ContractAddress) -> PathContractAddress {
    contract_address_bytes!(sn_addr.0.key().bytes())
}

pub fn path_to_sn_address(path_addr: PathContractAddress) -> ContractAddress {
    contract_address!(path_addr.to_string().as_str())
}

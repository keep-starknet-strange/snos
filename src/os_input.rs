use std::collections::HashMap;

use cairo_felt::Felt252;

use crate::{
    business_logic::transaction::types::InternalTransaction, config::StarknetGeneralConfig,
    path_state::ContractState, storage::starknet::CommitmentInfo,
};

struct StarknetOsInput {
    contract_state_commitment_info: CommitmentInfo,
    contract_class_commitment_info: CommitmentInfo,
    deprecated_compiled_classes: HashMap<Felt252, Felt252>, // TODO: Add contract_class module
    compiled_classes: HashMap<Felt252, Felt252>,            // TODO: Add contract_class module
    contracts: HashMap<Felt252, ContractState>,
    class_hash_to_compiled_class_hash: HashMap<Felt252, Felt252>,
    general_config: StarknetGeneralConfig,
    transactions: Vec<InternalTransaction>,
    block_hash: Felt252,
}

use std::collections::HashMap;

use cairo_felt::Felt252;

use starknet_api::transaction::{MessageToL1, MessageToL2};

use crate::{
    business_logic::transaction::types::InternalTransaction, config::StarknetGeneralConfig,
    state::ContractState, storage::starknet::CommitmentInfo,
};

#[allow(unused)]
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

pub struct StarknetOsOutput {
    /// The state commitment before this block.
    pub prev_state_root: Felt252,
    /// The state commitment after this block.
    pub new_state_root: Felt252,
    /// The number (height) of this block.
    pub block_number: Felt252,
    /// The hash of this block.
    pub block_hash: Felt252,
    /// The Starknet chain config hash
    pub config_hash: Felt252,
    /// List of messages sent to L1 in this block
    pub messages_to_l1: Vec<MessageToL1>,
    /// List of messages from L1 handled in this block
    pub messages_to_l2: Vec<MessageToL2>,
}

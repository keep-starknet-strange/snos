use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use starknet::core::types::FieldElement;

use crate::{
    business_logic::transaction::types::InternalTransaction,
    fact_state::contract_state::ContractState,
    storage::{starknet::CommitmentInfo, Storage},
    utils::{definitions::general_config::StarknetGeneralConfig, hasher::HasherT},
};

#[derive(Serialize, Deserialize)]
struct StarknetOsInput<S: Storage, H: HasherT> {
    contract_state_commitment_info: CommitmentInfo<S, H>,
    contract_class_commitment_info: CommitmentInfo<S, H>,
    deprecated_compiled_classes: HashMap<FieldElement, FieldElement>, // TODO: Add contract_class module
    compiled_classes: HashMap<FieldElement, FieldElement>, // TODO: Add contract_class module
    contracts: HashMap<FieldElement, ContractState>,
    class_hash_to_compiled_class_hash: HashMap<FieldElement, FieldElement>,
    general_config: StarknetGeneralConfig,
    transactions: Vec<InternalTransaction>,
    block_hash: FieldElement,
}

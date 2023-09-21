use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use starknet::core::types::FieldElement;

use crate::{
    fact_state::contract_state::ContractState,
    storage::{starknet::CommitmentInfo, Storage},
    utils::{hasher::HasherT, definitions::general_config::StarknetGeneralConfig},
};

// TODO: Add missing fields
#[derive(Serialize, Deserialize)]
struct StarknetOsInput<S: Storage, H: HasherT> {
    contract_state_commitment_info: CommitmentInfo<S, H>,
    contract_class_commitment_info: CommitmentInfo<S, H>,
    contracts: HashMap<FieldElement, ContractState>,
    class_hash_to_compiled_class_hash: HashMap<FieldElement, FieldElement>,
    general_config: StarknetGeneralConfig,
    block_hash: FieldElement,
}

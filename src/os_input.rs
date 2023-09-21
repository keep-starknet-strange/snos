use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use starknet::core::types::FieldElement;

use crate::storage::starknet::CommitmentInfo;

// TODO: Add missing fields
#[derive(Serialize, Deserialize)]
struct StarknetOsInput {
    contract_state_commitment_info: CommitmentInfo,
    contract_class_commitment_info: CommitmentInfo,
    class_hash_to_compiled_class_hash: HashMap<FieldElement, FieldElement>,
    block_hash: FieldElement,
}

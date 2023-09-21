use serde::{Deserialize, Serialize};
use starknet::core::types::FieldElement;

use crate::storage::starknet::CommitmentInfo;

#[derive(Serialize, Deserialize)]
struct StarknetOsInput {
    contract_state_commitment_info: CommitmentInfo,
    block_hash: FieldElement,
}

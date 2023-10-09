use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use cairo_felt::Felt252;

type CommitmentFacts = HashMap<Felt252, Vec<Felt252>>;

#[derive(Serialize, Deserialize)]
pub struct CommitmentInfo {
    pub previous_root: Felt252,
    pub updated_root: Felt252,
    tree_height: usize,
    commitment_facts: CommitmentFacts,
}

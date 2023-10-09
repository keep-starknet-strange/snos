use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use cairo_felt::Felt252;

type CommitmentFacts = HashMap<Felt252, Vec<Felt252>>;

#[derive(Debug, Serialize, Deserialize)]
pub struct CommitmentInfo {
    pub previous_root: Felt252,
    pub updated_root: Felt252,
    pub(crate) tree_height: usize,
    pub(crate) commitment_facts: CommitmentFacts,
}

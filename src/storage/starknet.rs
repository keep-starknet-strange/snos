use serde::{Deserialize, Serialize};
use std::{collections::HashMap, marker::PhantomData};

use cairo_felt::Felt252;

use super::Storage;

type CommitmentFacts = HashMap<Felt252, Vec<Felt252>>;

#[derive(Serialize, Deserialize)]
pub struct CommitmentInfo {
    pub previous_root: Felt252,
    pub updated_root: Felt252,
    tree_height: usize,
    commitment_facts: CommitmentFacts,
}

// impl DBObject for ContractState {
//     fn db_key(suffix: Vec<u8>) -> Vec<u8> {
//         let prefix: &[u8] = b"contract_state";
//         let sep: &[u8] = b":";

//         [prefix, sep, suffix.as_slice()].concat()
//     }
// }

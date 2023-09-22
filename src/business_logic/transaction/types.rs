use std::collections::HashMap;

use cairo_felt::Felt252;
use serde::{Deserialize, Serialize};

// TODO: Complete this module

// TODO: Use a standard type from starknet_api/types-rs
#[derive(Serialize, Deserialize, PartialEq, Eq, Hash)]
struct Transaction {
    version: u8,
}

#[derive(Serialize, Deserialize)]
pub struct InternalTransaction {
    hash_value: Felt252,
    external_to_internal_cls: HashMap<Transaction, Self>,
}

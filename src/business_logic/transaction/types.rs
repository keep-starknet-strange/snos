use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use starknet::core::types::FieldElement;

// TODO: Complete this module

// TODO: Use a standard type from starknet_api/types-rs
#[derive(Serialize, Deserialize, PartialEq, Eq, Hash)]
struct Transaction {
    version: u8,
}

#[derive(Serialize, Deserialize)]
pub struct InternalTransaction {
    hash_value: FieldElement,
    external_to_internal_cls: HashMap<Transaction, Self>,
}

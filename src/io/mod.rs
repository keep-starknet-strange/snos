pub mod classes;
pub mod input;
pub mod output;

use cairo_vm::Felt252;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::utils::{Felt252HexNoPrefix, Felt252Str};

// TODO(#70):
// evaluate if we can use a more standard top level transaction type
// - starknet_api::transaction::Transaction -> no deserialization tag information
// - starknet::types::Transaction -> deserializes `transaction_hash` we have `hash_value`
#[serde_as]
#[derive(Deserialize, Clone, Debug, Serialize, Default, PartialEq)]
pub struct InternalTransaction {
    #[serde_as(as = "Felt252Str")]
    pub hash_value: Felt252,
    #[serde_as(as = "Option<Felt252Str>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<Felt252>,
    #[serde_as(as = "Option<Felt252Str>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_address: Option<Felt252>,
    #[serde_as(as = "Option<Felt252Str>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_address_salt: Option<Felt252>,
    #[serde_as(as = "Option<Felt252HexNoPrefix>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_hash: Option<Felt252>,
    #[serde_as(as = "Option<Vec<Felt252Str>>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constructor_calldata: Option<Vec<Felt252>>,
    #[serde_as(as = "Option<Felt252Str>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<Felt252>,
    #[serde_as(as = "Option<Felt252Str>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_address: Option<Felt252>,
    #[serde_as(as = "Option<Felt252Str>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_point_selector: Option<Felt252>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_point_type: Option<String>,
    #[serde_as(as = "Option<Vec<Felt252Str>>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Vec<Felt252>>,
    #[serde_as(as = "Option<Felt252Str>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class_hash: Option<Felt252>,
    #[serde_as(as = "Option<Felt252Str>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compiled_class_hash: Option<Felt252>,
    #[serde_as(as = "Option<Vec<Felt252Str>>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub calldata: Option<Vec<Felt252>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paid_on_l1: Option<bool>,
    pub r#type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_fee: Option<Felt252>,
}

#[derive(Debug)]
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
    pub messages_to_l1: Vec<Felt252>,
    /// List of messages from L1 handled in this block
    pub messages_to_l2: Vec<Felt252>,
    /// List of the storage updates.
    pub state_updates: Vec<Felt252>,
    /// List of the newly declared contract classes.
    pub contract_class_diff: Vec<Felt252>,
}

pub mod classes;
pub mod input;
pub mod output;

use cairo_vm::Felt252;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use starknet_api::transaction::ResourceBoundsMapping;

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
    #[serde_as(as = "Option<Felt252Str>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_fee: Option<Felt252>,
    #[serde_as(as = "Option<Felt252Str>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tip: Option<Felt252>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_bounds: Option<ResourceBoundsMapping>,
    #[serde_as(as = "Option<Vec<Felt252Str>>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paymaster_data: Option<Vec<Felt252>>,
    #[serde_as(as = "Option<Felt252Str>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce_data_availability_mode: Option<Felt252>,
    #[serde_as(as = "Option<Felt252Str>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_data_availability_mode: Option<Felt252>,
    #[serde_as(as = "Option<Vec<Felt252Str>>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_deployment_data: Option<Vec<Felt252>>,
}

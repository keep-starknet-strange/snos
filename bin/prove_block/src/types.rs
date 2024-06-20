//! Contains simplified types for parsing JSON-RPC responses.
//!
//! In order not to depend on pathfinder_lib these types "duplicate" similar
//! functionality already found in pathfinder. However, these types are
//! simplified and are missing fields that are irrelevant for load tests.
use pathfinder_common::GasPrice;
use pathfinder_crypto::Felt;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use starknet_api::block::{BlockBody, BlockHeader};

#[serde_as]
#[derive(Clone, Debug, serde::Deserialize, PartialEq, Eq)]
pub struct ResourcePrice {
    #[serde_as(as = "pathfinder_serde::GasPriceAsHexStr")]
    pub price_in_wei: GasPrice,
    #[serde_as(as = "pathfinder_serde::GasPriceAsHexStr")]
    pub price_in_fri: GasPrice,
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct Block {
    #[serde(flatten)]
    pub header: BlockHeader,
    #[serde(flatten)]
    pub body: BlockBody,
}

#[derive(Clone, Debug, serde::Deserialize, PartialEq, Eq)]
pub struct Transaction {
    pub r#type: String,
    pub transaction_hash: Felt,
}

#[derive(Clone, Debug, serde::Deserialize, PartialEq, Eq)]
pub struct TransactionReceipt {
    pub r#type: String,
    pub transaction_hash: Felt,
}

#[derive(Clone, Debug, serde::Deserialize, PartialEq, Eq)]
pub struct StateUpdate {
    pub block_hash: Felt,
    pub new_root: Felt,
    pub old_root: Felt,
}

#[derive(Clone, Debug, serde::Deserialize, PartialEq, Eq)]
pub struct ContractClass {
    pub abi: serde_json::Value,
    pub program: String,
}

#[derive(Clone, Debug, serde::Deserialize, PartialEq, Eq)]
pub struct FeeEstimate {
    pub gas_consumed: String,
    pub gas_price: String,
    pub overall_fee: String,
}

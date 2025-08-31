pub mod client;
pub mod pathfinder;
pub mod state_reader;
mod utils;

pub use client::RpcClient;

use starknet_types_core::felt::Felt;

/// Simplified hash function trait for our use case
pub trait SimpleHashFunction {
    fn hash(left: &Felt, right: &Felt) -> Felt;
}

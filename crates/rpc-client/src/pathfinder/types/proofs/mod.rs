pub mod class;
pub mod contract;
#[cfg(test)]
mod tests;

pub use crate::pathfinder::types::proofs::class::ClassProof;
pub use crate::pathfinder::types::proofs::contract::{ContractData, ContractProof, Height};

use crate::SimpleHashFunction;
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::{Pedersen, Poseidon, StarkHash};

pub struct PedersenHash;
impl SimpleHashFunction for PedersenHash {
    fn hash(left: &Felt, right: &Felt) -> Felt {
        Pedersen::hash(left, right)
    }
}

/// Implementation for Poseidon hash
pub struct PoseidonHash;
impl SimpleHashFunction for PoseidonHash {
    fn hash(left: &Felt, right: &Felt) -> Felt {
        Poseidon::hash(left, right)
    }
}

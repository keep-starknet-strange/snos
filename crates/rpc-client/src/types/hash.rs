use starknet_types_core::felt::Felt;
use starknet_types_core::hash::{Pedersen, Poseidon, StarkHash};

use crate::Hash;

pub struct PedersenHash;
impl Hash for PedersenHash {
    fn hash(left: &Felt, right: &Felt) -> Felt {
        Pedersen::hash(left, right)
    }
}

/// Implementation for Poseidon hash
pub struct PoseidonHash;
impl Hash for PoseidonHash {
    fn hash(left: &Felt, right: &Felt) -> Felt {
        Poseidon::hash(left, right)
    }
}

use starknet_crypto::{pedersen_hash, FieldElement};
use starknet_os_types::hash::Hash;

use crate::storage::storage::HashFunctionType;

#[derive(Clone, Debug, PartialEq)]
pub struct PedersenHash;

impl HashFunctionType for PedersenHash {
    fn hash(x: &[u8], y: &[u8]) -> Hash {
        let x_felt = FieldElement::from_byte_slice_be(x).unwrap();
        let y_felt = FieldElement::from_byte_slice_be(y).unwrap();

        Hash::from_bytes_be(pedersen_hash(&x_felt, &y_felt).to_bytes_be())
    }
}
